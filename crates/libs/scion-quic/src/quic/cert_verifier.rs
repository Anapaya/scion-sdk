// Copyright 2026 Anapaya Systems
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//   http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

//! Caller-supplied certificate verification.
//!
//! A [`CertVerifier`] decides whether the peer's certificate chain is trusted,
//! in place of the trust anchors that
//! [`QuicConfigBuilder`](super::config::QuicConfigBuilder) otherwise loads. See
//! [`QuicConfigBuilder::with_cert_verifier`](super::config::QuicConfigBuilder::with_cert_verifier).

use std::{
    error::Error,
    panic::{self, AssertUnwindSafe},
    sync::{Arc, Mutex, PoisonError},
};

/// Decides whether the peer's certificate chain is trusted.
///
/// This exists for platforms that do not let an application read their trust
/// anchors, so that the three CA sources of
/// [`QuicConfigBuilder`](super::config::QuicConfigBuilder) have nothing to
/// load. iOS is the case in point: an application can ask the system to
/// evaluate a chain through `SecTrust`, but it cannot enumerate the anchor set.
/// A verifier also expresses a trust decision that a set of anchors cannot,
/// such as certificate pinning.
///
/// A closure of the same shape implements this trait, so a verifier needs a
/// type of its own only when it carries state.
///
/// The verifier replaces the built-in validation rather than adding to it. See
/// [`QuicConfigBuilder::with_cert_verifier`](super::config::QuicConfigBuilder::with_cert_verifier)
/// for how it interacts with `verify_peer` and the CA sources.
pub trait CertVerifier: Send + Sync + 'static {
    /// Verifies the peer's certificate chain.
    ///
    /// Return `Ok(())` to let the handshake continue. Return a [`CertRejected`]
    /// to fail it, with a reason the caller of the connection can read from
    /// [`EstablishError::CertificateRejected`](crate::h3::client::EstablishError::CertificateRejected).
    ///
    /// The chain arrives with no validation of its own behind it, the name
    /// check included, so a verifier that authenticates a server has to compare
    /// [`PeerCertificates::server_name`] against the certificate itself.
    ///
    /// This runs on the task that drives the handshake, so a verifier that
    /// blocks holds up the connection. Connections verify in parallel, so it
    /// also has to tolerate being called from several threads at once.
    fn verify(&self, peer: &PeerCertificates<'_>) -> Result<(), CertRejected>;
}

impl<F> CertVerifier for F
where
    F: Fn(&PeerCertificates<'_>) -> Result<(), CertRejected> + Send + Sync + 'static,
{
    fn verify(&self, peer: &PeerCertificates<'_>) -> Result<(), CertRejected> {
        self(peer)
    }
}

/// What a [`CertVerifier`] is asked to check.
#[derive(Clone, Copy, Debug)]
pub struct PeerCertificates<'a> {
    chain: &'a [&'a [u8]],
    server_name: Option<&'a str>,
}

impl<'a> PeerCertificates<'a> {
    /// Creates the input of a verification.
    ///
    /// The connection builds this itself. It is public so that a verifier can
    /// be tested without a handshake.
    #[must_use]
    pub fn new(chain: &'a [&'a [u8]], server_name: Option<&'a str>) -> Self {
        Self { chain, server_name }
    }

    /// The certificates the peer sent, in the order it sent them: the leaf
    /// first, then the certificates that chain up from it.
    ///
    /// Each entry is a DER-encoded X.509 certificate. The chain is never empty.
    #[must_use]
    pub fn chain(&self) -> &'a [&'a [u8]] {
        self.chain
    }

    /// The name the peer is checked against.
    ///
    /// On a client this is the name the connection was opened with. On a
    /// server it is the name the client sent in the TLS SNI extension, which
    /// names the server rather than the peer being verified.
    ///
    /// It is `None` when no name was sent, and also when the name is not valid
    /// UTF-8, so a verifier cannot tell those two apart and has to reject a
    /// chain it cannot bind to a name.
    #[must_use]
    pub fn server_name(&self) -> Option<&'a str> {
        self.server_name
    }
}

/// Why a [`CertVerifier`] rejected the peer's certificate chain.
///
/// The message reaches the caller of the connection through
/// [`EstablishError::CertificateRejected`](crate::h3::client::EstablishError::CertificateRejected),
/// so write it for whoever reads that error and not for a log line.
#[derive(Debug, thiserror::Error)]
#[error("{message}")]
pub struct CertRejected {
    message: String,
    #[source]
    source: Option<Box<dyn Error + Send + Sync>>,
}

impl CertRejected {
    /// Rejects the chain, with a reason for the caller.
    #[must_use]
    pub fn new(message: impl Into<String>) -> Self {
        Self {
            message: message.into(),
            source: None,
        }
    }

    /// Attaches the error that led to the rejection, e.g. the one the platform
    /// trust evaluation returned.
    #[must_use]
    pub fn with_source(mut self, source: impl Into<Box<dyn Error + Send + Sync>>) -> Self {
        self.source = Some(source.into());
        self
    }

    /// The reason, without the rest of the source chain.
    #[must_use]
    pub fn message(&self) -> &str {
        &self.message
    }
}

/// Holds the reason a verifier rejected a chain, until the handshake that it
/// failed can name it.
///
/// One report belongs to one `squiche::Config`, which the client builds per
/// connection, so the reason a connection reports is its own.
#[derive(Clone, Debug, Default)]
pub(crate) struct RejectionReport(Arc<Mutex<Option<CertRejected>>>);

impl RejectionReport {
    /// Records a rejection, keeping the first one.
    ///
    /// The first rejection is the one that failed the handshake, so a later
    /// call does not displace it.
    fn record(&self, rejected: CertRejected) {
        let mut slot = self.0.lock().unwrap_or_else(PoisonError::into_inner);

        if slot.is_none() {
            *slot = Some(rejected);
        }
    }

    /// Takes the recorded rejection, leaving the report empty.
    pub(crate) fn take(&self) -> Option<CertRejected> {
        self.0.lock().unwrap_or_else(PoisonError::into_inner).take()
    }
}

/// Adapts `verifier` to what `squiche` calls during the handshake.
///
/// A rejection goes into `report`, when there is one. There is none where a
/// rejection cannot fail the handshake, because a reason recorded then would
/// be read as the cause of whatever else failed the connection.
pub(crate) fn to_squiche_verifier(
    verifier: &Arc<dyn CertVerifier>,
    report: Option<RejectionReport>,
) -> impl Fn(&[&[u8]], Option<&str>) -> squiche::CertificateVerdict + Send + Sync + 'static {
    let verifier = Arc::clone(verifier);

    move |chain, server_name| {
        let peer = PeerCertificates::new(chain, server_name);

        // The verifier is the caller's own code, and the frame below this one
        // belongs to a C library. squiche guards that boundary as well, but
        // catching here turns a panic into a reason the caller can read.
        let verdict = panic::catch_unwind(AssertUnwindSafe(|| verifier.verify(&peer)));

        let rejected = match verdict {
            Ok(Ok(())) => return squiche::CertificateVerdict::Trusted,
            Ok(Err(rejected)) => rejected,
            Err(_) => CertRejected::new("the certificate verifier panicked"),
        };

        if let Some(report) = &report {
            report.record(rejected);
        }

        squiche::CertificateVerdict::Untrusted
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Runs `verifier` the way a handshake does.
    fn verdict_of(
        verifier: impl Fn(&[&[u8]], Option<&str>) -> squiche::CertificateVerdict,
    ) -> squiche::CertificateVerdict {
        let chain: [&[u8]; 1] = [b"der"];

        verifier(&chain, Some("localhost"))
    }

    #[test]
    fn closure_implements_the_trait() {
        let verifier: Arc<dyn CertVerifier> = Arc::new(|peer: &PeerCertificates<'_>| {
            match peer.server_name() {
                Some("trusted") => Ok(()),
                _ => Err(CertRejected::new("unexpected name")),
            }
        });

        let chain: [&[u8]; 1] = [b"der"];

        assert!(
            verifier
                .verify(&PeerCertificates::new(&chain, Some("trusted")))
                .is_ok()
        );
        assert_eq!(
            verifier
                .verify(&PeerCertificates::new(&chain, Some("other")))
                .unwrap_err()
                .message(),
            "unexpected name"
        );
    }

    #[test]
    fn rejection_keeps_its_source() {
        let rejected = CertRejected::new("chain is not trusted")
            .with_source(std::io::Error::other("errSecNotTrusted"));

        assert_eq!(rejected.to_string(), "chain is not trusted");
        assert_eq!(
            rejected.source().map(ToString::to_string),
            Some("errSecNotTrusted".to_string())
        );
    }

    #[test]
    fn report_keeps_the_first_rejection() {
        let report = RejectionReport::default();

        report.record(CertRejected::new("first"));
        report.record(CertRejected::new("second"));

        assert_eq!(
            report.take().map(|r| r.message().to_string()),
            Some("first".to_string())
        );
        assert!(report.take().is_none());
    }

    #[test]
    fn a_panicking_verifier_rejects_with_a_reason() {
        let verifier: Arc<dyn CertVerifier> =
            Arc::new(|_: &PeerCertificates<'_>| -> Result<(), CertRejected> {
                panic!("verifier is broken")
            });
        let report = RejectionReport::default();
        let squiche_verifier = to_squiche_verifier(&verifier, Some(report.clone()));

        let hook = panic::take_hook();
        panic::set_hook(Box::new(|_| {}));
        let verdict = verdict_of(squiche_verifier);
        panic::set_hook(hook);

        assert_eq!(verdict, squiche::CertificateVerdict::Untrusted);
        assert_eq!(
            report.take().map(|r| r.message().to_string()),
            Some("the certificate verifier panicked".to_string())
        );
    }
}
