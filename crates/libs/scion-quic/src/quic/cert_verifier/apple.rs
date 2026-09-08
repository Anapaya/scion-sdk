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

//! Certificate verification with the Apple platform trust.
//!
//! [`PlatformVerifier`] evaluates the peer's chain with `SecTrust`, against the
//! system trust store. It is the verifier behind
//! [`QuicConfigBuilder::with_platform_verifier`](crate::quic::config::QuicConfigBuilder::with_platform_verifier)
//! on Apple targets.

use std::fmt;

use security_framework::{
    base::Error as SecurityError, certificate::SecCertificate, policy::SecPolicy,
    secure_transport::SslProtocolSide, trust::SecTrust,
};

use super::{CertRejected, CertVerifier, PeerCertificates};

/// Verifies the peer's certificate chain with the platform trust evaluation.
///
/// The chain is evaluated with `SecTrust`, against the system trust store, with
/// an SSL policy for [`PeerCertificates::server_name`]. A chain that comes
/// without a server name is rejected before the platform sees it.
///
/// Network fetching is disabled for the evaluation. The verifier runs on the
/// task that drives the handshake, so a fetch of a missing intermediate
/// certificate or of revocation data would block that task. A server has to
/// send its full chain.
#[derive(Clone, Copy, Debug, Default)]
pub struct PlatformVerifier(());

impl PlatformVerifier {
    /// Creates the verifier.
    #[must_use]
    pub fn new() -> Self {
        Self(())
    }
}

impl CertVerifier for PlatformVerifier {
    fn verify(&self, peer: &PeerCertificates<'_>) -> Result<(), CertRejected> {
        evaluate(peer, &Adjustments::default())
    }
}

/// Why the platform trust evaluation refused a chain.
///
/// This is the source of the [`CertRejected`] that [`PlatformVerifier`] returns
/// for a chain the platform evaluated. It carries the error domain and code
/// that the platform reported, e.g. `NSOSStatusErrorDomain` and
/// `errSecHostNameMismatch`. The platform's own error object is not `Send`, so
/// it does not cross into the rejection.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TrustEvaluationError {
    domain: String,
    code: i64,
}

impl TrustEvaluationError {
    /// The error domain the platform reported.
    #[must_use]
    pub fn domain(&self) -> &str {
        &self.domain
    }

    /// The error code the platform reported. In the `NSOSStatusErrorDomain`
    /// this is an `OSStatus` value such as `errSecHostNameMismatch`.
    #[must_use]
    pub fn code(&self) -> i64 {
        self.code
    }
}

impl fmt::Display for TrustEvaluationError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{} error {}", self.domain, self.code)
    }
}

impl std::error::Error for TrustEvaluationError {}

/// What the tests change about an evaluation. The default is what
/// [`PlatformVerifier`] uses: the system trust store.
#[derive(Default)]
struct Adjustments<'a> {
    /// Trusts these anchors alone, instead of the system trust store.
    anchors: Option<&'a [SecCertificate]>,
}

/// Evaluates `peer` with the platform trust.
fn evaluate(
    peer: &PeerCertificates<'_>,
    adjustments: &Adjustments<'_>,
) -> Result<(), CertRejected> {
    let Some(server_name) = peer.server_name() else {
        return Err(CertRejected::new(
            "no server name to check the certificate chain against",
        ));
    };

    let chain = peer
        .chain()
        .iter()
        .enumerate()
        .map(|(index, der)| {
            SecCertificate::from_der(der).map_err(|err| {
                CertRejected::new(format!(
                    "certificate {index} in the chain is not a valid DER certificate"
                ))
                .with_source(err)
            })
        })
        .collect::<Result<Vec<_>, _>>()?;

    let policy = SecPolicy::create_ssl(SslProtocolSide::SERVER, Some(server_name));
    let mut trust = SecTrust::create_with_certificates(&chain, &[policy])
        .map_err(|err| setup_failed("create the trust evaluation", err))?;
    trust
        .set_network_fetch_allowed(false)
        .map_err(|err| setup_failed("disable network fetching", err))?;
    if let Some(anchors) = adjustments.anchors {
        trust
            .set_anchor_certificates(anchors)
            .map_err(|err| setup_failed("set the anchors", err))?;
        trust
            .set_trust_anchor_certificates_only(true)
            .map_err(|err| setup_failed("restrict the anchors", err))?;
    }

    trust.evaluate_with_error().map_err(|err| {
        CertRejected::new(format!(
            "the platform does not trust the certificate chain for {server_name}: {}",
            err.description()
        ))
        .with_source(TrustEvaluationError {
            domain: err.domain().to_string(),
            code: err.code() as i64,
        })
    })
}

/// The rejection for a platform call that failed before the chain was
/// evaluated.
fn setup_failed(step: &str, err: SecurityError) -> CertRejected {
    CertRejected::new(format!("the platform could not {step}")).with_source(err)
}

#[cfg(test)]
mod tests {
    use std::error::Error;

    use super::*;

    /// The name in the generated leaf certificates.
    const SERVER_NAME: &str = "localhost";

    /// `OSStatus` codes from Apple's `SecBase.h`.
    const ERR_SEC_HOST_NAME_MISMATCH: i64 = -67602;
    const ERR_SEC_CERTIFICATE_EXPIRED: i64 = -67818;

    /// A leaf certificate for [`SERVER_NAME`], and the CA that issued it.
    struct IssuedChain {
        leaf_der: Vec<u8>,
        ca: SecCertificate,
    }

    impl IssuedChain {
        /// Issues a leaf that is valid now.
        fn valid() -> Self {
            Self::issue(|_| {})
        }

        /// Issues a leaf whose validity period ended in 2021.
        fn expired() -> Self {
            Self::issue(|params| {
                params.not_before = rcgen::date_time_ymd(2020, 1, 1);
                params.not_after = rcgen::date_time_ymd(2021, 1, 1);
            })
        }

        fn issue(adjust_leaf: impl FnOnce(&mut rcgen::CertificateParams)) -> Self {
            let ca_key = rcgen::KeyPair::generate().unwrap();
            let mut ca_params = rcgen::CertificateParams::new(Vec::new()).unwrap();
            ca_params.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
            ca_params.key_usages = vec![
                rcgen::KeyUsagePurpose::KeyCertSign,
                rcgen::KeyUsagePurpose::CrlSign,
            ];
            ca_params
                .distinguished_name
                .push(rcgen::DnType::CommonName, "test ca");
            let ca = rcgen::CertifiedIssuer::self_signed(ca_params, ca_key).unwrap();

            let leaf_key = rcgen::KeyPair::generate().unwrap();
            let mut leaf_params =
                rcgen::CertificateParams::new(vec![SERVER_NAME.to_string()]).unwrap();
            leaf_params.extended_key_usages = vec![rcgen::ExtendedKeyUsagePurpose::ServerAuth];
            adjust_leaf(&mut leaf_params);
            let leaf = leaf_params.signed_by(&leaf_key, &ca).unwrap();

            Self {
                leaf_der: leaf.der().to_vec(),
                ca: SecCertificate::from_der(ca.der()).unwrap(),
            }
        }

        /// Evaluates the leaf for `server_name`, with the CA as the one anchor.
        fn evaluate(&self, server_name: &str) -> Result<(), CertRejected> {
            let chain: [&[u8]; 1] = [&self.leaf_der];
            let anchors = [self.ca.clone()];

            super::evaluate(
                &PeerCertificates::new(&chain, Some(server_name)),
                &Adjustments {
                    anchors: Some(anchors.as_slice()),
                },
            )
        }
    }

    /// The platform's error code behind a rejection.
    fn platform_code(rejected: &CertRejected) -> i64 {
        rejected
            .source()
            .and_then(|source| source.downcast_ref::<TrustEvaluationError>())
            .unwrap_or_else(|| panic!("no platform error behind: {rejected}"))
            .code()
    }

    #[test]
    fn a_chain_up_to_a_trusted_anchor_is_accepted() {
        IssuedChain::valid()
            .evaluate(SERVER_NAME)
            .expect("the anchor verifies the chain");
    }

    #[test]
    fn an_expired_chain_is_rejected() {
        let rejected = IssuedChain::expired().evaluate(SERVER_NAME).unwrap_err();

        assert!(rejected.message().contains(SERVER_NAME), "{rejected}");
        assert_eq!(
            platform_code(&rejected),
            ERR_SEC_CERTIFICATE_EXPIRED,
            "{rejected}"
        );
    }

    #[test]
    fn a_hostname_mismatch_is_rejected() {
        let rejected = IssuedChain::valid().evaluate("wrong.invalid").unwrap_err();

        assert!(rejected.message().contains("wrong.invalid"), "{rejected}");
        assert_eq!(
            platform_code(&rejected),
            ERR_SEC_HOST_NAME_MISMATCH,
            "{rejected}"
        );
    }

    /// The system trust store, which [`PlatformVerifier`] uses, does not hold
    /// the test CA.
    #[test]
    fn a_chain_up_to_an_unknown_anchor_is_rejected() {
        let chain = IssuedChain::valid();
        let der: [&[u8]; 1] = [&chain.leaf_der];

        let rejected = PlatformVerifier::new()
            .verify(&PeerCertificates::new(&der, Some(SERVER_NAME)))
            .unwrap_err();

        assert!(rejected.message().contains(SERVER_NAME), "{rejected}");
        assert!(rejected.source().is_some(), "{rejected}");
    }

    #[test]
    fn a_chain_without_a_server_name_is_rejected() {
        let chain = IssuedChain::valid();
        let der: [&[u8]; 1] = [&chain.leaf_der];

        let rejected = PlatformVerifier::new()
            .verify(&PeerCertificates::new(&der, None))
            .unwrap_err();

        assert_eq!(
            rejected.message(),
            "no server name to check the certificate chain against"
        );
    }

    #[test]
    fn malformed_der_is_rejected() {
        let chain: [&[u8]; 1] = [b"der"];

        let rejected = PlatformVerifier::new()
            .verify(&PeerCertificates::new(&chain, Some(SERVER_NAME)))
            .unwrap_err();

        assert_eq!(
            rejected.message(),
            "certificate 0 in the chain is not a valid DER certificate"
        );
    }
}
