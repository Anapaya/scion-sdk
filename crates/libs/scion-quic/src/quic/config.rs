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

//! QUIC configuration options.

use std::{fmt, sync::Arc, time::Duration};

use crate::{
    DEFAULT_MAX_UDP_PAYLOAD_SIZE,
    quic::cert_verifier::{self, CertVerifier, RejectionReport},
};

/// Default handshake timeout.
const DEFAULT_HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(5);

/// Default idle timeout for connections.
const DEFAULT_IDLE_TIMEOUT: Duration = Duration::from_secs(30);

/// QUIC client configuration.
#[derive(Clone)]
pub struct QuicConfig {
    /// Timeout for QUIC handshake completion.
    pub handshake_timeout: Duration,
    /// Idle timeout for connections.
    pub idle_timeout: Duration,
    /// Maximum UDP payload size.
    pub max_udp_payload_size: usize,
    /// Application protocols to advertise (ALPN).
    pub application_protos: Vec<Vec<u8>>,
    /// Whether to verify the server certificate.
    pub verify_peer: bool,
    /// Optional path to CA certificates directory.
    pub ca_certs_directory: Option<String>,
    /// Optional path to a CA certificate PEM file for verification.
    pub ca_certs_file: Option<String>,
    /// Optional bundle of PEM-encoded CA certificates for verification, held in
    /// memory.
    ///
    /// This is for platforms whose trust anchors don't live in a file or a
    /// directory, e.g. Android, where the system key store holds them.
    ///
    /// Trust anchors accumulate: the bundle is added to the same certificate
    /// store as [`ca_certs_directory`](Self::ca_certs_directory) and
    /// [`ca_certs_file`](Self::ca_certs_file), so a chain verifies if it is
    /// anchored in any of the configured sources.
    pub ca_certs_pem: Option<Vec<u8>>,
    /// Optional verifier that decides whether the peer's certificate chain is
    /// trusted, in place of the trust anchors.
    ///
    /// A verifier replaces the built-in validation, so
    /// [`ca_certs_directory`](Self::ca_certs_directory),
    /// [`ca_certs_file`](Self::ca_certs_file) and
    /// [`ca_certs_pem`](Self::ca_certs_pem) are not consulted while one is set.
    /// See
    /// [`QuicConfigBuilder::with_cert_verifier`](QuicConfigBuilder::with_cert_verifier).
    pub cert_verifier: Option<Arc<dyn CertVerifier>>,
    /// Optional list of signature algorithm preferences for certificate verification.
    /// If set, overrides the default list. Use `squiche::SIGN_ED25519` (0x0807) to
    /// accept Ed25519 certificates.
    pub verify_algorithm_prefs: Option<Vec<u16>>,
    /// Initial max data.
    pub initial_max_data: u64,
    /// Initial max stream data for bidirectional local streams.
    pub initial_max_stream_data_bidi_local: u64,
    /// Initial max stream data for bidirectional remote streams.
    pub initial_max_stream_data_bidi_remote: u64,
    /// Initial max stream data for unidirectional streams.
    pub initial_max_stream_data_uni: u64,
    /// Initial max bidirectional streams.
    pub initial_max_streams_bidi: u64,
    /// Initial max unidirectional streams.
    pub initial_max_streams_uni: u64,
}

impl Default for QuicConfig {
    fn default() -> Self {
        Self {
            handshake_timeout: DEFAULT_HANDSHAKE_TIMEOUT,
            idle_timeout: DEFAULT_IDLE_TIMEOUT,
            max_udp_payload_size: DEFAULT_MAX_UDP_PAYLOAD_SIZE,
            application_protos: vec![b"h3".to_vec()],
            verify_peer: true,
            ca_certs_directory: None,
            ca_certs_file: None,
            ca_certs_pem: None,
            cert_verifier: None,
            verify_algorithm_prefs: None,
            initial_max_data: 10_000_000,
            initial_max_stream_data_bidi_local: 1_000_000,
            initial_max_stream_data_bidi_remote: 1_000_000,
            initial_max_stream_data_uni: 1_000_000,
            initial_max_streams_bidi: 100,
            initial_max_streams_uni: 100,
        }
    }
}

// Written by hand because `cert_verifier` holds caller code, which has no
// `Debug` of its own.
impl fmt::Debug for QuicConfig {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("QuicConfig")
            .field("handshake_timeout", &self.handshake_timeout)
            .field("idle_timeout", &self.idle_timeout)
            .field("max_udp_payload_size", &self.max_udp_payload_size)
            .field("application_protos", &self.application_protos)
            .field("verify_peer", &self.verify_peer)
            .field("ca_certs_directory", &self.ca_certs_directory)
            .field("ca_certs_file", &self.ca_certs_file)
            .field("ca_certs_pem", &self.ca_certs_pem)
            .field(
                "cert_verifier",
                &self.cert_verifier.as_ref().map(|_| "<cert verifier>"),
            )
            .field("verify_algorithm_prefs", &self.verify_algorithm_prefs)
            .field("initial_max_data", &self.initial_max_data)
            .field(
                "initial_max_stream_data_bidi_local",
                &self.initial_max_stream_data_bidi_local,
            )
            .field(
                "initial_max_stream_data_bidi_remote",
                &self.initial_max_stream_data_bidi_remote,
            )
            .field(
                "initial_max_stream_data_uni",
                &self.initial_max_stream_data_uni,
            )
            .field("initial_max_streams_bidi", &self.initial_max_streams_bidi)
            .field("initial_max_streams_uni", &self.initial_max_streams_uni)
            .finish()
    }
}

impl QuicConfig {
    /// Creates a new configuration builder.
    pub fn builder() -> QuicConfigBuilder {
        QuicConfigBuilder::default()
    }

    /// Creates a squiche::Config from this configuration.
    ///
    /// A [`cert_verifier`](Self::cert_verifier) is installed on the returned
    /// configuration and still fails the handshake it rejects, but the reason
    /// it gives is dropped. Connections established through
    /// [`Http3Client`](crate::h3::client::Http3Client) keep the reason and
    /// report it as
    /// [`EstablishError::CertificateRejected`](crate::h3::client::EstablishError::CertificateRejected).
    pub fn to_quiche_config(&self) -> Result<squiche::Config, squiche::Error> {
        self.to_quiche_config_reporting().map(|(config, _)| config)
    }

    /// Creates a squiche::Config, and the report that names why a verifier
    /// rejected the peer, for the connection that fails because of it.
    ///
    /// There is no report where no reason can be recorded: no verifier is set,
    /// or [`verify_peer`](Self::verify_peer) is `false`, which makes a
    /// rejection non-fatal.
    pub(crate) fn to_quiche_config_reporting(
        &self,
    ) -> Result<(squiche::Config, Option<RejectionReport>), squiche::Error> {
        let mut config = squiche::Config::new(squiche::SCION_PROTOCOL_VERSION)?;

        config.set_application_protos(
            &self
                .application_protos
                .iter()
                .map(|p| p.as_slice())
                .collect::<Vec<_>>(),
        )?;

        if let Some(ca_certs_dir) = &self.ca_certs_directory {
            config.load_verify_locations_from_directory(ca_certs_dir)?;
        }
        if let Some(ca_certs_file) = &self.ca_certs_file {
            config.load_verify_locations_from_file(ca_certs_file)?;
        }
        if let Some(ca_certs_pem) = &self.ca_certs_pem {
            config.load_verify_locations_from_memory(ca_certs_pem)?;
        }

        // Without `verify_peer` the verifier still runs, but squiche ignores
        // its verdict. A reason recorded then would be read as the cause of
        // whatever else fails this connection.
        let report =
            (self.cert_verifier.is_some() && self.verify_peer).then(RejectionReport::default);

        if let Some(verifier) = &self.cert_verifier {
            config.set_certificate_verifier(cert_verifier::to_squiche_verifier(
                verifier,
                report.clone(),
            ))?;
        }

        config.set_max_idle_timeout(self.idle_timeout.as_millis() as u64);
        config.set_max_recv_udp_payload_size(self.max_udp_payload_size);
        config.set_max_send_udp_payload_size(self.max_udp_payload_size);
        config.set_initial_max_data(self.initial_max_data);
        config.set_initial_max_stream_data_bidi_local(self.initial_max_stream_data_bidi_local);
        config.set_initial_max_stream_data_bidi_remote(self.initial_max_stream_data_bidi_remote);
        config.set_initial_max_stream_data_uni(self.initial_max_stream_data_uni);
        config.set_initial_max_streams_bidi(self.initial_max_streams_bidi);
        config.set_initial_max_streams_uni(self.initial_max_streams_uni);
        config.set_disable_active_migration(true);

        config.verify_peer(self.verify_peer);

        if let Some(prefs) = &self.verify_algorithm_prefs {
            config.set_verify_algorithm_prefs(prefs)?;
        }

        Ok((config, report))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::quic::cert_verifier::{CertRejected, PeerCertificates};

    fn rejecting_verifier() -> impl CertVerifier {
        |_: &PeerCertificates<'_>| Err(CertRejected::new("no thanks"))
    }

    #[test]
    fn a_report_exists_only_where_a_rejection_can_fail_the_handshake() {
        // No verifier, so nothing can be recorded.
        let (_, report) = QuicConfig::default().to_quiche_config_reporting().unwrap();
        assert!(report.is_none());

        // A verifier whose verdict is enforced.
        let (_, report) = QuicConfig::builder()
            .verify_peer(true)
            .with_cert_verifier(rejecting_verifier())
            .build()
            .to_quiche_config_reporting()
            .unwrap();
        assert!(report.is_some());

        // The same verifier, with squiche ignoring its verdict. A reason
        // recorded here would be read as the cause of an unrelated failure.
        let (_, report) = QuicConfig::builder()
            .verify_peer(false)
            .with_cert_verifier(rejecting_verifier())
            .build()
            .to_quiche_config_reporting()
            .unwrap();
        assert!(report.is_none());
    }
}

/// Builder for [`QuicConfig`].
#[derive(Debug, Default)]
pub struct QuicConfigBuilder {
    config: QuicConfig,
}

impl QuicConfigBuilder {
    /// Sets the handshake timeout.
    pub fn handshake_timeout(mut self, timeout: Duration) -> Self {
        self.config.handshake_timeout = timeout;
        self
    }

    /// Sets the idle timeout.
    pub fn idle_timeout(mut self, timeout: Duration) -> Self {
        self.config.idle_timeout = timeout;
        self
    }

    /// Sets the maximum UDP payload size.
    pub fn max_udp_payload_size(mut self, size: usize) -> Self {
        self.config.max_udp_payload_size = size;
        self
    }

    /// Sets the application protocols (ALPN).
    pub fn application_protos(mut self, protos: Vec<Vec<u8>>) -> Self {
        self.config.application_protos = protos;
        self
    }

    /// Sets whether to verify the peer's certificate.
    pub fn verify_peer(mut self, verify: bool) -> Self {
        self.config.verify_peer = verify;
        self
    }

    /// Sets the path to a CA certificates directory for verification.
    pub fn ca_certs_dir(mut self, path: impl Into<String>) -> Self {
        self.config.ca_certs_directory = Some(path.into());
        self
    }

    /// Sets the path to a CA certificate PEM file for verification.
    pub fn ca_certs_file(mut self, path: impl Into<String>) -> Self {
        self.config.ca_certs_file = Some(path.into());
        self
    }

    /// Sets a bundle of PEM-encoded CA certificates for verification, read from
    /// memory instead of the filesystem.
    ///
    /// Use this where the trust anchors are not on disk, e.g. on Android, where
    /// they come from the system key store. The bundle may hold several
    /// certificates; PEM blocks that hold something other than a certificate are
    /// skipped. A malformed bundle, or one without a single certificate, fails
    /// the later [`QuicConfig::to_quiche_config`], not this call.
    ///
    /// Anchors from here are added to the same store as those from
    /// [`ca_certs_file`](Self::ca_certs_file) and
    /// [`ca_certs_dir`](Self::ca_certs_dir), so the sources combine. Calling
    /// this twice replaces the bundle rather than extending it; concatenate the
    /// PEM blocks to load several.
    pub fn ca_certs_pem(mut self, pem: impl Into<Vec<u8>>) -> Self {
        self.config.ca_certs_pem = Some(pem.into());
        self
    }

    /// Sets a verifier that decides whether the peer's certificate chain is
    /// trusted, in place of the trust anchors.
    ///
    /// Use this where the platform does not let an application read its trust
    /// anchors, so that [`ca_certs_pem`](Self::ca_certs_pem) and the two path
    /// based sources have nothing to load.
    ///
    /// A verifier replaces the built-in validation rather than adding to it.
    /// While one is set, the anchors of
    /// [`ca_certs_file`](Self::ca_certs_file),
    /// [`ca_certs_dir`](Self::ca_certs_dir) and
    /// [`ca_certs_pem`](Self::ca_certs_pem) are not consulted, in whichever
    /// order the setters are called. The name check goes with them, so a
    /// verifier has to compare
    /// [`PeerCertificates::server_name`](super::cert_verifier::PeerCertificates::server_name)
    /// against the certificate itself.
    ///
    /// [`verify_peer`](Self::verify_peer) still decides whether the verdict is
    /// fatal. With `verify_peer(false)` the verifier runs and a rejection is
    /// ignored, exactly as a failed built-in check is ignored. A verifier is
    /// therefore not a way to switch verification on.
    ///
    /// A panic inside a verifier rejects the connection, with
    /// `the certificate verifier panicked` as the reason. It never unwinds into
    /// the TLS library.
    ///
    /// Calling this twice keeps the last verifier.
    ///
    /// ## Examples
    ///
    /// ```
    /// use scion_quic::quic::{
    ///     cert_verifier::{CertRejected, PeerCertificates},
    ///     config::QuicConfig,
    /// };
    ///
    /// let config = QuicConfig::builder()
    ///     .verify_peer(true)
    ///     .with_cert_verifier(|peer: &PeerCertificates<'_>| {
    ///         match peer.chain().first() {
    ///             Some(leaf) if leaf == &PINNED_LEAF => Ok(()),
    ///             _ => Err(CertRejected::new("the peer is not the pinned server")),
    ///         }
    ///     })
    ///     .build();
    /// # const PINNED_LEAF: &[u8] = b"";
    /// ```
    #[must_use]
    pub fn with_cert_verifier(mut self, verifier: impl CertVerifier) -> Self {
        self.config.cert_verifier = Some(Arc::new(verifier));
        self
    }

    /// Sets the signature algorithm preferences for certificate verification.
    pub fn verify_algorithm_prefs(mut self, prefs: Vec<u16>) -> Self {
        self.config.verify_algorithm_prefs = Some(prefs);
        self
    }

    /// Builds the configuration.
    pub fn build(self) -> QuicConfig {
        self.config
    }
}
