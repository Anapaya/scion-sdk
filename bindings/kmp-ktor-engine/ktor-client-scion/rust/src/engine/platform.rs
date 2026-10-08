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

//! The certificate trust of the platform, for HTTP/3 and for the TLS session
//! inside a gateway tunnel.
//!
//! On Apple targets, `QuicConfigBuilder::with_platform_verifier` sets a
//! `SecTrust` verifier. On all other targets that call has no effect, so
//! [`verifier::PlatformVerifier`] hands the chain to `rustls-platform-verifier`
//! instead.

// TODO: Move `verifier` into scion-quic, so that `with_platform_verifier` sets
// it on every target other than Apple.

use std::sync::Arc;

use scion_http3::scion_quic::quic::{
    cert_verifier::CertVerifier,
    config::{QuicConfig, QuicConfigBuilder},
};

/// A QUIC config that verifies the peer with the platform trust.
#[cfg(target_vendor = "apple")]
pub(crate) fn quic_config() -> QuicConfigBuilder {
    QuicConfig::builder().with_platform_verifier()
}

/// A QUIC config that verifies the peer with the platform trust.
#[cfg(not(target_vendor = "apple"))]
pub(crate) fn quic_config() -> QuicConfigBuilder {
    QuicConfig::builder().with_cert_verifier(verifier::PlatformVerifier::new())
}

/// The same verifier that [`quic_config`] sets.
#[cfg(target_vendor = "apple")]
pub(crate) fn cert_verifier() -> Arc<dyn CertVerifier> {
    Arc::new(scion_http3::scion_quic::quic::cert_verifier::apple::PlatformVerifier::new())
}

/// The same verifier that [`quic_config`] sets.
#[cfg(not(target_vendor = "apple"))]
pub(crate) fn cert_verifier() -> Arc<dyn CertVerifier> {
    Arc::new(verifier::PlatformVerifier::new())
}

#[cfg(not(target_vendor = "apple"))]
mod verifier {
    use std::{
        fmt,
        panic::{self, AssertUnwindSafe},
        sync::{Arc, OnceLock},
    };

    use rustls::{
        client::danger::ServerCertVerifier,
        crypto::CryptoProvider,
        pki_types::{CertificateDer, ServerName, UnixTime},
    };
    use rustls_platform_verifier::Verifier as RustlsPlatformVerifier;
    use scion_http3::scion_quic::quic::cert_verifier::{
        CertRejected, CertVerifier, PeerCertificates,
    };
    use tokio::runtime::{Handle, RuntimeFlavor};

    /// Verifies the peer's certificate chain with the platform trust.
    ///
    /// `rustls-platform-verifier` does the evaluation:
    ///
    /// - On Android, a trust manager over the `AndroidCAStore` key store evaluates the chain. It
    ///   trusts the system CAs and the user CAs, and it ignores the Network Security Config of the
    ///   application. The application has to initialize `rustls-platform-verifier` before the first
    ///   handshake. Without that, every chain is rejected.
    /// - On Windows, the CryptoAPI evaluates the chain against the system store.
    /// - On Linux and other Unix targets, WebPKI evaluates the chain against the system store. The
    ///   verifier loads the store at the first handshake. `SSL_CERT_FILE` and `SSL_CERT_DIR`
    ///   override the location.
    ///
    /// The evaluation runs on the task that drives the handshake. It can block:
    /// on Android it calls into the JVM, and the trust manager can check
    /// revocation over the network. The first evaluation also builds the
    /// verifier, which loads the system store on Linux. So the evaluation runs
    /// in `tokio::task::block_in_place`: the other tasks of the worker move to
    /// another thread, and only this handshake waits.
    pub struct PlatformVerifier {
        verifier: OnceLock<Result<RustlsPlatformVerifier, rustls::Error>>,
        /// Anchors in addition to the platform trust, for the tests only.
        ///
        /// Android has no such option: `rustls-platform-verifier` offers
        /// `new_with_extra_roots` on every target except Android. There, the
        /// trust manager over `AndroidCAStore` in the JVM evaluates the chain,
        /// and the crate passes it no anchors of its own.
        #[cfg(all(test, not(target_os = "android")))]
        extra_roots: Vec<CertificateDer<'static>>,
    }

    impl PlatformVerifier {
        /// Creates the verifier.
        #[must_use]
        pub fn new() -> Self {
            Self {
                verifier: OnceLock::new(),
                #[cfg(all(test, not(target_os = "android")))]
                extra_roots: Vec::new(),
            }
        }

        fn verifier(&self) -> Result<&RustlsPlatformVerifier, CertRejected> {
            self.verifier
                .get_or_init(|| {
                    // Use default provider or fall back to ring if not available.
                    let provider = CryptoProvider::get_default()
                        .cloned()
                        .unwrap_or_else(|| Arc::new(rustls::crypto::ring::default_provider()));

                    #[cfg(all(test, not(target_os = "android")))]
                    if !self.extra_roots.is_empty() {
                        return RustlsPlatformVerifier::new_with_extra_roots(
                            self.extra_roots.clone(),
                            provider,
                        );
                    }

                    RustlsPlatformVerifier::new(provider)
                })
                .as_ref()
                .map_err(|err| {
                    CertRejected::new(format!("the platform verifier is not available: {err}"))
                        .with_source(err.clone())
                })
        }
    }

    impl Default for PlatformVerifier {
        fn default() -> Self {
            Self::new()
        }
    }

    impl fmt::Debug for PlatformVerifier {
        fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            f.debug_struct("PlatformVerifier").finish_non_exhaustive()
        }
    }

    impl CertVerifier for PlatformVerifier {
        fn verify(&self, peer: &PeerCertificates<'_>) -> Result<(), CertRejected> {
            // Check the server name.
            let Some(server_name) = peer.server_name() else {
                return Err(CertRejected::new(
                    "no server name to check the certificate chain against",
                ));
            };
            let name = ServerName::try_from(server_name).map_err(|err| {
                CertRejected::new(format!("{server_name} is not a valid server name"))
                    .with_source(err)
            })?;

            // Split the chain.
            let (end_entity, intermediates) = peer
                .chain()
                .split_first()
                .ok_or_else(|| CertRejected::new("the peer sent no certificate"))?;
            let end_entity = CertificateDer::from(*end_entity);
            let intermediates: Vec<_> = intermediates
                .iter()
                .map(|der| CertificateDer::from(*der))
                .collect();

            // Prepare the evaluation.
            let evaluate = || {
                let verifier = self.verifier()?;

                // On Android, an uninitialized rustls-platform-verifier panics.
                panic::catch_unwind(AssertUnwindSafe(|| {
                    verifier.verify_server_cert(
                        &end_entity,
                        &intermediates,
                        &name,
                        &[],
                        UnixTime::now(),
                    )
                }))
                .map_err(|_| {
                    CertRejected::new(
                        "the platform verifier failed. On Android, initialize \
                         rustls-platform-verifier before the first connection",
                    )
                })
            };

            // Run it off the worker. block_in_place panics on a current-thread
            // runtime, so the evaluation runs in place there.
            let on_current_thread = Handle::try_current()
                .is_ok_and(|handle| handle.runtime_flavor() == RuntimeFlavor::CurrentThread);
            // The lint forbids block_in_place because of that panic. The check
            // above avoids it.
            //
            // TODO: Make `CertVerifier` in scion-quic async, then use
            // `spawn_blocking` here instead.
            #[allow(clippy::disallowed_methods)]
            let verdict = if on_current_thread {
                evaluate()
            } else {
                tokio::task::block_in_place(evaluate)
            }?;

            verdict.map(|_| ()).map_err(|err| {
                CertRejected::new(format!(
                    "the platform does not trust the certificate chain for {server_name}: {err}"
                ))
                .with_source(err)
            })
        }
    }

    #[cfg(all(test, not(target_os = "android")))]
    mod tests {
        use std::error::Error;

        use super::*;

        /// The name in the generated leaf certificates.
        const SERVER_NAME: &str = "localhost";

        /// A leaf certificate for [`SERVER_NAME`], and the CA that issued it.
        struct IssuedChain {
            leaf_der: Vec<u8>,
            ca_der: CertificateDer<'static>,
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
                // Create the CA.
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

                // Create the leaf.
                let leaf_key = rcgen::KeyPair::generate().unwrap();
                let mut leaf_params =
                    rcgen::CertificateParams::new(vec![SERVER_NAME.to_string()]).unwrap();
                leaf_params.extended_key_usages = vec![rcgen::ExtendedKeyUsagePurpose::ServerAuth];
                adjust_leaf(&mut leaf_params);
                let leaf = leaf_params.signed_by(&leaf_key, &ca).unwrap();

                Self {
                    leaf_der: leaf.der().to_vec(),
                    ca_der: ca.der().clone().into_owned(),
                }
            }

            /// Verifies the leaf for `server_name`, with the CA as an extra root.
            fn verify(&self, server_name: &str) -> Result<(), CertRejected> {
                // Trust the CA as an extra root.
                let chain: [&[u8]; 1] = [&self.leaf_der];
                let verifier = PlatformVerifier {
                    verifier: OnceLock::new(),
                    extra_roots: vec![self.ca_der.clone()],
                };

                verifier.verify(&PeerCertificates::new(&chain, Some(server_name)))
            }
        }

        #[test]
        fn a_chain_up_to_a_trusted_anchor_is_accepted() {
            IssuedChain::valid()
                .verify(SERVER_NAME)
                .expect("the extra root verifies the chain");
        }

        #[test]
        fn an_expired_chain_is_rejected() {
            let rejected = IssuedChain::expired().verify(SERVER_NAME).unwrap_err();

            // Check the reason.
            assert!(rejected.message().contains(SERVER_NAME), "{rejected}");
            assert!(rejected.source().is_some(), "{rejected}");
        }

        #[test]
        fn a_hostname_mismatch_is_rejected() {
            let rejected = IssuedChain::valid().verify("wrong.invalid").unwrap_err();

            // Check the reason.
            assert!(rejected.message().contains("wrong.invalid"), "{rejected}");
        }

        /// The system trust store does not hold the test CA.
        #[test]
        fn a_chain_up_to_an_unknown_anchor_is_rejected() {
            // Issue a chain.
            let chain = IssuedChain::valid();
            let der: [&[u8]; 1] = [&chain.leaf_der];

            // Verify with the system trust only.
            let rejected = PlatformVerifier::new()
                .verify(&PeerCertificates::new(&der, Some(SERVER_NAME)))
                .unwrap_err();

            // Check the reason.
            assert!(rejected.source().is_some(), "{rejected}");
        }

        #[test]
        fn a_chain_without_a_server_name_is_rejected() {
            // Issue a chain.
            let chain = IssuedChain::valid();
            let der: [&[u8]; 1] = [&chain.leaf_der];

            // Verify without a name.
            let rejected = PlatformVerifier::new()
                .verify(&PeerCertificates::new(&der, None))
                .unwrap_err();

            // Check the reason.
            assert_eq!(
                rejected.message(),
                "no server name to check the certificate chain against"
            );
        }
    }
}
