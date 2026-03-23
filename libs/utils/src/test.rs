// Copyright 2025 Anapaya Systems
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
//! Utilities for testing.

use std::{sync::Arc, time::Duration};

use anapaya_quinn::{
    TransportConfig,
    crypto::rustls::QuicServerConfig,
    rustls::pki_types::{CertificateDer, PrivatePkcs8KeyDer},
};
use ed25519_dalek::pkcs8::EncodePrivateKey;
use rustls::pki_types::PrivateKeyDer;

/// Generate a self-signed certificate with keys derived deterministically from
/// a fixed seed.
///
/// This function uses an Ed25519 keypair generated from a fixed 32-byte seed
/// and then uses rcgen to build a self-signed certificate valid for
/// subject alternative names provided in the `subject_alt_names` parameter.
pub fn generate_cert(
    seed: [u8; 32],
    subject_alt_names: Vec<String>,
    alpn_protocols: Vec<Vec<u8>>,
) -> (CertificateDer<'static>, anapaya_quinn::ServerConfig) {
    let dalek_keypair = ed25519_dalek::SigningKey::from_bytes(&seed);

    let kp = ed25519_dalek::pkcs8::KeypairBytes {
        secret_key: *dalek_keypair.as_bytes(),
        public_key: Some(ed25519_dalek::pkcs8::PublicKeyBytes(
            *dalek_keypair.verifying_key().as_bytes(),
        )),
    };
    let pkcs8 = kp.to_pkcs8_der().unwrap();
    let pem = pem::Pem::new("PRIVATE KEY", pkcs8.as_bytes());
    let pem_str = pem::encode(&pem);
    let key_pair = rcgen::KeyPair::from_pem(&pem_str).unwrap();

    // Prepare certificate parameters.
    let cert = rcgen::CertificateParams::new(subject_alt_names)
        .unwrap()
        .self_signed(&key_pair)
        .unwrap();

    let cert_der = CertificateDer::from(cert.der().to_vec());
    let priv_key = PrivatePkcs8KeyDer::from(key_pair.serialize_der());
    let mut tls_config = rustls::ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(vec![cert_der.clone()], PrivateKeyDer::Pkcs8(priv_key))
        .unwrap();
    tls_config.alpn_protocols = alpn_protocols;
    let mut server_config = anapaya_quinn::ServerConfig::with_crypto(Arc::new(
        QuicServerConfig::try_from(tls_config).expect("is valid config"),
    ));
    let mut transport_config = TransportConfig::default();
    // 5 secs == 1/6 default idle timeout
    transport_config.keep_alive_interval(Some(Duration::from_secs(5)));
    server_config.transport_config(Arc::new(transport_config));

    (cert_der, server_config)
}
