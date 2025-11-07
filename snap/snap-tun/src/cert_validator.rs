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
//! Module containing an implementation of a certificate validator.

use quinn::rustls::{self, client::danger::ServerCertVerified};
use x509_cert::{Certificate, der::Decode, spki::ObjectIdentifier};

/// Validation only succeeds if the subject's Ed25519 public key matches the
/// configured public key.
///
/// The intended use case is verifying the identity of a remote server for which
/// the public key is known and the server presents a self-signed certificate
/// containing an Ed25519 public key.
///
/// Other than the server's public key, all parameters of the server's
/// certificate are ignored.
#[derive(Debug)]
pub struct Ed25519ServerCertValidator(pub [u8; 32]);

// OID for Ed25519 (1.3.101.112)
const ED25519_OID: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.3.101.112");

impl rustls::client::danger::ServerCertVerifier for Ed25519ServerCertValidator {
    fn verify_server_cert(
        &self,
        end_entity: &rustls::pki_types::CertificateDer<'_>,
        _intermediates: &[rustls::pki_types::CertificateDer<'_>],
        _server_name: &rustls::pki_types::ServerName<'_>,
        _ocsp_response: &[u8],
        _now: rustls::pki_types::UnixTime,
    ) -> Result<rustls::client::danger::ServerCertVerified, rustls::Error> {
        verify_ed25519_public_key(&self.0, end_entity)
    }

    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &rustls::pki_types::CertificateDer<'_>,
        _dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        Err(rustls::Error::PeerIncompatible(
            rustls::PeerIncompatible::Tls12NotOffered,
        ))
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &rustls::pki_types::CertificateDer<'_>,
        dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        let provider = rustls::crypto::ring::default_provider();
        let all_algs = provider.signature_verification_algorithms;

        if dss.scheme != rustls::SignatureScheme::ED25519 {
            return Err(rustls::Error::PeerIncompatible(
                rustls::PeerIncompatible::NoSignatureSchemesInCommon,
            ));
        }

        rustls::crypto::verify_tls13_signature(message, cert, dss, &all_algs)
    }

    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        vec![rustls::SignatureScheme::ED25519]
    }
}

fn verify_ed25519_public_key(
    expected_pubkey: &[u8; 32],
    end_entity: &[u8],
) -> Result<rustls::client::danger::ServerCertVerified, rustls::Error> {
    let certificate = Certificate::from_der(end_entity)
        .map_err(|e| rustls::Error::General(format!("failed to parse certificate: {e}")))?;
    let spki = &certificate.tbs_certificate.subject_public_key_info;

    if spki.algorithm.oid != ED25519_OID {
        return Err(rustls::Error::General(
            "server's public key algorithm is not Ed25519.".to_string(),
        ));
    }

    let public_key_bytes = match spki.subject_public_key.as_bytes() {
        Some(bytes) => bytes,
        None => {
            return Err(rustls::Error::General(
                "failed to extract public key bytes from certificate.".to_string(),
            ));
        }
    };

    if expected_pubkey.as_slice() != public_key_bytes {
        return Err(rustls::Error::General(
            "server's public key did not match the expected pinned public key.".to_string(),
        ));
    }
    Ok(ServerCertVerified::assertion())
}

#[cfg(test)]
mod tests {
    use ed25519_dalek::pkcs8::EncodePrivateKey;
    use quinn::rustls::pki_types::CertificateDer;

    use super::verify_ed25519_public_key;

    #[test]
    fn verify_ed25519_certificate_succeeds() {
        let seed = [84u8; 32];
        let dalek_keypair = ed25519_dalek::SigningKey::from_bytes(&seed);

        let expected_pubkey = *dalek_keypair.verifying_key().as_bytes();

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
        let cert = rcgen::CertificateParams::new(vec!["test".into()])
            .unwrap()
            .self_signed(&key_pair)
            .unwrap();

        let cert_der = CertificateDer::from(cert.der().to_vec());

        assert!(verify_ed25519_public_key(&expected_pubkey, &cert_der).is_ok());
    }
}
