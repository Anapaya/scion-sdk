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

//! Support for signing and validating protobuf messages with ECDSA signatures.

use std::borrow::Cow;

use ecdsa::signature::{
    self,
    hazmat::{PrehashSigner, PrehashVerifier},
};
use prost::{DecodeError, Message};
use prost_types::Timestamp;
use scion_protobuf::control_plane::v1::VerificationKeyId;
use serde::{Deserialize, Serialize};
use sha2::Digest;
use thiserror::Error;

/// Supported digest algorithms for signing.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[allow(missing_docs)]
pub enum DigestAlgorithm {
    Sha256,
    Sha384,
    Sha512,
}

#[derive(Debug, Error)]
/// Validation failures returned when verifying signed messages.
pub enum ValidateError {
    /// Header-and-body framing could not be decoded.
    #[error("invalid header and body")]
    InvalidHeaderAndBody,
    /// Header could not be decoded.
    #[error("invalid header")]
    InvalidHeader,
    /// Validation key id could not be decoded from the header, or is malformed.
    #[error("invalid validation key id")]
    InvalidValidationKeyId,
    /// The length of the provided associated data does not match the length specified in the
    /// header.
    #[error("associated data length mismatch (expected {expected}, got {actual})")]
    InvalidAssociatedDataLength {
        /// Expected length of the associated data as specified in the header.
        expected: usize,
        /// Actual length of the associated data provided for validation.
        actual: usize,
    },
    /// Signature algorithm is unknown or unsupported.
    #[error("invalid digest algorithm")]
    InvalidDigestAlgorithm,
    /// Body could not be decoded.
    #[error("invalid body")]
    InvalidBody,
    /// Metadata could not be decoded.
    #[error("invalid metadata")]
    InvalidMetadata,
    /// The provided key id does not match the header key id.
    #[error("no key matching key found: {0}")]
    KeyMissing(Cow<'static, str>),
    /// Signature bytes are malformed.
    #[error("signature malformed")]
    SignatureMalformed,
    /// Signature verification failed.
    #[error("signature verification failed")]
    SignatureVerificationFailed(#[source] ecdsa::Error),
}

/// Signed protobuf message.
///
/// The Message is composed of:
/// - HeaderAndBody: [HeaderAndBodyInternal](scion_protobuf::crypto::v1::HeaderAndBodyInternal)
///   Where:
///   - Header: Contains signature metadata such as the signature algorithm, key identifier,
///     timestamp, and optional metadata.
///   - Body: A encoded protobuf message containing the actual content being signed
///
/// - Signature: A Der-encoded ECDSA signature over the header, body and associated data, using the
///   specified digest algorithm.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct SignedMessage {
    /// The header and body of the message.
    pub header_and_body: Vec<u8>,
    /// The signature of the message.
    pub signature: Vec<u8>,
}
// Signing
impl SignedMessage {
    /// Signs the given message using the provided ECDSA signing key and digest algorithm.
    ///
    /// ## Parameters
    /// - `key`: The ECDSA signing key to use for signing the message.
    /// - `digest_algo`: The digest algorithm to use for hashing the message before signing.
    /// - `timestamp`: The timestamp to include in the signature header.
    /// - `verification_key_id`: The identifier for the verification key to include in the signature
    ///   header.
    /// - `associated_data`: Additional data that is covered by the signature but not included in
    ///   the header and body.
    /// - `message`: The message to be wrapped and signed.
    /// - `metadata`: Arbitrary metadata to include in the signature header. If not needed pass
    ///   `&()`.
    pub fn sign<'a>(
        key: &'a p256::ecdsa::SigningKey,
        digest_algo: DigestAlgorithm,
        timestamp: u32,
        verification_key_id: Option<VerificationKeyId>,
        associated_data: (usize, impl IntoIterator<Item = &'a [u8]>),
        message: &impl prost::Message,
        metadata: &impl prost::Message,
    ) -> signature::Result<SignedMessage> {
        let signature_algorithm = match digest_algo {
            DigestAlgorithm::Sha256 => {
                scion_protobuf::crypto::v1::SignatureAlgorithm::EcdsaWithSha256
            }
            DigestAlgorithm::Sha384 => {
                scion_protobuf::crypto::v1::SignatureAlgorithm::EcdsaWithSha384
            }
            DigestAlgorithm::Sha512 => {
                scion_protobuf::crypto::v1::SignatureAlgorithm::EcdsaWithSha512
            }
        };

        let verification_key_id = verification_key_id.map(|k| k.encode_to_vec());

        let header = scion_protobuf::crypto::v1::Header {
            signature_algorithm: signature_algorithm as i32,
            verification_key_id: verification_key_id.unwrap_or_default(),
            timestamp: Some(Timestamp {
                seconds: timestamp as i64,
                nanos: 0,
            }),
            associated_data_length: associated_data.0 as i32,
            metadata: metadata.encode_to_vec(),
        };

        let header_and_body = scion_protobuf::crypto::v1::HeaderAndBodyInternal {
            header: header.encode_to_vec(),
            body: message.encode_to_vec(),
        };

        // Signature is (header_and_body || associated_data...) we pass everything as a iterator
        let encoded_header_and_body = header_and_body.encode_to_vec();
        let signature: p256::ecdsa::Signature = {
            let hash = match digest_algo {
                DigestAlgorithm::Sha256 => {
                    hash::<sha2::Sha256>(&encoded_header_and_body, associated_data.1)
                }
                DigestAlgorithm::Sha384 => {
                    hash::<sha2::Sha384>(&encoded_header_and_body, associated_data.1)
                }
                DigestAlgorithm::Sha512 => {
                    hash::<sha2::Sha512>(&encoded_header_and_body, associated_data.1)
                }
            };

            key.sign_prehash(&hash)?
        };

        // We use ASN1 DER encoding for the signature.
        let signature = signature.to_der().as_bytes().to_vec();

        Ok(SignedMessage {
            header_and_body: encoded_header_and_body,
            signature,
        })
    }
}
// Validation
impl SignedMessage {
    /// Validates the signature of the signed message using the provided ECDSA verification key.
    ///
    /// ## Parameters
    /// - `key_provider`: A function taking the content of `header.verification_key_id` and returns
    ///   the corresponding `p256::ecdsa::VerifyingKey` if available. The `VerificationKeyId` is
    ///   extracted from the message header, and can be used to look up the appropriate key for
    ///   signature verification. If the header does not include a key id, the function will be
    ///   called with an empty slice.
    /// - `associated_data`: Additional data that is covered by the signature but not included in
    ///   the header and body, which should be provided for validation if it was included during
    ///   signing.
    pub fn validate<'a>(
        &'a self,
        key_provider: impl Fn(&[u8]) -> Result<p256::ecdsa::VerifyingKey, ValidateError>,
        associated_data: (usize, impl IntoIterator<Item = &'a [u8]>),
    ) -> Result<(scion_protobuf::crypto::v1::Header, Vec<u8>), ValidateError> {
        {
            // Check header
            let header_and_body = scion_protobuf::crypto::v1::HeaderAndBodyInternal::decode(
                &self.header_and_body[..],
            )
            .map_err(|_| ValidateError::InvalidHeaderAndBody)?;

            let header = scion_protobuf::crypto::v1::Header::decode(&header_and_body.header[..])
                .map_err(|_| ValidateError::InvalidHeader)?;

            let verification_key = key_provider(&header.verification_key_id[..])?;

            if header.associated_data_length as usize != associated_data.0 {
                return Err(ValidateError::InvalidAssociatedDataLength {
                    expected: header.associated_data_length as usize,
                    actual: associated_data.0,
                });
            }

            let algo = match scion_protobuf::crypto::v1::SignatureAlgorithm::try_from(
                header.signature_algorithm,
            )
            .ok()
            {
                Some(scion_protobuf::crypto::v1::SignatureAlgorithm::EcdsaWithSha256) => {
                    DigestAlgorithm::Sha256
                }
                Some(scion_protobuf::crypto::v1::SignatureAlgorithm::EcdsaWithSha384) => {
                    DigestAlgorithm::Sha384
                }
                Some(scion_protobuf::crypto::v1::SignatureAlgorithm::EcdsaWithSha512) => {
                    DigestAlgorithm::Sha512
                }
                _ => return Err(ValidateError::InvalidDigestAlgorithm),
            };

            // Verify signature is (header_and_body || associated_data...) we pass everything as a
            // iterator
            let hash = {
                match algo {
                    DigestAlgorithm::Sha256 => {
                        hash::<sha2::Sha256>(self.header_and_body.as_slice(), associated_data.1)
                    }
                    DigestAlgorithm::Sha384 => {
                        hash::<sha2::Sha384>(self.header_and_body.as_slice(), associated_data.1)
                    }
                    DigestAlgorithm::Sha512 => {
                        hash::<sha2::Sha512>(self.header_and_body.as_slice(), associated_data.1)
                    }
                }
            };

            let sig = p256::ecdsa::Signature::from_der(&self.signature)
                .map_err(|_| ValidateError::SignatureMalformed)?;

            verification_key
                .verify_prehash(&hash, &sig)
                .map_err(ValidateError::SignatureVerificationFailed)?;

            Ok((header, header_and_body.body))
        }
    }
}
// Decoding
impl SignedMessage {
    /// Decodes a signed message after validating its signature.
    pub fn decode_validated<'a, Body, Metadata>(
        &'a self,
        key_provider: impl Fn(&[u8]) -> Result<p256::ecdsa::VerifyingKey, ValidateError>,
        associated_data: (usize, impl IntoIterator<Item = &'a [u8]>),
    ) -> Result<(Body, Option<Metadata>), ValidateError>
    where
        Body: prost::Message + Default,
        Metadata: prost::Message + Default,
    {
        let (header, body) = self.validate(key_provider, associated_data)?;

        let body = Body::decode(&body[..]).map_err(|_| ValidateError::InvalidBody)?;

        let metadata = if !header.metadata.is_empty() {
            Some(
                Metadata::decode(&header.metadata[..])
                    .map_err(|_| ValidateError::InvalidMetadata)?,
            )
        } else {
            None
        };

        Ok((body, metadata))
    }

    /// Decodes the header and body of the signed message, returning the body and optional metadata.
    ///
    /// If metadata should be ignored, the caller can use `()` as the `Metadata` type parameter
    pub fn decode_unvalidated<Body, Metadata>(
        &self,
    ) -> Result<(Body, Option<Metadata>), DecodeError>
    where
        Body: prost::Message + Default,
        Metadata: prost::Message + Default,
    {
        let header_and_body =
            scion_protobuf::crypto::v1::HeaderAndBodyInternal::decode(&self.header_and_body[..])?;
        let header = scion_protobuf::crypto::v1::Header::decode(&header_and_body.header[..])?;

        let body = Body::decode(&header_and_body.body[..])?;

        let metadata = if !header.metadata.is_empty() {
            Some(Metadata::decode(&header.metadata[..])?)
        } else {
            None
        };

        Ok((body, metadata))
    }
}
// Protobuf conversions
impl SignedMessage {
    /// Converts this signed message into the protobuf representation used for RPCs.
    pub fn into_rpc(self) -> scion_protobuf::crypto::v1::SignedMessage {
        scion_protobuf::crypto::v1::SignedMessage {
            header_and_body: self.header_and_body,
            signature: self.signature,
        }
    }

    /// Converts from the protobuf representation of a signed message to this struct.
    pub fn from_rpc(value: scion_protobuf::crypto::v1::SignedMessage) -> Self {
        Self {
            header_and_body: value.header_and_body,
            signature: value.signature,
        }
    }
}
impl From<scion_protobuf::crypto::v1::SignedMessage> for SignedMessage {
    fn from(value: scion_protobuf::crypto::v1::SignedMessage) -> Self {
        SignedMessage::from_rpc(value)
    }
}
impl From<SignedMessage> for scion_protobuf::crypto::v1::SignedMessage {
    fn from(signed: SignedMessage) -> Self {
        signed.into_rpc()
    }
}

/// Computes the hash of the given data using the specified digest algorithm.
fn hash<D: Digest>(msg: &[u8], data: impl IntoIterator<Item: AsRef<[u8]>>) -> Vec<u8> {
    let mut hasher = D::new();
    hasher.update(msg);
    for chunk in data {
        hasher.update(chunk.as_ref());
    }
    hasher.finalize().to_vec()
}

#[cfg(test)]
mod test {
    use ecdsa::signature::rand_core::OsRng;
    use prost::Message;

    use super::*;

    fn test_data() -> (
        p256::ecdsa::SigningKey,
        VerificationKeyId,
        Vec<u8>,
        scion_protobuf::control_plane::v1::SegmentsRequest,
        scion_protobuf::control_plane::v1::SegmentsRequest,
    ) {
        let key = p256::ecdsa::SigningKey::random(&mut OsRng);
        let key_id: Vec<u8> = key.to_bytes()[..16].to_vec();
        let key_id = VerificationKeyId {
            isd_as: 1,
            subject_key_id: key_id.clone(),
            trc_base: 125,
            trc_serial: 31536,
        };

        let assoc_data = "hello crypto".as_bytes().to_vec();
        let message = scion_protobuf::control_plane::v1::SegmentsRequest {
            src_isd_as: 1,
            dst_isd_as: 2,
        };
        let metadata = scion_protobuf::control_plane::v1::SegmentsRequest {
            src_isd_as: 2,
            dst_isd_as: 3,
        };

        (key, key_id, assoc_data, message, metadata)
    }

    fn signed_message_with_metadata(
        key: &p256::ecdsa::SigningKey,
        key_id: VerificationKeyId,
        assoc_data: &Vec<u8>,
        message: &scion_protobuf::control_plane::v1::SegmentsRequest,
        metadata: &scion_protobuf::control_plane::v1::SegmentsRequest,
    ) -> SignedMessage {
        SignedMessage::sign(
            key,
            DigestAlgorithm::Sha256,
            0, // timestamp
            Some(key_id),
            (assoc_data.len(), std::iter::once(assoc_data.as_slice())),
            message,
            metadata,
        )
        .expect("failed to sign message")
    }

    #[test]
    fn should_roundtrip() {
        let (key, key_id, assoc_data, message, metadata) = test_data();
        let signed_message =
            signed_message_with_metadata(&key, key_id.clone(), &assoc_data, &message, &metadata);

        let verifying_key = key.verifying_key();
        let validation_result = signed_message
            .decode_validated::<scion_protobuf::control_plane::v1::SegmentsRequest, scion_protobuf::control_plane::v1::SegmentsRequest>(             |encoded_key_id| {
                    let decoded_key_id = VerificationKeyId::decode(encoded_key_id)
                        .map_err(|_| ValidateError::InvalidValidationKeyId)?;
                    if decoded_key_id != key_id {
                        return Err(ValidateError::KeyMissing(format!(
                            "expected key id {:?}, got {:?}",
                            key_id, decoded_key_id
                        ).into()));
                    }
                    Ok(*verifying_key)
                },
                (assoc_data.len(), std::iter::once(assoc_data.as_slice())),
            );

        assert!(
            validation_result.is_ok(),
            "signature validation failed: {:?}",
            validation_result
        );

        let (decoded_message, decoded_metadata) = validation_result.unwrap();

        assert_eq!(
            decoded_message, message,
            "decoded message does not match original"
        );
        assert_eq!(
            decoded_metadata.unwrap(),
            metadata,
            "decoded metadata does not match original"
        );
    }

    #[test]
    fn should_fail_on_tampered_body() {
        let (key, key_id, assoc_data, message, metadata) = test_data();
        let signed_message =
            signed_message_with_metadata(&key, key_id.clone(), &assoc_data, &message, &metadata);

        let mut tampered = signed_message.clone();
        let mut header_and_body = scion_protobuf::crypto::v1::HeaderAndBodyInternal::decode(
            &tampered.header_and_body[..],
        )
        .expect("failed to decode header and body");
        if let Some(byte) = header_and_body.body.first_mut() {
            *byte ^= 0x01;
        } else {
            header_and_body.body.push(0x01);
        }
        tampered.header_and_body = header_and_body.encode_to_vec();

        let verifying_key = key.verifying_key();
        let result = tampered.validate(
            |encoded_key_id| {
                let decoded_key_id = VerificationKeyId::decode(encoded_key_id)
                    .map_err(|_| ValidateError::InvalidValidationKeyId)?;
                if decoded_key_id != key_id {
                    return Err(ValidateError::KeyMissing(
                        format!("expected key id {:?}, got {:?}", key_id, decoded_key_id).into(),
                    ));
                }
                Ok(*verifying_key)
            },
            (assoc_data.len(), std::iter::once(assoc_data.as_slice())),
        );

        assert!(matches!(
            result,
            Err(ValidateError::SignatureVerificationFailed(_))
        ));
    }

    #[test]
    fn should_fail_on_wrong_key_id() {
        let (key, key_id, assoc_data, message, metadata) = test_data();
        let signed_message =
            signed_message_with_metadata(&key, key_id.clone(), &assoc_data, &message, &metadata);

        let verifying_key = key.verifying_key();
        let wrong_key_id_bytes: Vec<u8> = key_id.subject_key_id.iter().map(|b| b ^ 0x01).collect();
        let result = signed_message.validate(
            |encoded_key_id| {
                // Return error if the key id doesn't match what we expect
                if encoded_key_id != wrong_key_id_bytes {
                    return Err(ValidateError::KeyMissing("key id mismatch".into()));
                }
                Ok(*verifying_key)
            },
            (assoc_data.len(), std::iter::once(assoc_data.as_slice())),
        );

        assert!(matches!(result, Err(ValidateError::KeyMissing(_))));
    }

    #[test]
    fn should_fail_on_wrong_associated_data_len() {
        let (key, key_id, assoc_data, message, metadata) = test_data();
        let signed_message =
            signed_message_with_metadata(&key, key_id.clone(), &assoc_data, &message, &metadata);

        let verifying_key = key.verifying_key();
        let wrong_assoc_data = "wrong data".as_bytes().to_vec();
        let result = signed_message.validate(
            |encoded_key_id| {
                let decoded_key_id = VerificationKeyId::decode(encoded_key_id)
                    .map_err(|_| ValidateError::InvalidValidationKeyId)?;
                if decoded_key_id != key_id {
                    return Err(ValidateError::KeyMissing(
                        format!("expected key id {:?}, got {:?}", key_id, decoded_key_id).into(),
                    ));
                }
                Ok(*verifying_key)
            },
            (
                wrong_assoc_data.len(),
                std::iter::once(wrong_assoc_data.as_slice()),
            ),
        );

        assert!(
            matches!(
                result,
                Err(ValidateError::InvalidAssociatedDataLength { .. })
            ),
            "validation should fail with InvalidAssociatedDataLength, but got: {result:?}"
        );
    }

    #[test]
    fn should_fail_on_wrong_associated_data() {
        let (key, key_id, mut assoc_data, message, metadata) = test_data();
        let signed_message =
            signed_message_with_metadata(&key, key_id.clone(), &assoc_data, &message, &metadata);

        assoc_data[0] ^= 0x01; // Modify the associated data to make it incorrect

        let verifying_key = key.verifying_key();
        let result = signed_message.validate(
            |encoded_key_id| {
                let decoded_key_id = VerificationKeyId::decode(encoded_key_id)
                    .map_err(|_| ValidateError::InvalidValidationKeyId)?;
                if decoded_key_id != key_id {
                    return Err(ValidateError::KeyMissing(
                        format!("expected key id {:?}, got {:?}", key_id, decoded_key_id).into(),
                    ));
                }
                Ok(*verifying_key)
            },
            (assoc_data.len(), std::iter::once(assoc_data.as_slice())),
        );

        assert!(
            matches!(result, Err(ValidateError::SignatureVerificationFailed(_))),
            "validation should fail with SignatureVerificationFailed, but got: {result:?}"
        );
    }

    #[test]
    fn should_fail_on_wrong_body_type() {
        let (key, key_id, assoc_data, message, metadata) = test_data();
        let signed_message =
            signed_message_with_metadata(&key, key_id, &assoc_data, &message, &metadata);

        let mut header_and_body = scion_protobuf::crypto::v1::HeaderAndBodyInternal::decode(
            &signed_message.header_and_body[..],
        )
        .expect("failed to decode header and body");
        header_and_body.body = vec![0xff];
        let invalid_body_message = SignedMessage {
            header_and_body: header_and_body.encode_to_vec(),
            signature: Vec::new(),
        };

        let decode_result = invalid_body_message.decode_unvalidated::<
            scion_protobuf::control_plane::v1::SegmentsRequest,
            scion_protobuf::control_plane::v1::SegmentsRequest,
        >();

        assert!(decode_result.is_err());
    }

    #[test]
    fn should_fail_on_wrong_metadata_type() {
        let (key, key_id, assoc_data, message, metadata) = test_data();
        let signed_message =
            signed_message_with_metadata(&key, key_id, &assoc_data, &message, &metadata);

        let mut header_and_body = scion_protobuf::crypto::v1::HeaderAndBodyInternal::decode(
            &signed_message.header_and_body[..],
        )
        .expect("failed to decode header and body");
        let mut header = scion_protobuf::crypto::v1::Header::decode(&header_and_body.header[..])
            .expect("failed to decode header");
        header.metadata = vec![0xff];
        header_and_body.header = header.encode_to_vec();
        let invalid_metadata_message = SignedMessage {
            header_and_body: header_and_body.encode_to_vec(),
            signature: Vec::new(),
        };

        let decode_result = invalid_metadata_message.decode_unvalidated::<
            scion_protobuf::control_plane::v1::SegmentsRequest,
            scion_protobuf::control_plane::v1::SegmentsRequest,
        >();

        assert!(decode_result.is_err());
    }

    #[test]
    fn should_ignore_metadata_with_empty_message_type() {
        let (key, key_id, assoc_data, message, metadata) = test_data();
        let signed_message =
            signed_message_with_metadata(&key, key_id.clone(), &assoc_data, &message, &metadata);

        let verifying_key = key.verifying_key();
        let result = signed_message
            .decode_validated::<scion_protobuf::control_plane::v1::SegmentsRequest, ()>(
                |encoded_key_id| {
                    let decoded_key_id = VerificationKeyId::decode(encoded_key_id)
                        .map_err(|_| ValidateError::InvalidValidationKeyId)?;
                    if decoded_key_id != key_id {
                        return Err(ValidateError::KeyMissing(
                            format!("expected key id {:?}, got {:?}", key_id, decoded_key_id)
                                .into(),
                        ));
                    }
                    Ok(*verifying_key)
                },
                (assoc_data.len(), std::iter::once(assoc_data.as_slice())),
            );

        assert!(result.is_ok(), "validation failed: {result:?}");
        let (decoded_message, decoded_metadata) = result.unwrap();

        assert_eq!(decoded_message, message);
        assert!(decoded_metadata.is_some());
    }
}
