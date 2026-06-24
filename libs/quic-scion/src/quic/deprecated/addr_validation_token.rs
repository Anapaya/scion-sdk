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

//! Token manager for the QUIC server side for source address validation.
//!
//! Inspired by tokio-quiche, check:
//! <https://github.com/cloudflare/quiche/blob/master/tokio-quiche/src/quic/addr_validation_token.rs>

use std::{
    io::{self, Write},
    net::IpAddr,
};

use ring::rand::SystemRandom;
use squiche::ConnectionId;
use thiserror::Error;

const HMAC_TAG_LEN: usize = 32;

/// Manager for the token-based client address validation in QUIC.
///
/// The token must be encoded in the initial packet a client sends to the server to initiate a new
/// connection. The purpose of this mechanism is to mitigate amplification attacks with spoofed
/// addresses. Address validation is implicitly completed when a client receives a valid Handshake
/// packet from the server, as this means that the server successfully processed an Initial packet.
pub(crate) struct AddrValidationTokenManager {
    sign_key: ring::hmac::Key,
}

impl Default for AddrValidationTokenManager {
    fn default() -> Self {
        let sign_key =
            ring::hmac::Key::generate(ring::hmac::HMAC_SHA256, &SystemRandom::new()).unwrap();

        AddrValidationTokenManager { sign_key }
    }
}

/// Token error.
#[derive(Debug, Error)]
pub(super) enum TokenError {
    /// Invalid token length.
    #[error("Token has invalid length")]
    InvalidTokenLength,
    /// Signature verification failed.
    #[error("Signature verification failed")]
    InvalidSignature,
    /// IP address mismatch.
    #[error("IP address mismatch")]
    AddressMismatch,
}

impl AddrValidationTokenManager {
    // Generates an address validation token for the given original DCID and client address.
    //
    // Format: [HMAC tag || IP address || original DCID]
    pub(super) fn generate(
        &self,
        original_dcid: &[u8],
        client_addr: std::net::SocketAddr,
    ) -> Vec<u8> {
        let ip_bytes = match client_addr.ip() {
            IpAddr::V4(addr) => addr.octets().to_vec(),
            IpAddr::V6(addr) => addr.octets().to_vec(),
        };

        let token_len = HMAC_TAG_LEN + ip_bytes.len() + original_dcid.len();
        let mut token = io::Cursor::new(vec![0u8; token_len]);

        token.set_position(HMAC_TAG_LEN as u64);
        token.write_all(&ip_bytes).unwrap();
        token.write_all(original_dcid).unwrap();

        let tag = ring::hmac::sign(&self.sign_key, &token.get_ref()[HMAC_TAG_LEN..]);

        token.set_position(0);
        token.write_all(tag.as_ref()).unwrap();

        token.into_inner()
    }

    pub(super) fn validate_and_extract_original_dcid<'t>(
        &self,
        token: &'t [u8],
        client_addr: std::net::SocketAddr,
    ) -> Result<ConnectionId<'t>, TokenError> {
        let ip_bytes = match client_addr.ip() {
            IpAddr::V4(addr) => addr.octets().to_vec(),
            IpAddr::V6(addr) => addr.octets().to_vec(),
        };

        let hmac_and_ip_len = HMAC_TAG_LEN + ip_bytes.len();

        if token.len() < hmac_and_ip_len {
            return Err(TokenError::InvalidTokenLength);
        }

        let (tag, payload) = token.split_at(HMAC_TAG_LEN);
        if let Err(_err) = ring::hmac::verify(&self.sign_key, payload, tag) {
            return Err(TokenError::InvalidSignature);
        }

        if payload[..ip_bytes.len()] != *ip_bytes {
            return Err(TokenError::AddressMismatch);
        }

        Ok(ConnectionId::from_ref(&token[hmac_and_ip_len..]))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn generate() {
        let manager = AddrValidationTokenManager::default();

        let assert_tag_generated = |token: &[u8]| {
            let tag = &token[..HMAC_TAG_LEN];
            let all_nulls = tag.iter().all(|b| *b == 0u8);

            assert!(!all_nulls);
        };

        let token = manager.generate(b"foo", "127.0.0.1:1337".parse().unwrap());

        assert_tag_generated(&token);
        assert_eq!(token[HMAC_TAG_LEN..HMAC_TAG_LEN + 4], [127, 0, 0, 1]);
        assert_eq!(&token[HMAC_TAG_LEN + 4..], b"foo");

        let token = manager.generate(b"bar", "[::1]:1338".parse().unwrap());

        assert_tag_generated(&token);

        assert_eq!(
            token[HMAC_TAG_LEN..HMAC_TAG_LEN + 16],
            [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1]
        );

        assert_eq!(&token[HMAC_TAG_LEN + 16..], b"bar");
    }

    #[test]
    fn validate() {
        let manager = AddrValidationTokenManager::default();

        let addr = "127.0.0.1:1337".parse().unwrap();
        let token = manager.generate(b"foo", addr);

        assert_eq!(
            manager
                .validate_and_extract_original_dcid(&token, addr)
                .unwrap(),
            ConnectionId::from_ref(b"foo")
        );

        let addr = "[::1]:1338".parse().unwrap();
        let token = manager.generate(b"barbaz", addr);

        assert_eq!(
            manager
                .validate_and_extract_original_dcid(&token, addr)
                .unwrap(),
            ConnectionId::from_ref(b"barbaz")
        );
    }

    #[test]
    fn validate_err_short_token() {
        let manager = AddrValidationTokenManager::default();
        let v4_addr = "127.0.0.1:1337".parse().unwrap();
        let v6_addr = "[::1]:1338".parse().unwrap();

        for addr in &[v4_addr, v6_addr] {
            assert!(
                manager
                    .validate_and_extract_original_dcid(b"", *addr)
                    .is_err()
            );

            assert!(
                manager
                    .validate_and_extract_original_dcid(&[1u8; HMAC_TAG_LEN], *addr)
                    .is_err()
            );

            assert!(
                manager
                    .validate_and_extract_original_dcid(&[1u8; HMAC_TAG_LEN + 1], *addr)
                    .is_err()
            );
        }
    }

    #[test]
    fn validate_err_ips_mismatch() {
        let manager = AddrValidationTokenManager::default();

        let token = manager.generate(b"foo", "127.0.0.1:1337".parse().unwrap());

        assert!(
            manager
                .validate_and_extract_original_dcid(&token, "127.0.0.2:1337".parse().unwrap())
                .is_err()
        );

        let token = manager.generate(b"barbaz", "[::1]:1338".parse().unwrap());

        assert!(
            manager
                .validate_and_extract_original_dcid(&token, "[::2]:1338".parse().unwrap())
                .is_err()
        );
    }

    #[test]
    fn validate_err_invalid_signature() {
        let manager = AddrValidationTokenManager::default();

        let addr = "127.0.0.1:1337".parse().unwrap();
        let mut token = manager.generate(b"foo", addr);

        token[..HMAC_TAG_LEN].copy_from_slice(&[1u8; HMAC_TAG_LEN]);

        assert!(
            manager
                .validate_and_extract_original_dcid(&token, addr)
                .is_err()
        );
    }
}
