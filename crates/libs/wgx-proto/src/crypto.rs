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
//
// This file incorporates code from mullvad/gotatun, at the v0.2.0 tag that
// ana-gotatun forked from:
// https://github.com/mullvad/gotatun/blob/67de7d50fa9d6b83e64c6cee279b856f874c7f49
// Copyright (c) 2019 Cloudflare, Inc. All rights reserved.
// Copyright (c) 2025 Mullvad VPN.
// SPDX-License-Identifier: BSD-3-Clause
//
// A "BEGIN gotatun verbatim" marker names the code that comes from gotatun
// without a change, and the permalink on the next line points at the lines it
// comes from. Everything outside such a pair is the code of this crate.
// tools/check_verbatim.py compares every marked region against gotatun.

//! The cryptographic primitives that the Noise handshake uses.
//!
//! The functions come from gotatun without a change of the algorithm. Only the
//! two AEAD wrappers differ: they work on a buffer of the caller or on the
//! stack, so that they allocate nothing.

use blake2::{
    Blake2s256, Blake2sMac, Digest,
    digest::{FixedOutput, KeyInit},
};
use ring::aead::{Aad, CHACHA20_POLY1305, LessSafeKey, Nonce, UnboundKey};

use crate::{
    error::Error,
    wire::{COOKIE_LEN, EncryptedWithTag},
};

/// The length of a key, in bytes.
pub(crate) const KEY_LEN: usize = 32;

/// The label that the computation of `mac1` uses.
pub(crate) const LABEL_MAC1: &[u8; 8] = b"mac1----";

/// The label that the encryption of a cookie uses.
pub(crate) const LABEL_COOKIE: &[u8; 8] = b"cookie--";

/// The largest ciphertext that [`aead_open`] accepts, in bytes.
///
/// The handshake seals a static public key (32 bytes), a timestamp (12 bytes),
/// and a socket address (20 bytes). Each one carries a tag of 16 bytes.
const MAX_SEALED_LEN: usize = KEY_LEN + 16;

// BEGIN gotatun verbatim:
// https://github.com/mullvad/gotatun/blob/67de7d50fa9d6b83e64c6cee279b856f874c7f49/gotatun/src/noise/handshake.rs#L33-L79
// initiator.chaining_key = HASH(CONSTRUCTION)
pub(crate) const INITIAL_CHAIN_KEY: [u8; KEY_LEN] = [
    96, 226, 109, 174, 243, 39, 239, 192, 46, 195, 53, 226, 160, 37, 210, 208, 22, 235, 66, 6, 248,
    114, 119, 245, 45, 56, 209, 152, 139, 120, 205, 54,
];

// initiator.chaining_hash = HASH(initiator.chaining_key || IDENTIFIER)
pub(crate) const INITIAL_CHAIN_HASH: [u8; KEY_LEN] = [
    34, 17, 179, 97, 8, 26, 197, 102, 105, 18, 67, 219, 69, 138, 213, 50, 45, 156, 108, 102, 34,
    147, 232, 183, 14, 225, 156, 101, 186, 7, 158, 243,
];

#[inline]
pub(crate) fn b2s_hash(data1: &[u8], data2: &[u8]) -> [u8; 32] {
    let mut hash = Blake2s256::new();
    hash.update(data1);
    hash.update(data2);
    hash.finalize().into()
}

#[inline]
/// RFC 2401 HMAC+Blake2s, not to be confused with *keyed* Blake2s
pub(crate) fn b2s_hmac(key: &[u8], data1: &[u8]) -> [u8; 32] {
    use blake2::digest::Update;
    type HmacBlake2s = hmac::SimpleHmac<Blake2s256>;
    let mut hmac = HmacBlake2s::new_from_slice(key).unwrap();
    hmac.update(data1);
    hmac.finalize_fixed().into()
}

#[inline]
/// Like [`b2s_hmac`], but chain data1 and data2 together
pub(crate) fn b2s_hmac2(key: &[u8], data1: &[u8], data2: &[u8]) -> [u8; 32] {
    use blake2::digest::Update;
    type HmacBlake2s = hmac::SimpleHmac<Blake2s256>;
    let mut hmac = HmacBlake2s::new_from_slice(key).unwrap();
    hmac.update(data1);
    hmac.update(data2);
    hmac.finalize_fixed().into()
}

#[inline]
pub(crate) fn b2s_keyed_mac_16(key: &[u8], data1: &[u8]) -> [u8; 16] {
    let mut hmac = Blake2sMac::new_from_slice(key).unwrap();
    blake2::digest::Update::update(&mut hmac, data1);
    hmac.finalize_fixed().into()
}
// END gotatun verbatim.

/// Builds the nonce that a counter of the protocol denotes.
#[inline]
pub(crate) fn nonce_from_counter(counter: u64) -> [u8; 12] {
    let mut nonce = [0u8; 12];
    nonce[4..12].copy_from_slice(&counter.to_le_bytes());
    nonce
}

/// Returns a key that seals and opens a message.
#[inline]
pub(crate) fn aead_key(key: &[u8]) -> LessSafeKey {
    LessSafeKey::new(UnboundKey::new(&CHACHA20_POLY1305, key).expect("the key has 32 bytes"))
}

/// Seals `plaintext` into `sealed`, and appends the tag.
///
/// `sealed` must hold `plaintext.len() + 16` bytes.
#[inline]
pub(crate) fn aead_seal(sealed: &mut [u8], key: &[u8], counter: u64, plaintext: &[u8], aad: &[u8]) {
    aead_seal_with_nonce(sealed, key, nonce_from_counter(counter), plaintext, aad);
}

#[inline]
fn aead_seal_with_nonce(
    sealed: &mut [u8],
    key: &[u8],
    nonce: [u8; 12],
    plaintext: &[u8],
    aad: &[u8],
) {
    let (ciphertext, tag_out) = sealed.split_at_mut(plaintext.len());
    ciphertext.copy_from_slice(plaintext);

    let tag = aead_key(key)
        .seal_in_place_separate_tag(
            Nonce::assume_unique_for_key(nonce),
            Aad::from(aad),
            ciphertext,
        )
        .expect("the encryption succeeds");

    tag_out.copy_from_slice(tag.as_ref());
}

/// Opens `sealed` into `plaintext`.
///
/// `sealed` holds the ciphertext and the tag that follows it. `plaintext` must
/// hold `sealed.len() - 16` bytes. The function copies `sealed` onto the stack,
/// so it leaves the message of the caller unchanged.
#[inline]
pub(crate) fn aead_open(
    plaintext: &mut [u8],
    key: &[u8],
    counter: u64,
    sealed: &[u8],
    aad: &[u8],
) -> Result<(), Error> {
    let mut scratch = [0u8; MAX_SEALED_LEN];
    let scratch = scratch
        .get_mut(..sealed.len())
        .ok_or(Error::IncorrectPacketLength)?;
    scratch.copy_from_slice(sealed);

    let opened = aead_key(key)
        .open_in_place(
            Nonce::assume_unique_for_key(nonce_from_counter(counter)),
            Aad::from(aad),
            scratch,
        )
        .map_err(|_| Error::InvalidAeadTag)?;

    if opened.len() != plaintext.len() {
        return Err(Error::IncorrectPacketLength);
    }
    plaintext.copy_from_slice(opened);
    Ok(())
}

/// Opens the cookie of a cookie reply.
///
/// The cookie reply uses XChaCha20-Poly1305, which takes a nonce of 24 bytes.
/// It is the only place in the protocol that does.
#[inline]
pub(crate) fn xaead_open_cookie(
    key: &[u8; KEY_LEN],
    nonce: &[u8; 24],
    sealed: &EncryptedWithTag<[u8; COOKIE_LEN]>,
    aad: &[u8],
) -> Result<[u8; COOKIE_LEN], Error> {
    use chacha20poly1305::{
        KeyInit, XChaCha20Poly1305,
        aead::{AeadInPlace, generic_array::GenericArray},
    };

    let mut cookie = sealed.encrypted;
    XChaCha20Poly1305::new(GenericArray::from_slice(key))
        .decrypt_in_place_detached(
            GenericArray::from_slice(nonce),
            aad,
            &mut cookie,
            GenericArray::from_slice(&sealed.tag),
        )
        .map_err(|_| Error::InvalidAeadTag)?;

    Ok(cookie)
}

/// Seals a cookie into a cookie reply.
///
/// The crate sends no cookie reply, because it implements no rate limiting.
/// The function exists so that a test can build the reply that a peer under
/// load would send.
#[cfg(test)]
pub(crate) fn xaead_seal_cookie(
    key: &[u8; KEY_LEN],
    nonce: &[u8; 24],
    cookie: [u8; COOKIE_LEN],
    aad: &[u8],
) -> EncryptedWithTag<[u8; COOKIE_LEN]> {
    use chacha20poly1305::{
        KeyInit, XChaCha20Poly1305,
        aead::{AeadInPlace, generic_array::GenericArray},
    };

    let mut encrypted = cookie;
    let tag = XChaCha20Poly1305::new(GenericArray::from_slice(key))
        .encrypt_in_place_detached(GenericArray::from_slice(nonce), aad, &mut encrypted)
        .expect("the encryption succeeds");

    EncryptedWithTag {
        encrypted,
        tag: tag.into(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn chacha20_seal_matches_the_rfc7539_test_vector() {
        let plaintext = b"Ladies and Gentlemen of the class of '99: If I could offer you only one tip for the future, sunscreen would be it.";
        let aad: [u8; 12] = [
            0x50, 0x51, 0x52, 0x53, 0xc0, 0xc1, 0xc2, 0xc3, 0xc4, 0xc5, 0xc6, 0xc7,
        ];
        let key: [u8; 32] = [
            0x80, 0x81, 0x82, 0x83, 0x84, 0x85, 0x86, 0x87, 0x88, 0x89, 0x8a, 0x8b, 0x8c, 0x8d,
            0x8e, 0x8f, 0x90, 0x91, 0x92, 0x93, 0x94, 0x95, 0x96, 0x97, 0x98, 0x99, 0x9a, 0x9b,
            0x9c, 0x9d, 0x9e, 0x9f,
        ];
        let nonce: [u8; 12] = [
            0x07, 0x00, 0x00, 0x00, 0x40, 0x41, 0x42, 0x43, 0x44, 0x45, 0x46, 0x47,
        ];

        let mut sealed = vec![0; plaintext.len() + 16];
        aead_seal_with_nonce(&mut sealed, &key, nonce, plaintext, &aad);

        const EXPECTED_CIPHERTEXT: [u8; 114] = [
            0xd3, 0x1a, 0x8d, 0x34, 0x64, 0x8e, 0x60, 0xdb, 0x7b, 0x86, 0xaf, 0xbc, 0x53, 0xef,
            0x7e, 0xc2, 0xa4, 0xad, 0xed, 0x51, 0x29, 0x6e, 0x08, 0xfe, 0xa9, 0xe2, 0xb5, 0xa7,
            0x36, 0xee, 0x62, 0xd6, 0x3d, 0xbe, 0xa4, 0x5e, 0x8c, 0xa9, 0x67, 0x12, 0x82, 0xfa,
            0xfb, 0x69, 0xda, 0x92, 0x72, 0x8b, 0x1a, 0x71, 0xde, 0x0a, 0x9e, 0x06, 0x0b, 0x29,
            0x05, 0xd6, 0xa5, 0xb6, 0x7e, 0xcd, 0x3b, 0x36, 0x92, 0xdd, 0xbd, 0x7f, 0x2d, 0x77,
            0x8b, 0x8c, 0x98, 0x03, 0xae, 0xe3, 0x28, 0x09, 0x1b, 0x58, 0xfa, 0xb3, 0x24, 0xe4,
            0xfa, 0xd6, 0x75, 0x94, 0x55, 0x85, 0x80, 0x8b, 0x48, 0x31, 0xd7, 0xbc, 0x3f, 0xf4,
            0xde, 0xf0, 0x8e, 0x4b, 0x7a, 0x9d, 0xe5, 0x76, 0xd2, 0x65, 0x86, 0xce, 0xc6, 0x4b,
            0x61, 0x16,
        ];
        const EXPECTED_TAG: [u8; 16] = [
            0x1a, 0xe1, 0x0b, 0x59, 0x4f, 0x09, 0xe2, 0x6a, 0x7e, 0x90, 0x2e, 0xcb, 0xd0, 0x60,
            0x06, 0x91,
        ];

        assert_eq!(sealed[..plaintext.len()], EXPECTED_CIPHERTEXT);
        assert_eq!(sealed[plaintext.len()..], EXPECTED_TAG);
    }

    #[test]
    fn a_counter_occupies_the_last_eight_bytes_of_the_nonce() {
        assert_eq!(
            nonce_from_counter(u64::from_le_bytes([
                0x40, 0x41, 0x42, 0x43, 0x44, 0x45, 0x46, 0x47
            ])),
            [
                0x00, 0x00, 0x00, 0x00, 0x40, 0x41, 0x42, 0x43, 0x44, 0x45, 0x46, 0x47
            ]
        );
    }

    #[test]
    fn open_reverses_seal() {
        let key = [3u8; 32];
        let aad = [7u8; 32];
        let plaintext = [42u8; KEY_LEN];

        let mut sealed = [0u8; KEY_LEN + 16];
        aead_seal(&mut sealed, &key, 0, &plaintext, &aad);

        let mut opened = [0u8; KEY_LEN];
        aead_open(&mut opened, &key, 0, &sealed, &aad).expect("the message opens");
        assert_eq!(opened, plaintext);
    }

    #[test]
    fn open_rejects_a_modified_tag() {
        let key = [3u8; 32];
        let mut sealed = [0u8; KEY_LEN + 16];
        aead_seal(&mut sealed, &key, 0, &[42u8; KEY_LEN], &[]);
        sealed[KEY_LEN] ^= 1;

        let mut opened = [0u8; KEY_LEN];
        assert!(matches!(
            aead_open(&mut opened, &key, 0, &sealed, &[]),
            Err(Error::InvalidAeadTag)
        ));
    }

    #[test]
    fn a_cookie_survives_a_round_trip() {
        let key = [5u8; KEY_LEN];
        let nonce = [6u8; 24];
        let cookie = [7u8; COOKIE_LEN];
        let aad = [8u8; 16];

        let sealed = xaead_seal_cookie(&key, &nonce, cookie, &aad);
        assert_eq!(
            xaead_open_cookie(&key, &nonce, &sealed, &aad).expect("the cookie opens"),
            cookie
        );
    }

    #[test]
    fn a_cookie_does_not_open_under_another_mac1() {
        let key = [5u8; KEY_LEN];
        let nonce = [6u8; 24];
        let sealed = xaead_seal_cookie(&key, &nonce, [7u8; COOKIE_LEN], &[8u8; 16]);

        assert!(matches!(
            xaead_open_cookie(&key, &nonce, &sealed, &[9u8; 16]),
            Err(Error::InvalidAeadTag)
        ));
    }

    #[test]
    fn open_rejects_a_ciphertext_that_the_stack_buffer_cannot_hold() {
        let mut opened = [0u8; MAX_SEALED_LEN];
        assert!(matches!(
            aead_open(&mut opened, &[3u8; 32], 0, &[0u8; MAX_SEALED_LEN + 1], &[]),
            Err(Error::IncorrectPacketLength)
        ));
    }
}
