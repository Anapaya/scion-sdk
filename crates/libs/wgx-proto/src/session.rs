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

//! The transport session: the two keys that a handshake derives, the counter
//! of the sender, and the replay window of the receiver.
//!
//! The session encrypts and decrypts in the buffer of the caller. It holds no
//! lock and no atomic counter, because every method takes an exclusive
//! reference.

use ring::aead::{Aad, LessSafeKey, Nonce};

use crate::{
    crypto::{aead_key, nonce_from_counter},
    error::Error,
    wire::{Data, DataHeader, TAG_LEN},
};

// BEGIN gotatun verbatim:
// https://github.com/mullvad/gotatun/blob/67de7d50fa9d6b83e64c6cee279b856f874c7f49/gotatun/src/noise/session.rs#L42-L45
// Receiving buffer constants
const WORD_SIZE: u64 = 64;
const N_WORDS: u64 = 16; // Suffice to reorder 64*16 = 1024 packets; can be increased at will
const N_BITS: u64 = WORD_SIZE * N_WORDS;
// END gotatun verbatim.

/// The state that one handshake establishes.
pub(crate) struct Session {
    /// The index that this peer gave the session. The peer writes it into the
    /// `receiver_idx` field of a data message.
    pub(crate) receiving_index: u32,
    /// The index that the remote peer gave the session.
    sending_index: u32,
    receiver: LessSafeKey,
    sender: LessSafeKey,
    sending_key_counter: u64,
    receiving_key_counter: ReceivingKeyCounterValidator,
}

impl std::fmt::Debug for Session {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "Session: {}<- ->{}",
            self.receiving_index, self.sending_index
        )
    }
}

impl Session {
    pub(crate) fn new(
        local_index: u32,
        peer_index: u32,
        receiving_key: [u8; 32],
        sending_key: [u8; 32],
    ) -> Session {
        Session {
            receiving_index: local_index,
            sending_index: peer_index,
            receiver: aead_key(&receiving_key),
            sender: aead_key(&sending_key),
            sending_key_counter: 0,
            receiving_key_counter: ReceivingKeyCounterValidator::default(),
        }
    }

    pub(crate) fn local_index(&self) -> usize {
        self.receiving_index as usize
    }

    /// Encrypts the payload that sits at offset [`DataHeader::LEN`] of
    /// `buffer`, and writes the header and the tag around it.
    ///
    /// Returns the length of the message. `buffer` must hold
    /// `DataHeader::LEN + payload_len + TAG_LEN` bytes.
    pub(crate) fn encrypt(
        &mut self,
        buffer: &mut [u8],
        payload_len: usize,
    ) -> Result<usize, Error> {
        let len = DataHeader::LEN + payload_len + TAG_LEN;
        let buffer = buffer.get_mut(..len).ok_or(Error::BufferTooSmall)?;

        let counter = self.sending_key_counter;
        self.sending_key_counter += 1;

        let (header, payload_and_tag) = buffer.split_at_mut(DataHeader::LEN);
        let (payload, tag_out) = payload_and_tag.split_at_mut(payload_len);

        // The tag follows the payload, so the tag has to be written after the
        // encryption reads the payload.
        let tag = self
            .sender
            .seal_in_place_separate_tag(
                Nonce::assume_unique_for_key(nonce_from_counter(counter)),
                Aad::from(&[]),
                payload,
            )
            .expect("the encryption succeeds");
        tag_out.copy_from_slice(tag.as_ref());

        header.copy_from_slice(zerocopy::IntoBytes::as_bytes(
            &DataHeader::new()
                .with_receiver_idx(self.sending_index)
                .with_counter(counter),
        ));

        Ok(len)
    }

    /// Decrypts `data` in place, and returns the length of the payload.
    ///
    /// The payload starts at offset [`DataHeader::LEN`] of the buffer that
    /// holds `data`.
    pub(crate) fn decrypt(&mut self, data: &mut Data) -> Result<usize, Error> {
        if data.header.receiver_idx.get() != self.receiving_index {
            return Err(Error::WrongIndex);
        }

        let counter = data.header.counter.get();

        // Check the counter before the decryption. A replay is then cheap to
        // reject.
        self.receiving_key_counter.will_accept(counter)?;

        let payload_len = self
            .receiver
            .open_in_place(
                Nonce::assume_unique_for_key(nonce_from_counter(counter)),
                Aad::from(&[]),
                data.ciphertext_and_tag_mut(),
            )
            .map_err(|_| Error::InvalidAeadTag)?
            .len();

        // The decryption authenticated the counter, so the window can take it.
        self.receiving_key_counter.mark_did_receive(counter)?;

        Ok(payload_len)
    }
}

/// The window that rejects a replayed counter.
///
/// It keeps a bitmap of the counters it received and the highest counter, so
/// that it accepts a reordered message but no duplicate.
#[derive(Debug, Clone, Default)]
struct ReceivingKeyCounterValidator {
    next: u64,
    bitmap: [u64; N_WORDS as usize],
}

// BEGIN gotatun verbatim:
// https://github.com/mullvad/gotatun/blob/67de7d50fa9d6b83e64c6cee279b856f874c7f49/gotatun/src/noise/session.rs#L57-L160
impl ReceivingKeyCounterValidator {
    #[inline(always)]
    fn set_bit(&mut self, idx: u64) {
        let bit_idx = idx % N_BITS;
        let word = (bit_idx / WORD_SIZE) as usize;
        let bit = (bit_idx % WORD_SIZE) as usize;
        self.bitmap[word] |= 1 << bit;
    }

    #[inline(always)]
    fn clear_bit(&mut self, idx: u64) {
        let bit_idx = idx % N_BITS;
        let word = (bit_idx / WORD_SIZE) as usize;
        let bit = (bit_idx % WORD_SIZE) as usize;
        self.bitmap[word] &= !(1u64 << bit);
    }

    /// Clear the word that contains idx
    #[inline(always)]
    fn clear_word(&mut self, idx: u64) {
        let bit_idx = idx % N_BITS;
        let word = (bit_idx / WORD_SIZE) as usize;
        self.bitmap[word] = 0;
    }

    /// Returns true if bit is set, false otherwise
    #[inline(always)]
    fn check_bit(&self, idx: u64) -> bool {
        let bit_idx = idx % N_BITS;
        let word = (bit_idx / WORD_SIZE) as usize;
        let bit = (bit_idx % WORD_SIZE) as usize;
        ((self.bitmap[word] >> bit) & 1) == 1
    }

    /// Returns true if the counter was not yet received, and is not too far back
    #[inline(always)]
    fn will_accept(&self, counter: u64) -> Result<(), Error> {
        if counter >= self.next {
            // As long as the counter is growing no replay took place for sure
            return Ok(());
        }
        if counter + N_BITS < self.next {
            // Drop if too far back
            return Err(Error::InvalidCounter);
        }
        if self.check_bit(counter) {
            Err(Error::DuplicateCounter)
        } else {
            Ok(())
        }
    }

    /// Marks the counter as received, and returns true if it is still good (in case during
    /// decryption something changed)
    #[inline(always)]
    fn mark_did_receive(&mut self, counter: u64) -> Result<(), Error> {
        if counter + N_BITS < self.next {
            // Drop if too far back
            return Err(Error::InvalidCounter);
        }
        if counter == self.next {
            // Usually the packets arrive in order, in that case we simply mark the bit and
            // increment the counter
            self.set_bit(counter);
            self.next += 1;
            return Ok(());
        }
        if counter < self.next {
            // A packet arrived out of order, check if it is valid, and mark
            if self.check_bit(counter) {
                return Err(Error::InvalidCounter);
            }
            self.set_bit(counter);
            return Ok(());
        }
        // Packets where dropped, or maybe reordered, skip them and mark unused
        if counter - self.next >= N_BITS {
            // Too far ahead, clear all the bits
            for c in self.bitmap.iter_mut() {
                *c = 0;
            }
        } else {
            let mut i = self.next;
            while !i.is_multiple_of(WORD_SIZE) && i < counter {
                // Clear until i aligned to word size
                self.clear_bit(i);
                i += 1;
            }
            while i + WORD_SIZE < counter {
                // Clear whole word at a time
                self.clear_word(i);
                i = (i + WORD_SIZE) & 0u64.wrapping_sub(WORD_SIZE);
            }
            while i < counter {
                // Clear any remaining bits
                self.clear_bit(i);
                i += 1;
            }
        }
        self.set_bit(counter);
        self.next = counter + 1;
        Ok(())
    }
}
// END gotatun verbatim.

#[cfg(test)]
mod tests {
    use super::*;
    use crate::wire::{Message, parse};

    /// Returns the two sessions that one handshake would establish.
    fn session_pair() -> (Session, Session) {
        let initiator_to_responder = [1u8; 32];
        let responder_to_initiator = [2u8; 32];
        (
            Session::new(1, 2, responder_to_initiator, initiator_to_responder),
            Session::new(2, 1, initiator_to_responder, responder_to_initiator),
        )
    }

    #[test]
    fn a_payload_survives_a_round_trip_in_one_buffer() {
        let (mut sender, mut receiver) = session_pair();
        let payload = b"the payload of the caller";

        let mut buffer = [0u8; 256];
        buffer[DataHeader::LEN..DataHeader::LEN + payload.len()].copy_from_slice(payload);
        let len = sender
            .encrypt(&mut buffer, payload.len())
            .expect("the buffer is large enough");
        assert_eq!(len, DataHeader::LEN + payload.len() + TAG_LEN);
        assert_ne!(
            &buffer[DataHeader::LEN..DataHeader::LEN + payload.len()],
            payload
        );

        let Message::Data(data) = parse(&mut buffer[..len]).expect("the message parses") else {
            panic!("expected a data message");
        };
        let payload_len = receiver.decrypt(data).expect("the message opens");
        assert_eq!(payload_len, payload.len());
        assert_eq!(
            &buffer[DataHeader::LEN..DataHeader::LEN + payload_len],
            payload
        );
    }

    #[test]
    fn a_keepalive_carries_no_payload() {
        let (mut sender, mut receiver) = session_pair();

        let mut buffer = [0u8; 64];
        let len = sender
            .encrypt(&mut buffer, 0)
            .expect("the buffer is large enough");
        assert_eq!(len, Data::OVERHEAD);

        let Message::Data(data) = parse(&mut buffer[..len]).expect("the message parses") else {
            panic!("expected a data message");
        };
        assert!(data.is_keepalive());
        assert_eq!(receiver.decrypt(data).expect("the message opens"), 0);
    }

    #[test]
    fn encrypt_rejects_a_buffer_that_is_too_small() {
        let (mut sender, _) = session_pair();
        let mut buffer = [0u8; Data::OVERHEAD + 4];
        assert!(matches!(
            sender.encrypt(&mut buffer, 5),
            Err(Error::BufferTooSmall)
        ));
    }

    #[test]
    fn decrypt_rejects_a_replay() {
        let (mut sender, mut receiver) = session_pair();

        let mut buffer = [0u8; 64];
        let len = sender
            .encrypt(&mut buffer, 0)
            .expect("the buffer is large enough");
        let replay = buffer;

        let Message::Data(data) = parse(&mut buffer[..len]).expect("the message parses") else {
            panic!("expected a data message");
        };
        receiver.decrypt(data).expect("the message opens");

        let mut buffer = replay;
        let Message::Data(data) = parse(&mut buffer[..len]).expect("the message parses") else {
            panic!("expected a data message");
        };
        assert!(matches!(
            receiver.decrypt(data),
            Err(Error::DuplicateCounter)
        ));
    }

    #[test]
    fn decrypt_rejects_a_message_of_another_session() {
        let (mut sender, mut receiver) = session_pair();

        let mut buffer = [0u8; 64];
        let len = sender
            .encrypt(&mut buffer, 0)
            .expect("the buffer is large enough");
        // Name a session index that the receiver does not hold.
        buffer[4..8].copy_from_slice(&99u32.to_le_bytes());

        let Message::Data(data) = parse(&mut buffer[..len]).expect("the message parses") else {
            panic!("expected a data message");
        };
        assert!(matches!(receiver.decrypt(data), Err(Error::WrongIndex)));
    }

    #[test]
    fn the_replay_window_accepts_a_counter_once() {
        let mut c = ReceivingKeyCounterValidator::default();

        assert!(c.mark_did_receive(0).is_ok());
        assert!(c.mark_did_receive(0).is_err());
        assert!(c.mark_did_receive(1).is_ok());
        assert!(c.mark_did_receive(1).is_err());
        assert!(c.mark_did_receive(63).is_ok());
        assert!(c.mark_did_receive(63).is_err());
        assert!(c.mark_did_receive(15).is_ok());
        assert!(c.mark_did_receive(15).is_err());

        for i in 64..N_BITS + 128 {
            assert!(c.mark_did_receive(i).is_ok());
            assert!(c.mark_did_receive(i).is_err());
        }

        assert!(c.mark_did_receive(N_BITS * 3).is_ok());
        for i in 0..=N_BITS * 2 {
            assert!(matches!(c.will_accept(i), Err(Error::InvalidCounter)));
            assert!(c.mark_did_receive(i).is_err());
        }
        for i in N_BITS * 2 + 1..N_BITS * 3 {
            assert!(c.will_accept(i).is_ok());
        }
        assert!(matches!(
            c.will_accept(N_BITS * 3),
            Err(Error::DuplicateCounter)
        ));

        for i in (N_BITS * 2 + 1..N_BITS * 3).rev() {
            assert!(c.mark_did_receive(i).is_ok());
            assert!(c.mark_did_receive(i).is_err());
        }

        assert!(c.mark_did_receive(N_BITS * 3 + 70).is_ok());
        assert!(c.mark_did_receive(N_BITS * 3 + 71).is_ok());
        assert!(c.mark_did_receive(N_BITS * 3 + 72).is_ok());
        assert!(c.mark_did_receive(N_BITS * 3 + 72 + 125).is_ok());
        assert!(c.mark_did_receive(N_BITS * 3 + 63).is_ok());

        assert!(c.mark_did_receive(N_BITS * 3 + 70).is_err());
        assert!(c.mark_did_receive(N_BITS * 3 + 71).is_err());
        assert!(c.mark_did_receive(N_BITS * 3 + 72).is_err());
    }
}
