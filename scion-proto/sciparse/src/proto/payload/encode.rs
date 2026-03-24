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

//! SCION packet payload encoding trait.
//!
//! This trait mirrors the [crate::core::encode::WireEncode] trait but allows payload encodings to
//! depend on the total size of the SCION packet and contents of the SCION
//! address header.

use crate::{core::encode::EncodeError, header::model::AddressHeader};

/// Allows encoding scion packet payload models to wire format.
///
/// Implementors are responsible for correctly reporting the number of bytes
/// that will be written and for upholding the safety requirements of
/// `encode_unchecked`.
pub trait PayloadEncode {
    /// Returns the size required for the wire encoding.
    ///
    /// The `header_and_extensions_size` parameter is the size in bytes of the
    /// SCION header and all extensions that precede the payload.
    ///
    /// ## Safety
    /// This size must be correct, it is used to validate buffer sizes in
    /// `encode`. If this size is smaller than the actual encoded size,
    /// undefined behavior will occur.
    fn required_size(&self, header_and_extensions_size: usize) -> usize;

    /// Writes the wire encoding into the provided buffer.
    ///
    /// Returns the number of bytes written.
    ///
    /// ## Safety
    /// - The buffer must be at least `self.required_size(header_and_extensions_size)` bytes long.
    unsafe fn encode_unchecked(
        &self,
        buf: &mut [u8],
        address_header: &AddressHeader,
        // The size of the SCION packet header and all extension headers before the SCMP payload.
        header_and_extensions_size: usize,
    ) -> usize;

    /// Writes the wire encoding into the provided buffer.
    ///
    /// Returns the number of bytes written on success, or an
    /// [`EncodeError::BufferTooSmall`] error containing the required size if
    /// the buffer is too small.
    fn encode(
        &self,
        buf: &mut [u8],
        address_header: &AddressHeader,
        // The size of the SCION packet header and all extension headers before the SCMP payload.
        header_and_extensions_size: usize,
    ) -> Result<usize, EncodeError> {
        let required_size = self.required_size(header_and_extensions_size);
        if buf.len() < required_size {
            return Err(EncodeError::BufferTooSmall(required_size));
        }

        // SAFETY: buffer length is checked above.
        Ok(unsafe { self.encode_unchecked(buf, address_header, header_and_extensions_size) })
    }

    /// Validates that all fields in the structure are valid for encoding.
    ///
    /// Note: This only checks the minimal set of fields required for encoding, do not expect
    /// comprehensive validation.
    ///
    /// Returns Ok(()) if valid, otherwise a static error reference.
    fn wire_valid(&self) -> Result<(), crate::core::encode::InvalidStructureError>;
}

/// Encodes a slice of bytes as the payload disregarding the address header and header and
/// extensions size.
impl PayloadEncode for &[u8] {
    fn required_size(&self, _header_and_extensions_size: usize) -> usize {
        self.len()
    }

    unsafe fn encode_unchecked(
        &self,
        buf: &mut [u8],
        _address_header: &AddressHeader,
        _header_and_extensions_size: usize,
    ) -> usize {
        // SAFETY: we know the buffer is large enough.
        // See the comment on [`PayloadEncode::encode_unchecked`].
        unsafe {
            std::ptr::copy_nonoverlapping(self.as_ptr(), buf.as_mut_ptr(), self.len());
        }
        self.len()
    }

    fn wire_valid(&self) -> Result<(), crate::core::encode::InvalidStructureError> {
        Ok(())
    }
}
