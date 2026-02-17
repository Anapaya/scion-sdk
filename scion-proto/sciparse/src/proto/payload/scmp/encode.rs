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

//! SCMP-specific encoding trait.
//!
//! This trait mirrors the encoding pattern used by the SCMP models in this
//! module: a size computation that depends on the SCION header and extensions
//! size, and an unchecked encoder that requires the caller to provide a
//! sufficiently large buffer.

use crate::{core::encode::EncodeError, header::model::AddressHeader};

/// Allows encoding SCMP models to wire format.
///
/// Implementors are responsible for correctly reporting the number of bytes
/// that will be written and for upholding the safety requirements of
/// `encode_unchecked`.
pub trait ScmpWireEncode {
    /// Returns the size required for the wire encoding.
    ///
    /// The `header_and_extensions_size` parameter is the size in bytes of the
    /// SCION header and all extensions that precede the SCMP payload.
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
}
