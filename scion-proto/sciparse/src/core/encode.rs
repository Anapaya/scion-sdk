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

//! Utilities for encoding model representations into byte buffers
//!
//! All model structures intended for encoding should implement the `WireEncode` trait.
//!
//! This trait has three main responsibilities:
//!
//! 1. Calculating the required size for the wire encoding
//! 2. Validating that the structure is in a valid state for encoding
//! 3. Writing the wire format into a provided byte buffer
//!
//! ### Validation
//!
//! In this case, validation does not mean comprehensive semantic validation of all fields.
//! Instead, it focuses on ensuring that all fields required for encoding are valid.
//! E.g. we can not encode a unknown path, if the data inside is not aligned to 4 bytes.
//!
//! This validation is purely aims to prevent encoding data which would lead to an invalid wire
//! format.

/// Allows encoding to wire format.
pub trait WireEncode {
    /// Returns the size required for the wire encoding.
    ///
    /// ## Safety
    /// This size must be correct, it is used to validate buffer sizes in `encode`.
    /// If this size is smaller than the actual encoded size, undefined behavior will occur.
    fn required_size(&self) -> usize;

    /// Validates that all fields in the structure are valid for encoding.
    ///
    /// Note: This only checks the minimal set of fields required for encoding, do not expect
    /// comprehensive validation.
    ///
    /// Returns Ok(()) if valid, otherwise a static error reference.
    fn wire_valid(&self) -> Result<(), InvalidStructureError>;

    /// Writes the wire encoding into the provided buffer.
    ///
    /// Returns the number of bytes written.
    ///
    /// ## SAFETY
    /// 1. The buffer must be at least `self.required_size()` bytes long
    /// 2. The structure must be valid for encoding, i.e., `self.valid()` must return `Ok(())`
    unsafe fn encode_unchecked(&self, buf: &mut [u8]) -> usize;

    /// Writes the wire encoding into the provided buffer.
    ///
    /// Returns the number of bytes written on success, or `Err(usize)` of the required size if the
    /// buffer is too small or the packet.
    ///
    /// The buffer must be at least `self.required_size()` bytes long.
    fn encode(&self, buf: &mut [u8]) -> Result<usize, EncodeError> {
        self.wire_valid()?;

        let required_size = self.required_size();
        if buf.len() < required_size {
            return Err(EncodeError::BufferTooSmall(required_size));
        }

        // SAFETY: buffer length is checked above
        unsafe { Ok(self.encode_unchecked(buf)) }
    }
}

/// Errors that can occur during encoding.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum EncodeError {
    /// The structure which was attempted to be encoded is invalid.
    #[error(transparent)]
    InvalidStructure(#[from] InvalidStructureError),
    /// The provided buffer is too small.
    #[error("buffer too small: required {0}")]
    BufferTooSmall(usize),
}

/// Given Structure has invalid fields to encode correctly.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("cannot encode structure: {0}")]
pub struct InvalidStructureError(&'static str);
impl From<&'static str> for InvalidStructureError {
    fn from(s: &'static str) -> Self {
        InvalidStructureError(s)
    }
}
