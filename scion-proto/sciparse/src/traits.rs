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

//! Traits

/// Allows encoding to wire format.
pub trait WireEncode {
    /// Returns the size required for the wire encoding.
    ///
    /// ## Safety
    /// This size must be correct, it is used to validate buffer sizes in `encode`.
    /// If this size is smaller than the actual encoded size, undefined behavior will occur.
    fn required_size(&self) -> usize;

    /// Writes the wire encoding into the provided buffer.
    ///
    /// Returns the number of bytes written.
    ///
    /// ## SAFETY
    /// The buffer must be at least `self.required_size()` bytes long, otherwise
    /// behavior is undefined.
    unsafe fn encode_unchecked(&self, buf: &mut [u8]) -> usize;

    /// Writes the wire encoding into the provided buffer.
    ///
    /// Returns the number of bytes written on success, or `Err(usize)` of the required size if the
    /// buffer is too small.
    ///
    /// The buffer must be at least `self.required_size()` bytes long.
    fn encode(&self, buf: &mut [u8]) -> Result<usize, usize> {
        let required_size = self.required_size();
        if buf.len() < required_size {
            return Err(required_size);
        }

        // SAFETY: buffer length is checked above
        unsafe { Ok(self.encode_unchecked(buf)) }
    }
}
