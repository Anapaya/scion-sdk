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

//! Utilities for interacting with byte buffers via zero-copy views
//!
//! Views are zero-copy representations of data structures over byte buffers.
//!
//! All views must be #[repr(transparent)] wrappers around `[u8]` (or `[u8; fixed_size]`).
//! Essentially, this means that every view is just a wide/thin pointer.
//!
//! This allows interpreting byte slices as views via transmute:
//!
//! * &[u8] == &View
//! * &mut [u8] == &mut View
//! * `Box<[u8]>` == `Box<View>`
//!
//! Thanks to this, mutability and ownership is fully handled by Rust's built-in types.
//!
//! ### Safety
//!
//! Core invariant needing to be upheld is that the buffer which the view points to, is large enough
//! to read all fields of the view.
//!
//! This needs to be uphold by checking all fields which are size relevant, before the buffer may be
//! interpreted.
//!
//! The transmut itself is safe, as we are esentially just reinterpreting a pointer.
//!
//! ### Limitations
//!
//! * We can not have any data inside the view structs, since that would break the
//!   #[repr(transparent)] attribute.
//!
//! * Therefore we need to combine Header which depend on each other into a single view. E.g.
//!   CommonHeader + AddressHeader

use crate::core::layout::LayoutParseError;

/// Trait for views over byte buffers
///
/// Views are zero-copy representations of data structures over byte buffers.
/// They provide methods to read fields directly from the buffer without copying data.
///
/// A view must implement methods to check the required size of the buffer
pub trait View {
    /// Asserts that the buffer has the required size for the view.
    /// Returns the range of bytes used by the view in the buffer.
    ///
    /// If the buffer is too small, returns a ViewConversionError.
    ///
    /// # Important
    ///
    /// This function ensures that all view functions are safe to call after it returns Ok.
    /// If this function is incorrectly implemented, it will lead to undefined behavior.
    fn has_required_size(buf: &[u8]) -> Result<usize, ViewConversionError>;

    /// Converts a slice into the view
    ///
    /// This function checks that the buffer is at least as large as required by the view.
    #[inline]
    fn from_slice(buf: &[u8]) -> Result<(&Self, &[u8]), ViewConversionError> {
        let size = Self::has_required_size(buf)?;

        debug_assert!(buf.len() >= size);

        // SAFETY: size is checked to be at least the required size
        let (view_buf, rest) = unsafe { buf.split_at_unchecked(size) };
        let view = unsafe { Self::from_slice_unchecked(view_buf) };

        Ok((view, rest))
    }

    /// Converts a mutable slice into the view
    ///
    /// This function checks that the buffer is at least as large as required by the view.
    #[inline]
    fn from_mut_slice(buf: &mut [u8]) -> Result<(&mut Self, &mut [u8]), ViewConversionError> {
        let size = Self::has_required_size(buf)?;

        debug_assert!(buf.len() >= size);

        // SAFETY: size is checked to be at least the required size
        let (view_buf, rest) = unsafe { buf.split_at_mut_unchecked(size) };
        let view = unsafe { Self::from_mut_slice_unchecked(view_buf) };

        Ok((view, rest))
    }

    /// Converts a boxed slice into the view
    ///
    /// This function checks that the buffer is exactly as large as required by the view.
    #[inline]
    fn from_boxed(buf: Box<[u8]>) -> Result<Box<Self>, ViewConversionError> {
        let size = Self::has_required_size(&buf)?;

        if buf.len() != size {
            return Err(ViewConversionError::Other(
                "Boxed buffer size does not match view size",
            ));
        }

        Ok(unsafe { Self::from_boxed_unchecked(buf) })
    }

    /// Returns the underlying byte representation of the view
    fn as_bytes(&self) -> &[u8];

    /// Converts the view into an owned boxed slice
    #[inline]
    fn to_owned(&self) -> Box<Self> {
        unsafe { Self::from_boxed_unchecked(self.as_bytes().to_vec().into_boxed_slice()) }
    }

    /// Converts the slice into the view without checking sizes
    ///
    /// # Safety
    /// The caller must ensure that the buffer is at least as large as required by the view
    /// this is usually done by calling [View::has_required_size] before.
    unsafe fn from_slice_unchecked(buf: &[u8]) -> &Self;

    /// Converts the mutable slice into the view without checking sizes
    ///
    /// # Safety
    /// The caller must ensure that the buffer is at least as large as required by the view
    /// this is usually done by calling [View::has_required_size] before.
    unsafe fn from_mut_slice_unchecked(buf: &mut [u8]) -> &mut Self;

    /// Converts the boxed slice into the view without checking sizes
    ///
    /// # Safety
    /// The caller must ensure that the buffer is at least as large as required by the view
    /// this is usually done by calling [View::has_required_size] before.
    unsafe fn from_boxed_unchecked(buf: Box<[u8]>) -> Box<Self>;
}

/// Errors that can occur during view conversion
#[derive(Clone, Copy, Debug, thiserror::Error, PartialEq, Eq, Hash)]
pub enum ViewConversionError {
    /// Buffer is too small for the view
    #[error("Buffer too small at {at}: required {required}, got {actual}")]
    BufferTooSmall {
        /// Location where the error occurred
        at: &'static str,
        /// Required size in bytes
        required: usize,
        /// Actual size in bytes
        actual: usize,
    },
    /// Other errors
    #[error("Could not convert view: {0}")]
    Other(&'static str),
}
impl From<LayoutParseError> for ViewConversionError {
    fn from(value: LayoutParseError) -> Self {
        match value {
            LayoutParseError::BufferTooSmall {
                at,
                required,
                actual,
            } => {
                ViewConversionError::BufferTooSmall {
                    at,
                    required,
                    actual,
                }
            }
            LayoutParseError::InvalidHeaderLength { .. } => {
                ViewConversionError::Other("InvalidHeaderLength")
            }
            LayoutParseError::UnsupportedVersion => {
                ViewConversionError::Other("UnsupportedVersion")
            }
        }
    }
}

pub(crate) mod macros {
    /// Macro to generate unaligned field readers - expects self to be a wrapper around [u8]
    ///
    /// - $name: name of the generated function
    /// - $bit_range: bit range of the field
    /// - $repr: representation type of the field
    ///
    /// Repr can be any integer from u8 to u64, u128 can only be read if it is aligned.
    macro_rules! gen_field_read {
        ($name:ident, $bit_range:expr, $repr:ty) => {
            #[inline]
            #[allow(unused)]
            /// Reads the field
            pub fn $name(&self) -> $repr {
                use $crate::core::read::unchecked_bit_range_be_read;
                unsafe { unchecked_bit_range_be_read::<$repr>(&self.0, $bit_range) }
            }
        };
    }
    pub(crate) use gen_field_read;

    /// Macro to generate unaligned field writers - expects self to be a wrapper around [u8]
    ///
    /// - $name: name of the generated function
    /// - $bit_range: bit range of the field
    /// - $repr: representation type of the field
    ///
    /// Repr can be any integer from u8 to u64, u128 can only be written if it is aligned.
    macro_rules! gen_field_write {
        ($name:ident, $bit_range:expr, $repr:ty) => {
            #[inline]
            #[allow(unused)]
            /// Writes the field
            pub fn $name(&mut self, value: $repr) {
                use $crate::core::write::unchecked_bit_range_be_write;
                unsafe { unchecked_bit_range_be_write::<$repr>(&mut self.0, $bit_range, value) }
            }
        };
    }
    pub(crate) use gen_field_write;

    macro_rules! gen_unsafe_field_write {
        ($name:ident, $bit_range:expr, $repr:ty) => {
            #[inline]
            #[allow(unused)]
            /// Writes the field
            ///
            /// Writing to this field is considered unsafe, as editing this field changes the
            /// required size for the view. Accesses after writing to this field may lead to
            /// undefined behavior.
            ///
            /// ## Safety
            ///
            /// The caller must ensure that subsequent accesses to the view are valid, i.e. the
            /// underlying buffer is large enough to hold the view with the new field value.
            pub unsafe fn $name(&mut self, value: $repr) {
                use $crate::core::write::unchecked_bit_range_be_write;
                unsafe { unchecked_bit_range_be_write::<$repr>(&mut self.0, $bit_range, value) }
            }
        };
    }
    pub(crate) use gen_unsafe_field_write;
}
