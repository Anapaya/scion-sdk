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

//! Traits for models that can be encoded to wire format and have a corresponding view type.

use crate::core::{
    encode::{EncodeError, InvalidStructureError, WireEncode},
    view::View,
};

/// Trait for models that can be encoded to wire format and have a corresponding view type.
///
/// All `Model` types should also implement [TryFromView](crate::core::convert::TryFromView) or
/// [FromView](crate::core::convert::FromView) and implement
/// [TryFromModel](crate::core::convert::TryFromModel) for their corresponding view type.
///
/// Not all models can implement [Model] as they require additional information to be encoded.
pub trait Model: WireEncode {
    /// The type of view that corresponds to this model.
    type ViewType: View + ?Sized;

    /// Encodes the model into the provided buffer and returns a view over the encoded data.
    ///
    /// Returns the view and the remaining buffer after the encoded data on success, or an
    /// `EncodeError` if encoding fails.
    #[inline]
    fn try_encode_to_view<'buf>(
        &self,
        buf: &'buf mut [u8],
    ) -> Result<(&'buf mut Self::ViewType, &'buf mut [u8]), EncodeError> {
        let encoded_size = self.try_encode(buf)?;

        let (view_buf, rest) = buf.split_at_mut(encoded_size);

        // SAFETY: all encoded models must produce valid view encodings, and the view is only
        // constructed from the encoded data.
        let (view, rest2) = Self::ViewType::try_from_mut_slice(view_buf)
            .expect("All encoded models must produce valid view encodings");

        debug_assert!(
            rest2.is_empty(),
            "View should consume the entire encoded buffer"
        );

        Ok((view, rest))
    }

    /// Encodes the model into a boxed view, returning an error if encoding fails.
    #[inline]
    fn try_encode_to_owned_view(&self) -> Result<Box<Self::ViewType>, InvalidStructureError> {
        let vec = self.try_encode_to_vec()?;
        // SAFETY:`` buffer length is checked above, and all encoded models must produce valid view
        // encodings.
        let view = Self::ViewType::try_from_boxed(vec.into_boxed_slice())
            .expect("All encoded models must produce valid view encodings");

        Ok(view)
    }
}
