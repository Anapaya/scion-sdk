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

//! Traits for converting between views and models.

use crate::core::{
    encode::{EncodeError, InvalidStructureError},
    model::Model,
    view::{View, ViewConversionError},
};

// View to Model

/// Fallible conversion from a view to a model.
///
/// Use [FromView] for infallible conversions.
///
/// [TryFromView] is implemented for all types that implement [FromView].
pub trait TryFromView: Sized {
    /// The type of view that can be converted into this model.
    type ViewType: View + ?Sized;

    /// Attempts to parse a model from the provided view, returning an error if the view is
    /// invalid.
    fn try_from_view(view: &Self::ViewType) -> Result<Self, ViewConversionError>;

    /// Attempts to parse a model from the provided buffer, returning the model and the
    /// remaining buffer on success.
    #[inline]
    fn try_from_slice<'buf>(buf: &'buf [u8]) -> Result<(Self, &'buf [u8]), ViewConversionError>
    where
        <Self as TryFromView>::ViewType: 'buf,
    {
        let (view, rest) = Self::ViewType::from_slice(buf)?;
        let model = Self::try_from_view(view)?;
        Ok((model, rest))
    }
}

/// Infallible conversion from a view to a model.
///
/// Use [TryFromView] for fallible conversions.
///
/// [TryFromView] is implemented for all types that implement [FromView].
pub trait FromView: Sized {
    /// The type of view that can be converted into this model.
    type ViewType: View + ?Sized;

    /// Converts a view into a model.
    fn from_view(view: &Self::ViewType) -> Self;
}
/// Blanket implementation of `TryFromView` for any type that implements `FromView`.
impl<VT: FromView> TryFromView for VT {
    type ViewType = VT::ViewType;

    /// Attempts to parse a model from the provided view, returning an error if the view is
    /// invalid.
    #[inline]
    fn try_from_view(view: &Self::ViewType) -> Result<Self, ViewConversionError> {
        Ok(VT::from_view(view))
    }
}

/// Fallible conversion from a view to a model
pub trait TryToModel: View {
    /// The type of model that can be converted from this view.
    type ModelType: TryFromView<ViewType = Self>;

    /// Attempts to parse a model from the provided view, returning an error if the view is
    /// invalid.
    ///
    /// Prefer [ToModel::to_model] if it exists, as it is infallible.
    #[inline]
    fn try_to_model(&self) -> Result<Self::ModelType, ViewConversionError> {
        Self::ModelType::try_from_view(self)
    }
}
/// Blanket implementation of `TryToModel` for any type that implements `TryFromModel`.
impl<V: View + TryFromModel + ?Sized> TryToModel for V
where
    V::ModelType: TryFromView<ViewType = V>,
{
    type ModelType = V::ModelType;
}

/// Infallible conversion from a view to a model.
pub trait ToModel: View {
    /// The type of model that can be converted from this view.
    type ModelType: FromView<ViewType = Self>;

    /// Parses a model from the provided view.
    #[inline]
    fn to_model(&self) -> Self::ModelType {
        Self::ModelType::from_view(self)
    }
}
/// Blanket implementation of `ToModel` for any type that implements `FromView`.
impl<V: View + TryFromModel + ?Sized> ToModel for V
where
    V::ModelType: FromView<ViewType = V>,
{
    type ModelType = V::ModelType;
}

// Model to View

/// Conversion from a model to a view.
///
/// No Infallible conversion is provided, as encoding may fail due to insufficient buffer size or
/// other reasons.
pub trait TryFromModel: View {
    /// The type of model that can be converted from this view.
    type ModelType: Model<ViewType = Self>;

    /// Attempts to encode a model into the provided buffer and return a view over the encoded
    /// data.
    #[inline]
    fn try_from_model<'buf>(
        model: &Self::ModelType,
        buf: &'buf mut [u8],
    ) -> Result<(&'buf mut Self, &'buf mut [u8]), EncodeError> {
        model.encode_to_view(buf)
    }

    /// Attempts to encode a model into a boxed view and return it.
    #[inline]
    fn try_boxed_from_model(model: &Self::ModelType) -> Result<Box<Self>, InvalidStructureError> {
        model.encode_to_owned_view()
    }
}
