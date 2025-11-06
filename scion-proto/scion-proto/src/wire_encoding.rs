// Copyright 2025 Mysten Labs
// Copyright 2025 Anapaya Systems
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

//! Traits and tools to decode and encode objects.

use bytes::{Buf, BufMut, Bytes, BytesMut};

use crate::packet::InadequateBufferSize;

/// A trait for types decodable from a wire format, without any additional information.
pub trait WireDecode<T>: Sized {
    /// The error type returned on a failed decode.
    type Error;

    /// Decodes an object from the provided data, such as a [`bytes::Buf`].
    ///
    /// The buffer is advanced by as many bytes as necessary to decode the object.
    /// Bytes are consumed regardless of whether or not decoding fails.
    fn decode(data: &mut T) -> Result<Self, Self::Error>;
}

/// A trait for types decodable from a wire format, *with* additional information.
///
/// In contrast to [`WireDecode`], this trait allows the implementing type to specify
/// additional data that should be passed to the decode calls, by means of the
/// associated type [`Self::Context`].
pub trait WireDecodeWithContext<T>: Sized {
    /// The error type returned on a failed decode.
    type Error;
    /// Data that should be provided to calls to decode.
    type Context;

    /// Decodes an object from the provided data, such as a [`bytes::Buf`], with additional context.
    ///
    /// Callers must provide the required contextual information, as specified by [`Self::Context`],
    /// to decode the object. This may be, for example, the length of the amount of data comprising
    /// the object or the type of the object signalled elsewhere.
    ///
    /// The buffer is advanced by as many bytes as necessary to decode the object.
    /// Bytes are consumed regardless of whether or not decoding fails.
    fn decode_with_context(data: &mut T, context: Self::Context) -> Result<Self, Self::Error>;
}

/// The trait provides methods to encode the object to a provided buffer.
///
/// To implement the trait with just a single error, only the [`Self::encoded_length`] and
/// [`Self::encode_to_unchecked`] methods must be implemented. The default implementation of the
/// [`Self::encode_to`] method then checks if the buffer has sufficient capacity and returns the
/// default error otherwise.
///
/// If multiple different errors should be returned, the [`Self::encode_to`] method must be
/// implemented in addition. In that case, the [`Self::encode_to_unchecked`] method can simply
/// call `self.encode_to(buffer).unwrap()`.
pub trait WireEncode {
    /// The error type returned on a failed encode.
    type Error: std::error::Error + Default;

    /// Total length in bytes of the encoded data.
    fn encoded_length(&self) -> usize;

    /// Try to encode the object to the provided buffer.
    ///
    /// Errors:
    ///
    /// Returns an error if the buffer does not have sufficient capacity.
    fn encode_to<T: BufMut>(&self, buffer: &mut T) -> Result<(), Self::Error> {
        if buffer.remaining_mut() < self.encoded_length() {
            return Err(Self::Error::default());
        }
        self.encode_to_unchecked(buffer);
        Ok(())
    }

    /// Encode the object to the provided buffer.
    ///
    /// It is the caller's responsibility to provide a buffer of sufficient capacity.
    ///
    /// Can panic if the buffer does not have sufficient capacity.
    fn encode_to_unchecked<T: BufMut>(&self, buffer: &mut T);

    /// Encodes the object into a newly created buffer and returns it as a [`Bytes`] object.
    fn encode_to_bytes(&self) -> Bytes {
        let mut buffer = BytesMut::new();
        self.encode_to_unchecked(&mut buffer); // BytesMut will grow as needed
        buffer.freeze()
    }
}

impl WireEncode for Bytes {
    type Error = InadequateBufferSize;

    #[inline]
    fn encoded_length(&self) -> usize {
        self.remaining()
    }

    #[inline]
    fn encode_to_unchecked<T: BufMut>(&self, buffer: &mut T) {
        buffer.put_slice(self)
    }

    #[inline]
    fn encode_to_bytes(&self) -> Bytes {
        self.clone()
    }
}

/// The trait provides methods to encode the object to multiple `Bytes` objects, optionally using
/// a provided buffer to prevent the need for allocation.
///
/// The generic parameter specifies the length of the returned array of `Bytes`.
///
/// To implement the trait with just a single error, only the [`Self::required_capacity`],
/// [`Self::total_length`], and [`Self::encode_with_unchecked`] methods must be implemented.
/// The default implementation of the [`Self::encode_with`] method then checks if the buffer has
/// sufficient capacity and returns the default error otherwise.
///
/// If multiple different errors should be returned, the [`Self::encode_with`] method must be
/// implemented in addition. In that case, the [`Self::encode_with_unchecked`] method can simply
/// call `self.encode_with(buffer).unwrap()`.
pub trait WireEncodeVec<const N: usize> {
    /// The error type returned on a failed encode.
    type Error: std::error::Error + Default;

    /// Try to encode the object, optionally using the provided buffer.
    ///
    /// Errors:
    ///
    /// Returns an error if the buffer does not have sufficient capacity.
    fn encode_with(&self, buffer: &mut BytesMut) -> Result<[Bytes; N], Self::Error> {
        if buffer.remaining_mut() < self.required_capacity() {
            return Err(Self::Error::default());
        }
        Ok(self.encode_with_unchecked(buffer))
    }

    /// Try to encode the object, optionally using the provided buffer.
    ///
    /// It is the caller's responsibility to provide a buffer of sufficient capacity.
    ///
    /// Can panic if the buffer does not have sufficient capacity.
    fn encode_with_unchecked(&self, buffer: &mut BytesMut) -> [Bytes; N];

    /// Encodes the object using a newly created buffer.
    fn encode_to_bytes_vec(&self) -> [Bytes; N] {
        let mut buffer = BytesMut::new();
        self.encode_with_unchecked(&mut buffer) // BytesMut will grow as needed
    }

    /// Total length in bytes of all `Bytes` returned by [`Self::encode_with`].
    fn total_length(&self) -> usize;

    /// Required buffer capacity for the encoding.
    fn required_capacity(&self) -> usize;
}

impl<T: WireEncode> WireEncodeVec<1> for T {
    type Error = <T as WireEncode>::Error;

    fn encode_with_unchecked(&self, buffer: &mut BytesMut) -> [Bytes; 1] {
        self.encode_to_unchecked(buffer);
        [buffer.split().freeze()]
    }

    #[inline]
    fn total_length(&self) -> usize {
        self.encoded_length()
    }

    #[inline]
    fn required_capacity(&self) -> usize {
        self.encoded_length()
    }
}

impl WireEncode for &[u8] {
    type Error = InadequateBufferSize;

    #[inline]
    fn encoded_length(&self) -> usize {
        self.len()
    }

    #[inline]
    fn encode_to_unchecked<T: BufMut>(&self, buffer: &mut T) {
        buffer.put_slice(self)
    }
}

/// An enum that stores the undecoded bytes of a field.
///
/// When presented with a typed, encoded, representation of a header field, this library may
/// not currently support decoding the type. In this case, it may return a MaybeEncoded
/// object in the case that the input may be valid but cannot be decoded.
#[derive(Debug, PartialEq, Eq, Clone, Copy)]
pub enum MaybeEncoded<T, U> {
    /// The successfully decoded variant.
    Decoded(T),
    /// The data associated with an instance that cannot currently be decoded by the library.
    Encoded(U),
}

impl<T, U> MaybeEncoded<T, U> {
    /// Consumes the MaybeEncoded returning an Some(t) for Maybe::Encoded(t) otherwise None.
    pub fn decoded(self) -> Option<T> {
        match self {
            MaybeEncoded::Decoded(decoded) => Some(decoded),
            MaybeEncoded::Encoded(_) => None,
        }
    }
}

impl<T, U> MaybeEncoded<T, U>
where
    T: Into<U>,
{
    /// Returns the encoded value of a [`MaybeEncoded`] object (encoding the given value if
    /// necessary).
    pub fn into_encoded(self) -> U {
        match self {
            MaybeEncoded::Decoded(decoded) => decoded.into(),
            MaybeEncoded::Encoded(encoded) => encoded,
        }
    }
}

macro_rules! bounded_uint {
    (
        $(#[$outer:meta])*
        pub struct $name:ident($type:ty : $bits:literal);
    ) => {
        $(#[$outer])*
        #[derive(Debug, Clone, Copy, PartialOrd, Ord, PartialEq, Eq, Hash)]
        pub struct $name($type);

        impl $name {
            /// The number of bits useable for an instance of this type.
            pub const BITS: u32 = $bits;

            /// The maximum possible value for an instance of this type.
            pub const MAX: Self = Self((1 << $bits) - 1);

            /// Create a new instance if the value is at most `Self::MAX.value()`.
            pub const fn new(value: $type) -> Option<Self> {
                if value <= Self::MAX.0 {
                    Some(Self(value))
                } else {
                    None
                }
            }

            /// Create a new instance with the provided value.
            ///
            /// # Safety
            ///
            /// The value should be at most `Self::MAX.value()`.
            pub const fn new_unchecked(value: $type) -> Self {
                debug_assert!(value <= Self::MAX.0);
                Self(value)
            }

            /// Get the value of this instance as its underlying type.
            #[inline]
            pub const fn get(&self) -> $type {
                self.0
            }
        }

        impl From<$type> for $name {
            fn from(value: $type) -> Self {
                Self::new_unchecked(value)
            }
        }
    };
}
pub(crate) use bounded_uint;

#[cfg(test)]
mod tests {
    use super::*;

    static BYTES: Bytes = Bytes::from_static(&[0, 1, 2, 3]);

    #[test]
    fn bytes_encoding() {
        let b = BYTES.clone();
        let mut buffer = BytesMut::new();
        assert!(b.encode_to(&mut buffer).is_ok());
        assert_eq!(b, buffer.split().freeze());
        assert_eq!(b, b.encode_to_bytes());
        assert_eq!(b.encoded_length(), 4);
        assert_eq!(b.encoded_length(), b.encode_to_bytes().len());
    }

    #[test]
    fn bytes_encoding_vec() {
        assert_eq!(std::slice::from_ref(&BYTES), BYTES.encode_to_bytes_vec());
        assert_eq!(BYTES.clone().required_capacity(), 4);
        assert_eq!(BYTES.clone().total_length(), 4);
        assert_eq!(BYTES.clone().encode_to_bytes_vec()[0].len(), 4);
    }

    #[test]
    #[should_panic]
    fn bytes_encoding_unchecked_failure() {
        let mut buffer = [0_u8; 1];
        BYTES.encode_to_unchecked(&mut buffer.as_mut());
    }

    #[test]
    fn bytes_encoding_failure() {
        let mut buffer = [0_u8; 1];
        assert_eq!(
            BYTES.clone().encode_to(&mut buffer.as_mut()),
            Err(InadequateBufferSize)
        );
    }
}
