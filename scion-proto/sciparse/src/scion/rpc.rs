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

//! RPC utility types

use std::borrow::Cow;

/// Errors that can occur when converting from RPC types.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("failed to convert from rpc: {message}")]
pub struct FromRpcError {
    /// Error message describing the conversion failure.
    pub message: Cow<'static, str>,
}
impl FromRpcError {
    /// Creates a new [`FromRpcError`] with the given message.
    #[inline]
    pub fn new(message: impl Into<Cow<'static, str>>) -> Self {
        Self {
            message: message.into(),
        }
    }
}

impl<T: Into<Cow<'static, str>>> From<T> for FromRpcError {
    #[inline]
    fn from(value: T) -> Self {
        Self::new(value)
    }
}
