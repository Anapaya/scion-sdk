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

//! Utility macros

/// Creates a basic From impl,
/// e.g.
/// ```ignore
/// impl_from!(Src, Dst, |v| body);
/// // expands to
/// impl From<Src> for Dst {
///     fn from(v: Src) -> Self {
///         body
///     }
/// }
/// ```
macro_rules! impl_from {
    ($src:ty, $dst:ty, |$v:ident| $body:expr) => {
        impl From<$src> for $dst {
            fn from($v: $src) -> Self {
                $body
            }
        }
    };
}
pub(crate) use impl_from;

macro_rules! impl_from_ref {
    ($src:ty, $dst:ty, |$v:ident| $body:expr) => {
        impl<'a> From<&'a $src> for $dst {
            fn from($v: &'a $src) -> Self {
                $body
            }
        }
    };
}
pub(crate) use impl_from_ref;
