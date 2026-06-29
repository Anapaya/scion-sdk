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

//! SCION dataplane path views

use std::fmt::Display;

use crate::{
    core::{macros::impl_from, view::View},
    dataplane_path::{
        model::DpPath,
        onehop::view::OneHopPathView,
        standard::view::StandardPathView,
        types::{PathReverseError, PathType},
    },
};

/// View over a SCION dataplane path, which can be of different types (e.g., standard, one-hop).
#[derive(Debug, Clone, Copy)]
pub enum ScionDpPathViewRef<'a> {
    /// View over a standard SCION path
    Standard(&'a StandardPathView),
    /// View over a one-hop SCION path
    OneHop(&'a OneHopPathView),
    /// View over an unsupported path type
    Unsupported {
        /// The unsupported path type
        path_type: PathType,
        /// Raw path data
        data: &'a [u8],
    },
    /// Empty path type
    Empty,
}
impl ScionDpPathViewExt for ScionDpPathViewRef<'_> {
    /// Returns an immutable view over the same path data.
    fn as_ref(&self) -> ScionDpPathViewRef<'_> {
        *self
    }
}
impl<'a> From<&'a StandardPathView> for ScionDpPathViewRef<'a> {
    fn from(value: &'a StandardPathView) -> Self {
        ScionDpPathViewRef::Standard(value)
    }
}
impl<'a> From<&'a OneHopPathView> for ScionDpPathViewRef<'a> {
    fn from(value: &'a OneHopPathView) -> Self {
        ScionDpPathViewRef::OneHop(value)
    }
}
impl Display for ScionDpPathViewRef<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        self.display(f)
    }
}

/// Mutable view over different path types
#[derive(Debug)]
pub enum ScionDpPathViewRefMut<'a> {
    /// Mutable view over a standard SCION path
    Standard(&'a mut StandardPathView),
    /// Mutable view over a one-hop SCION path
    OneHop(&'a mut OneHopPathView),
    /// Mutable view over an unsupported path type
    Unsupported {
        /// The unsupported path type
        path_type: PathType,
        /// Raw path data
        buf: &'a mut [u8],
    },
    /// Empty path type
    Empty,
}
impl ScionDpPathViewExt for ScionDpPathViewRefMut<'_> {
    /// Returns an immutable view over the same path data.
    fn as_ref(&self) -> ScionDpPathViewRef<'_> {
        match self {
            ScionDpPathViewRefMut::Standard(standard_path_view) => {
                ScionDpPathViewRef::Standard(standard_path_view)
            }
            ScionDpPathViewRefMut::OneHop(one_hop_path_view) => {
                ScionDpPathViewRef::OneHop(one_hop_path_view)
            }
            ScionDpPathViewRefMut::Unsupported { path_type, buf } => {
                ScionDpPathViewRef::Unsupported {
                    path_type: *path_type,
                    data: buf,
                }
            }
            ScionDpPathViewRefMut::Empty => ScionDpPathViewRef::Empty,
        }
    }
}
impl ScionDpPathViewExtMut for ScionDpPathViewRefMut<'_> {
    fn as_mut(&mut self) -> ScionDpPathViewRefMut<'_> {
        // XXX(ake): looks a bit weird, but this allows reborrowing the mutable reference while
        // preserving the lifetime.
        match self {
            ScionDpPathViewRefMut::Standard(v) => ScionDpPathViewRefMut::Standard(v),
            ScionDpPathViewRefMut::OneHop(v) => ScionDpPathViewRefMut::OneHop(v),
            ScionDpPathViewRefMut::Unsupported { path_type, buf } => {
                ScionDpPathViewRefMut::Unsupported {
                    path_type: *path_type,
                    buf,
                }
            }
            ScionDpPathViewRefMut::Empty => ScionDpPathViewRefMut::Empty,
        }
    }
}
impl<'a> From<&'a mut StandardPathView> for ScionDpPathViewRef<'a> {
    fn from(value: &'a mut StandardPathView) -> Self {
        ScionDpPathViewRef::Standard(value)
    }
}
impl<'a> From<&'a mut OneHopPathView> for ScionDpPathViewRef<'a> {
    fn from(value: &'a mut OneHopPathView) -> Self {
        ScionDpPathViewRef::OneHop(value)
    }
}
impl Display for ScionDpPathViewRefMut<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        self.display(f)
    }
}

/// Owned view over different path types
#[derive(Debug, Clone)]
pub enum ScionDpPathView {
    /// Owned view over a standard SCION path
    Standard(Box<StandardPathView>),
    /// Owned view over a one-hop SCION path
    OneHop(OneHopPathView),
    /// Owned view over an unsupported path type
    Unsupported {
        /// The unsupported path type
        path_type: PathType,
        /// Raw path data
        data: Box<[u8]>,
    },
    /// Empty path type
    Empty,
}
impl ScionDpPathViewExt for ScionDpPathView {
    /// Returns an immutable view over the same path data.
    fn as_ref(&self) -> ScionDpPathViewRef<'_> {
        match self {
            ScionDpPathView::Standard(standard_path_view) => {
                ScionDpPathViewRef::Standard(standard_path_view.as_ref())
            }
            ScionDpPathView::OneHop(one_hop_path_view) => {
                ScionDpPathViewRef::OneHop(one_hop_path_view)
            }
            ScionDpPathView::Unsupported { path_type, data } => {
                ScionDpPathViewRef::Unsupported {
                    path_type: *path_type,
                    data: data.as_ref(),
                }
            }
            ScionDpPathView::Empty => ScionDpPathViewRef::Empty,
        }
    }
}
impl ScionDpPathViewExtMut for ScionDpPathView {
    fn as_mut(&mut self) -> ScionDpPathViewRefMut<'_> {
        match self {
            ScionDpPathView::Standard(standard_path_view) => {
                ScionDpPathViewRefMut::Standard(standard_path_view.as_mut())
            }
            ScionDpPathView::OneHop(one_hop_path_view) => {
                ScionDpPathViewRefMut::OneHop(one_hop_path_view)
            }
            ScionDpPathView::Unsupported { path_type, data } => {
                ScionDpPathViewRefMut::Unsupported {
                    path_type: *path_type,
                    buf: data.as_mut(),
                }
            }
            ScionDpPathView::Empty => ScionDpPathViewRefMut::Empty,
        }
    }
}
impl_from!(Box<StandardPathView>, ScionDpPathView, |v| {
    ScionDpPathView::Standard(v)
});
impl_from!(OneHopPathView, ScionDpPathView, |v| {
    ScionDpPathView::OneHop(v)
});
impl Display for ScionDpPathView {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        self.display(f)
    }
}

/// Helper trait for working with [`ScionDpPathView`] and its references, providing common
/// functionality across different path types.
pub trait ScionDpPathViewExt {
    /// Returns an immutable view over the path data.
    fn as_ref(&self) -> ScionDpPathViewRef<'_>;

    /// Clones the path data into an owned view.
    fn to_owned_view(&self) -> ScionDpPathView {
        match self.as_ref() {
            ScionDpPathViewRef::Standard(standard_path_view) => {
                ScionDpPathView::Standard(standard_path_view.to_boxed())
            }
            ScionDpPathViewRef::OneHop(one_hop_path_view) => {
                ScionDpPathView::OneHop(one_hop_path_view.clone())
            }
            ScionDpPathViewRef::Unsupported { path_type, data } => {
                ScionDpPathView::Unsupported {
                    path_type,
                    data: Box::from(data),
                }
            }
            ScionDpPathViewRef::Empty => ScionDpPathView::Empty,
        }
    }

    /// Returns the raw bytes of the path data as a slice.
    fn as_slice(&self) -> &[u8] {
        match self.as_ref() {
            ScionDpPathViewRef::Standard(standard_path_view) => standard_path_view.as_slice(),
            ScionDpPathViewRef::OneHop(one_hop_path_view) => one_hop_path_view.as_slice(),
            ScionDpPathViewRef::Unsupported { data, .. } => data,
            ScionDpPathViewRef::Empty => &[],
        }
    }

    /// Returns the expiration time of the path in seconds since the UNIX epoch.
    ///
    /// Returns none if the path does not have an expiration time (e.g., unsupported path types).
    fn expiration(&self) -> Option<u32> {
        match self.as_ref() {
            ScionDpPathViewRef::Standard(standard_path_view) => {
                Some(standard_path_view.expiration())
            }
            ScionDpPathViewRef::OneHop(one_hop_path_view) => Some(one_hop_path_view.expiration()),
            ScionDpPathViewRef::Empty => Some(u32::MAX),
            ScionDpPathViewRef::Unsupported { .. } => None,
        }
    }

    /// Returns the first egress interface of the path, if available.
    fn first_egress_interface(&self) -> Option<u16> {
        match self.as_ref() {
            ScionDpPathViewRef::Standard(standard_path_view) => {
                Some(standard_path_view.hop_fields().first()?.cons_egress())
            }
            ScionDpPathViewRef::OneHop(one_hop_path_view) => {
                Some(one_hop_path_view.hop_fields().first()?.cons_egress())
            }
            ScionDpPathViewRef::Empty => None,
            ScionDpPathViewRef::Unsupported { .. } => None,
        }
    }

    /// Returns the last ingress interface of the path, if available.
    fn last_ingress_interface(&self) -> Option<u16> {
        match self.as_ref() {
            ScionDpPathViewRef::Standard(standard_path_view) => {
                Some(standard_path_view.hop_fields().last()?.cons_ingress())
            }
            ScionDpPathViewRef::OneHop(one_hop_path_view) => {
                Some(one_hop_path_view.hop_fields().last()?.cons_ingress())
            }
            ScionDpPathViewRef::Empty => None,
            ScionDpPathViewRef::Unsupported { .. } => None,
        }
    }

    /// Converts the view into a `DpPath` model.
    fn to_model(&self) -> DpPath {
        DpPath::from_view(&self.as_ref())
    }

    /// Displays the path view in a human-readable format.
    fn display(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self.as_ref() {
            ScionDpPathViewRef::Standard(standard_path_view) => write!(f, "{}", standard_path_view),
            ScionDpPathViewRef::OneHop(one_hop_path_view) => write!(f, "{}", one_hop_path_view),
            ScionDpPathViewRef::Unsupported { path_type, .. } => {
                write!(f, "[unsupported] {:?}", path_type)
            }
            ScionDpPathViewRef::Empty => write!(f, "[empty]"),
        }
    }
}
impl<T: ScionDpPathViewExt> ScionDpPathViewExt for &T {
    fn as_ref(&self) -> ScionDpPathViewRef<'_> {
        (*self).as_ref()
    }
}

/// Helper trait for working with mutable references to [`ScionDpPathView`], providing common
/// functionality across different path types.
pub trait ScionDpPathViewExtMut: ScionDpPathViewExt {
    /// Returns a mutable view over the path data.
    fn as_mut(&mut self) -> ScionDpPathViewRefMut<'_>;

    /// Attempts to reverse the path in place, if supported by the path type.
    ///
    /// Returns an error if the path type does not support reversal.
    fn try_reverse(&mut self) -> Result<&mut Self, PathReverseError>
    where
        Self: Sized,
    {
        let mut_self = self.as_mut();

        match mut_self {
            ScionDpPathViewRefMut::Standard(standard_path_view) => {
                standard_path_view.try_reverse()?;
                Ok(self)
            }
            ScionDpPathViewRefMut::OneHop(one_hop_path_view) => {
                one_hop_path_view.try_reverse()?;
                Ok(self)
            }
            ScionDpPathViewRefMut::Empty => Ok(self),
            ScionDpPathViewRefMut::Unsupported { .. } => {
                Err(PathReverseError::new(
                    "Cannot reverse unsupported path type",
                ))
            }
        }
    }
}
