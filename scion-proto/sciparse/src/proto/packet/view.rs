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

//! SCION header views
//!
//! See [`View`](crate::core::view) for more information about views in general.

use std::mem::transmute;

use super::classify::{ClassifiedPacketView, ClassifyError};
use crate::{
    core::view::{View, ViewConversionError},
    header::{layout::ScionHeaderLayout, view::ScionHeaderView},
    payload::{ProtocolNumber, scmp::view::ScmpPayloadView, udp::view::UdpDatagramView},
};

// Marker types for different view variants.
/// Marker type for a raw (untyped) SCION packet view.
pub struct Raw;
/// Marker type for a SCION/UDP packet view.
pub struct Udp;
/// Marker type for a SCION/SCMP packet view.
pub struct Scmp;

/// A view over a complete SCION packet
#[repr(transparent)]
pub struct ScionPacketView<T = Raw>(std::marker::PhantomData<T>, [u8]);
impl<T> ScionPacketView<T> {
    /// Returns a view over the SCION headers
    #[inline]
    pub fn header(&self) -> &ScionHeaderView {
        // Safety: Buffer size is checked on construction of ScionPacketView
        unsafe {
            let header_len = ScionHeaderView::from_slice_unchecked(&self.1).header_len() as usize;
            ScionHeaderView::from_slice_unchecked(self.1.get_unchecked(..header_len))
        }
    }

    /// Returns a mutable view over the SCION headers
    #[inline]
    pub fn header_mut(&mut self) -> &mut ScionHeaderView {
        // Safety: Buffer size is checked on construction of ScionPacketView
        unsafe {
            let header_len = ScionHeaderView::from_slice_unchecked(&self.1).header_len() as usize;
            ScionHeaderView::from_mut_slice_unchecked(self.1.get_unchecked_mut(..header_len))
        }
    }

    /// Returns a slice of the payload
    #[inline]
    pub fn payload(&self) -> &[u8] {
        // Safety: Buffer size is checked on construction of ScionPacketView
        unsafe {
            let header_len = ScionHeaderView::from_slice_unchecked(&self.1).header_len() as usize;
            self.1.get_unchecked(header_len..)
        }
    }
}

/// A view over a raw SCION packet (payload protocol unspecified).
pub type ScionRawPacketView = ScionPacketView<Raw>;
impl View for ScionRawPacketView {
    #[inline]
    fn has_required_size(buf: &[u8]) -> Result<usize, ViewConversionError> {
        let layout = ScionHeaderLayout::from_slice(buf)?;

        let packet_len = layout.header_len + layout.payload_len;

        if buf.len() < packet_len {
            return Err(ViewConversionError::BufferTooSmall {
                at: "Payload",
                required: packet_len,
                actual: buf.len(),
            });
        }

        Ok(packet_len)
    }

    #[inline]
    unsafe fn from_slice_unchecked(buf: &[u8]) -> &Self {
        // SAFETY: see View trait documentation
        unsafe { transmute(buf) }
    }

    #[inline]
    unsafe fn from_mut_slice_unchecked(buf: &mut [u8]) -> &mut Self {
        // SAFETY: see View trait documentation
        unsafe { transmute(buf) }
    }

    #[inline]
    unsafe fn from_boxed_unchecked(buf: Box<[u8]>) -> Box<Self> {
        // SAFETY: see View trait documentation
        unsafe { transmute(buf) }
    }

    #[inline]
    unsafe fn as_bytes_mut(&mut self) -> &mut [u8] {
        &mut self.1
    }

    #[inline]
    fn as_bytes_boxed(self: Box<Self>) -> Box<[u8]> {
        // SAFETY: This is safe because the view no longer exists after this call.
        // This just returns the underlying buffer.
        unsafe { std::mem::transmute(self) }
    }

    #[inline]
    fn as_bytes(&self) -> &[u8] {
        &self.1
    }
}
impl ScionRawPacketView {
    /// Returns a mutable slice of the payload
    #[inline]
    pub fn payload_mut(&mut self) -> &mut [u8] {
        // Safety: Buffer size is checked on construction of ScionPacketView
        unsafe {
            let header_len = ScionHeaderView::from_slice_unchecked(&self.1).header_len() as usize;
            self.1.get_unchecked_mut(header_len..)
        }
    }

    /// Classifies this packet by inspecting its `next_header` field.
    ///
    /// For UDP packets the destination port is read from the UDP header.
    /// For SCMP packets the destination port is deduced from the message type:
    /// - informational messages (echo request/reply, traceroute request/reply): identifier field
    /// - error messages: source port of the quoted inner UDP datagram (if parseable)
    ///
    /// Returns [`ClassifiedPacketView::Other`] only for unknown `next_header` values. SCMP packets
    /// are always classified as [`ClassifiedPacketView::Scmp`], with `dst_port` set to `None` when
    /// no port can be deduced. Never allocates.
    pub fn classify(&self) -> Result<ClassifiedPacketView<'_>, ClassifyError> {
        match self.header().next_header().into() {
            ProtocolNumber::Udp => {
                let udp =
                    ScionUdpPacketView::try_from_raw(self).map_err(ClassifyError::MalformedUdp)?;
                Ok(ClassifiedPacketView::Udp(udp))
            }
            ProtocolNumber::Scmp => {
                let scmp = ScionScmpPacketView::try_from_raw(self)
                    .map_err(ClassifyError::MalformedScmp)?;
                Ok(ClassifiedPacketView::Scmp(scmp))
            }
            _ => Ok(ClassifiedPacketView::Other(self)),
        }
    }

    /// Tries to interpret this packet as a SCION/UDP packet.
    ///
    /// Checks that the payload is large enough for a UDP header but does not verify the
    /// `next_header` field.
    pub fn try_into_udp(&self) -> Result<&ScionUdpPacketView, ViewConversionError> {
        ScionUdpPacketView::try_from_raw(self)
    }

    /// Converts this packet view into a mutable UDP packet view. This only checks that the payload
    /// is large enough for a UDP header but does not check the packets NextHeader field.
    pub fn try_into_udp_mut(&mut self) -> Result<&mut ScionUdpPacketView, ViewConversionError> {
        ScionUdpPacketView::try_from_raw_mut(self)
    }

    /// Converts this packet view into a UDP packet view. This only checks that the payload is
    /// large enough for a UDP header but does not check the packets NextHeader field.
    pub fn try_into_udp_owned(
        self: Box<Self>,
    ) -> Result<Box<ScionUdpPacketView>, ViewConversionError> {
        ScionUdpPacketView::try_from_raw_owned(self)
    }

    /// Tries to interpret this packet as a SCION/SCMP packet.
    ///
    /// Checks that the payload is large enough for a SCMP header but does not verify the
    /// `next_header` field.
    pub fn try_into_scmp(&self) -> Result<&ScionScmpPacketView, ViewConversionError> {
        ScionScmpPacketView::try_from_raw(self)
    }

    /// Converts this packet view into a mutable SCMP packet view. This only checks that the payload
    /// is large enough for a SCMP header but does not check the packets NextHeader field.
    pub fn try_into_scmp_mut(&mut self) -> Result<&mut ScionScmpPacketView, ViewConversionError> {
        ScionScmpPacketView::try_from_raw_mut(self)
    }

    /// Converts this packet view into a SCMP packet view. This only checks that the payload is
    /// large enough for a SCMP header but does not check the packets NextHeader field.
    pub fn try_into_scmp_owned(
        self: Box<Self>,
    ) -> Result<Box<ScionScmpPacketView>, ViewConversionError> {
        ScionScmpPacketView::try_from_raw_owned(self)
    }
}

/// A view over a SCION packet whose payload is a UDP datagram.
pub type ScionUdpPacketView = ScionPacketView<Udp>;
impl View for ScionUdpPacketView {
    #[inline]
    fn has_required_size(buf: &[u8]) -> Result<usize, ViewConversionError> {
        let packet_len = ScionRawPacketView::has_required_size(buf)?;
        let view = unsafe { ScionRawPacketView::from_slice_unchecked(buf) };
        // Note: we only check that the buffer is large enough for a UDP header, not
        // that the packet is actually a udp packet (the next_header field could be something else).
        _ = UdpDatagramView::has_required_size(view.payload())?;
        Ok(packet_len)
    }

    #[inline]
    unsafe fn from_slice_unchecked(buf: &[u8]) -> &Self {
        // SAFETY: see View trait documentation
        unsafe { transmute(buf) }
    }

    #[inline]
    unsafe fn from_mut_slice_unchecked(buf: &mut [u8]) -> &mut Self {
        // SAFETY: see View trait documentation
        unsafe { transmute(buf) }
    }

    #[inline]
    unsafe fn from_boxed_unchecked(buf: Box<[u8]>) -> Box<Self> {
        // SAFETY: see View trait documentation
        unsafe { transmute(buf) }
    }

    #[inline]
    unsafe fn as_bytes_mut(&mut self) -> &mut [u8] {
        &mut self.1
    }

    #[inline]
    fn as_bytes_boxed(self: Box<Self>) -> Box<[u8]> {
        // SAFETY: repr(transparent) over [u8], identical fat pointer layout
        unsafe { transmute(self) }
    }

    #[inline]
    fn as_bytes(&self) -> &[u8] {
        &self.1
    }
}
impl ScionUdpPacketView {
    /// Converts a raw SCION packet into a UDP packet view. This only checks that the payload is
    /// large enough for a UDP header but does not check the packets NextHeader field.
    pub fn try_from_raw(raw: &ScionRawPacketView) -> Result<&Self, ViewConversionError> {
        // There won't be any trailing bytes, so we can just use from_slice.
        let (view, _) = ScionUdpPacketView::from_slice(raw.as_bytes())?;
        Ok(view)
    }

    /// Converts a raw SCION packet into a UDP packet view. This only checks that the payload is
    /// large enough for a UDP header but does not check the packets NextHeader field.
    pub fn try_from_raw_mut(
        raw: &mut ScionRawPacketView,
    ) -> Result<&mut Self, ViewConversionError> {
        // There won't be any trailing bytes, so we can just use from_mut_slice.
        let (view, _) = {
            // SAFETY: ScionUdpPacketView does not offer safe functions to change the size of the
            // buffer or mutable access to fields that would cause out of bounds access.
            unsafe { ScionUdpPacketView::from_mut_slice(raw.as_bytes_mut())? }
        };
        Ok(view)
    }

    /// Converts a raw SCION packet into a UDP packet view. This only checks that the payload is
    /// large enough for a UDP header but does not check the packets NextHeader field.
    pub fn try_from_raw_owned(
        raw: Box<ScionRawPacketView>,
    ) -> Result<Box<Self>, ViewConversionError> {
        ScionUdpPacketView::from_boxed(raw.as_bytes_boxed())
    }

    /// Converts a UDP packet view into a raw SCION packet view.
    pub fn into_raw(&self) -> &ScionRawPacketView {
        // Safety: The buffer is large enough for a SCION raw packet.
        unsafe { ScionRawPacketView::from_slice_unchecked(self.as_bytes()) }
    }

    /// Converts a UDP packet view into a raw SCION packet view.
    pub fn into_raw_mut(&mut self) -> &mut ScionRawPacketView {
        // Safety: The buffer is large enough for a SCION raw packet.
        unsafe { ScionRawPacketView::from_mut_slice_unchecked(self.as_bytes_mut()) }
    }

    /// Converts a UDP packet view into a raw SCION packet view.
    pub fn into_raw_owned(self: Box<Self>) -> Box<ScionRawPacketView> {
        unsafe { ScionRawPacketView::from_boxed_unchecked(self.as_bytes_boxed()) }
    }

    /// Returns a UDP datagram view over packets payload.
    /// This returned view only includes the part of the payload slice that is actually taken up by
    /// the UDP datagram.
    pub fn udp(&self) -> &UdpDatagramView {
        // The buffer size was already checked when creating the ScionUdpPacketView.
        let (view, _) = UdpDatagramView::from_slice(self.payload())
            .expect("udp payload is not large enough for a UDP header");
        view
    }
}
impl<'a> TryFrom<&'a ScionRawPacketView> for &'a ScionUdpPacketView {
    type Error = ViewConversionError;

    fn try_from(value: &'a ScionRawPacketView) -> Result<Self, Self::Error> {
        ScionUdpPacketView::try_from_raw(value)
    }
}
impl<'a> TryFrom<&'a mut ScionRawPacketView> for &'a mut ScionUdpPacketView {
    type Error = ViewConversionError;

    fn try_from(value: &'a mut ScionRawPacketView) -> Result<Self, Self::Error> {
        ScionUdpPacketView::try_from_raw_mut(value)
    }
}
impl TryFrom<Box<ScionRawPacketView>> for Box<ScionUdpPacketView> {
    type Error = ViewConversionError;

    fn try_from(value: Box<ScionRawPacketView>) -> Result<Self, Self::Error> {
        ScionUdpPacketView::try_from_raw_owned(value)
    }
}
impl<'a> From<&'a ScionUdpPacketView> for &'a ScionRawPacketView {
    fn from(value: &'a ScionUdpPacketView) -> Self {
        value.into_raw()
    }
}
impl<'a> From<&'a mut ScionUdpPacketView> for &'a mut ScionRawPacketView {
    fn from(value: &'a mut ScionUdpPacketView) -> Self {
        value.into_raw_mut()
    }
}
impl From<Box<ScionUdpPacketView>> for Box<ScionRawPacketView> {
    fn from(value: Box<ScionUdpPacketView>) -> Self {
        value.into_raw_owned()
    }
}

/// A view over a SCION packet whose payload is an SCMP message.
pub type ScionScmpPacketView = ScionPacketView<Scmp>;
impl View for ScionScmpPacketView {
    #[inline]
    fn has_required_size(buf: &[u8]) -> Result<usize, ViewConversionError> {
        let packet_len = ScionRawPacketView::has_required_size(buf)?;
        let view = unsafe { ScionRawPacketView::from_slice_unchecked(buf) };
        // Note: we only check that the buffer is large enough for the SCMP message.
        // The next_header field could be something else.
        _ = ScmpPayloadView::has_required_size(view.payload())?;
        Ok(packet_len)
    }

    #[inline]
    unsafe fn from_slice_unchecked(buf: &[u8]) -> &Self {
        // SAFETY: see View trait documentation
        unsafe { transmute(buf) }
    }

    #[inline]
    unsafe fn from_mut_slice_unchecked(buf: &mut [u8]) -> &mut Self {
        // SAFETY: see View trait documentation
        unsafe { transmute(buf) }
    }

    #[inline]
    unsafe fn from_boxed_unchecked(buf: Box<[u8]>) -> Box<Self> {
        // SAFETY: see View trait documentation
        unsafe { transmute(buf) }
    }

    #[inline]
    unsafe fn as_bytes_mut(&mut self) -> &mut [u8] {
        &mut self.1
    }

    #[inline]
    fn as_bytes_boxed(self: Box<Self>) -> Box<[u8]> {
        // SAFETY: repr(transparent) over [u8], identical fat pointer layout
        unsafe { transmute(self) }
    }

    #[inline]
    fn as_bytes(&self) -> &[u8] {
        &self.1
    }
}
impl<'a> ScionScmpPacketView {
    /// Converts a raw SCION packet into a SCMP packet view. This only checks that the payload is
    /// large enough for a SCMP header but does not check the packets NextHeader field.
    pub fn try_from_raw(raw: &'a ScionRawPacketView) -> Result<&'a Self, ViewConversionError> {
        // There won't be any trailing bytes, so we can just use from_slice.
        let (view, _) = ScionScmpPacketView::from_slice(raw.as_bytes())?;
        Ok(view)
    }

    /// Converts a raw SCION packet into a SCMP packet view. This only checks that the payload is
    /// large enough for a SCMP header but does not check the packets NextHeader field.
    pub fn try_from_raw_mut(
        raw: &'a mut ScionRawPacketView,
    ) -> Result<&'a mut Self, ViewConversionError> {
        // We disregard any trailing bytes.
        let (view, _) = {
            // SAFETY: ScionScmpPacketView does not offer safe functions to change the size of the
            // buffer or mutable access to fields that would cause out of bounds access.
            unsafe { ScionScmpPacketView::from_mut_slice(raw.as_bytes_mut())? }
        };
        Ok(view)
    }

    /// Converts a raw SCION packet into a SCMP packet view. This only checks that the payload
    /// is large enough for a SCMP header but does not check the packets NextHeader field.
    pub fn try_from_raw_owned(
        raw: Box<ScionRawPacketView>,
    ) -> Result<Box<Self>, ViewConversionError> {
        // We disregard any trailing bytes.
        ScionScmpPacketView::from_boxed(raw.as_bytes_boxed())
    }

    /// Converts a SCMP packet view into a raw SCION packet view.
    pub fn into_raw(&self) -> &ScionRawPacketView {
        // Safety: The buffer is large enough for a SCION raw packet.
        unsafe { ScionRawPacketView::from_slice_unchecked(self.as_bytes()) }
    }

    /// Converts a SCMP packet view into a raw SCION packet view.
    ///
    /// # Safety
    /// The caller must ensure that the buffer is not mutated in a way that would invalidate the
    /// view. e.g. by changing the fields that have an effect on `has_required_size`.
    pub unsafe fn into_raw_mut(&mut self) -> &mut ScionRawPacketView {
        unsafe { ScionRawPacketView::from_mut_slice_unchecked(self.as_bytes_mut()) }
    }

    /// Converts a SCMP packet view into a raw SCION packet view.
    pub fn into_raw_owned(self: Box<Self>) -> Box<ScionRawPacketView> {
        unsafe { ScionRawPacketView::from_boxed_unchecked(self.as_bytes_boxed()) }
    }

    /// Returns a SCMP payload view over packets payload.
    /// This returned view only includes the part of the payload slice that is actually taken up by
    /// the SCMP message.
    pub fn scmp(&self) -> &ScmpPayloadView {
        // The buffer size was already checked when creating the ScionScmpPacketView.
        let (view, _) = ScmpPayloadView::from_slice(self.payload())
            .expect("scmp payload is not large enough for a SCMP header");
        view
    }
}
impl<'a> TryFrom<&'a ScionRawPacketView> for &'a ScionScmpPacketView {
    type Error = ViewConversionError;

    fn try_from(value: &'a ScionRawPacketView) -> Result<Self, Self::Error> {
        ScionScmpPacketView::try_from_raw(value)
    }
}
impl<'a> TryFrom<&'a mut ScionRawPacketView> for &'a mut ScionScmpPacketView {
    type Error = ViewConversionError;

    fn try_from(value: &'a mut ScionRawPacketView) -> Result<Self, Self::Error> {
        ScionScmpPacketView::try_from_raw_mut(value)
    }
}
impl TryFrom<Box<ScionRawPacketView>> for Box<ScionScmpPacketView> {
    type Error = ViewConversionError;

    fn try_from(value: Box<ScionRawPacketView>) -> Result<Self, Self::Error> {
        ScionScmpPacketView::try_from_raw_owned(value)
    }
}
impl<'a> From<&'a ScionScmpPacketView> for &'a ScionRawPacketView {
    fn from(value: &'a ScionScmpPacketView) -> Self {
        value.into_raw()
    }
}
impl From<Box<ScionScmpPacketView>> for Box<ScionRawPacketView> {
    fn from(value: Box<ScionScmpPacketView>) -> Self {
        value.into_raw_owned()
    }
}
