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

//! SCION packet views
//!
//! See [`View`](crate::core::view) for more information about views in general.

use std::{fmt::Debug, mem::transmute};

use super::classify::{ClassifiedPacketView, ClassifyError};
use crate::{
    address::{addr::ScionAddr, host_addr::WireHostAddrError, socket_addr::ScionSocketAddr},
    core::view::{View, ViewConversionError},
    header::{layout::ScionHeaderLayout, view::ScionHeaderView},
    payload::{ProtocolNumber, scmp::view::ScmpPayloadView, udp::view::UdpDatagramView},
};

// Marker types for different view variants.
/// Marker type for a raw (untyped) SCION packet view.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct Raw;
/// Marker type for a SCION/UDP packet view.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct Udp;
/// Marker type for a SCION/SCMP packet view.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
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
            let header = self.header();
            let header_len = header.header_len() as usize;
            let payload_len = header.payload_len() as usize;

            let tail_len = self.1.len().saturating_sub(header_len);
            let truncated_payload_len = std::cmp::min(payload_len, tail_len);

            self.1
                .get_unchecked(header_len..header_len + truncated_payload_len)
        }
    }

    /// Returns the source SCION address of the packet.
    ///
    /// If a invalid or unknown address type is encountered in the source host address, an error is
    /// returned.
    #[inline]
    pub fn src_scion_addr(&self) -> Result<ScionAddr, WireHostAddrError> {
        let host = self.header().src_host_addr()?.scion_host_addr()?;
        Ok(ScionAddr::new(self.header().src_ia(), host))
    }

    /// Returns the destination SCION address of the packet.
    ///
    /// If a invalid or unknown address type is encountered in the destination host address, an
    /// error is returned.
    #[inline]
    pub fn dst_scion_addr(&self) -> Result<ScionAddr, WireHostAddrError> {
        let host = self.header().dst_host_addr()?.scion_host_addr()?;
        Ok(ScionAddr::new(self.header().dst_ia(), host))
    }
}
/// A view over a raw SCION packet (payload protocol unspecified).
pub type ScionRawPacketView = ScionPacketView<Raw>;
impl View for ScionRawPacketView {
    #[inline]
    fn has_required_size(buf: &[u8]) -> Result<usize, ViewConversionError> {
        // Safety: This validates that the buffer is large enough for the header,
        // The payload may be truncated, which is handled in the accessor
        let layout = ScionHeaderLayout::try_from_slice(buf)?;

        let packet_len = std::cmp::min(layout.header_len + layout.payload_len, buf.len());
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
    unsafe fn as_slice_mut(&mut self) -> &mut [u8] {
        &mut self.1
    }

    #[inline]
    fn as_slice_boxed(self: Box<Self>) -> Box<[u8]> {
        // SAFETY: This is safe because the view no longer exists after this call.
        // This just returns the underlying buffer.
        unsafe { std::mem::transmute(self) }
    }

    #[inline]
    fn as_slice(&self) -> &[u8] {
        &self.1
    }
}
impl Debug for ScionRawPacketView {
    #[inline]
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ScionRawPacketView")
            .field("header", &self.header())
            .field("payload_len", &self.payload().len())
            .finish()
    }
}
impl ScionRawPacketView {
    /// Returns a mutable slice of the payload
    #[inline]
    pub fn payload_mut(&mut self) -> &mut [u8] {
        // Safety: Buffer size is checked on construction of ScionPacketView
        unsafe {
            let header = self.header();
            let header_len = header.header_len() as usize;
            let payload_len = header.payload_len() as usize;

            let tail_len = self.1.len().saturating_sub(header_len);
            let truncated_payload_len = std::cmp::min(payload_len, tail_len);

            self.1
                .get_unchecked_mut(header_len..header_len + truncated_payload_len)
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
    #[inline]
    pub fn try_classify(&self) -> Result<ClassifiedPacketView<'_>, ClassifyError> {
        match self.header().next_header() {
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
    /// Checks that the payload is large enough for a UDP header and that the expected next header
    /// is set.
    #[inline]
    pub fn try_as_udp(&self) -> Result<&ScionUdpPacketView, ViewConversionError> {
        if self.header().next_header() != ProtocolNumber::Udp {
            return Err(ViewConversionError::Other("next header not UDP"));
        }

        ScionUdpPacketView::try_from_raw(self)
    }

    /// Converts this packet view into a mutable UDP packet view.
    ///
    /// Checks that the payload is large enough for a UDP header and that the expected next header
    /// is set.
    #[inline]
    pub fn try_as_udp_mut(&mut self) -> Result<&mut ScionUdpPacketView, ViewConversionError> {
        if self.header().next_header() != ProtocolNumber::Udp {
            return Err(ViewConversionError::Other("next header not UDP"));
        }

        ScionUdpPacketView::try_from_raw_mut(self)
    }

    /// Converts this packet view into a UDP packet view.
    ///
    /// Checks that the payload is large enough for a UDP header and that the expected next header
    /// is set.
    #[inline]
    pub fn try_into_udp(self: Box<Self>) -> Result<Box<ScionUdpPacketView>, ViewConversionError> {
        if self.header().next_header() != ProtocolNumber::Udp {
            return Err(ViewConversionError::Other("next header not UDP"));
        }

        ScionUdpPacketView::try_from_raw_owned(self)
    }

    /// Tries to interpret this packet as a SCION/SCMP packet.
    ///
    /// Checks that the payload is large enough for a SCMP header and that the expected next header
    /// is set.
    #[inline]
    pub fn try_as_scmp(&self) -> Result<&ScionScmpPacketView, ViewConversionError> {
        if self.header().next_header() != ProtocolNumber::Scmp {
            return Err(ViewConversionError::Other("next header not SCMP"));
        }

        ScionScmpPacketView::try_from_raw(self)
    }

    /// Converts this packet view into a mutable SCMP packet view.
    ///
    /// Checks that the payload is large enough for a SCMP header and that the expected next header
    /// is set.
    #[inline]
    pub fn try_as_scmp_mut(&mut self) -> Result<&mut ScionScmpPacketView, ViewConversionError> {
        if self.header().next_header() != ProtocolNumber::Scmp {
            return Err(ViewConversionError::Other("next header not SCMP"));
        }

        ScionScmpPacketView::try_from_raw_mut(self)
    }

    /// Converts this packet view into a SCMP packet view.
    ///
    /// Checks that the payload is large enough for a SCMP header and that the expected next header
    /// is set.
    #[inline]
    pub fn try_into_scmp(self: Box<Self>) -> Result<Box<ScionScmpPacketView>, ViewConversionError> {
        if self.header().next_header() != ProtocolNumber::Scmp {
            return Err(ViewConversionError::Other("next header not SCMP"));
        }

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
    unsafe fn as_slice_mut(&mut self) -> &mut [u8] {
        &mut self.1
    }

    #[inline]
    fn as_slice_boxed(self: Box<Self>) -> Box<[u8]> {
        // SAFETY: repr(transparent) over [u8], identical fat pointer layout
        unsafe { transmute(self) }
    }

    #[inline]
    fn as_slice(&self) -> &[u8] {
        &self.1
    }
}
impl Debug for ScionUdpPacketView {
    #[inline]
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ScionUdpPacketView")
            .field("header", &self.header())
            .field("datagram", &self.udp())
            .finish()
    }
}
impl ScionUdpPacketView {
    /// Converts a raw SCION packet into a UDP packet view.
    ///
    /// Checks that the payload is large enough for a UDP header and that the expected next header
    /// is set.
    #[inline]
    pub fn try_from_raw(raw: &ScionRawPacketView) -> Result<&Self, ViewConversionError> {
        if raw.header().next_header() != ProtocolNumber::Udp {
            return Err(ViewConversionError::Other("next header not UDP"));
        }

        // There won't be any trailing bytes, so we can just use from_slice.
        let (view, _) = ScionUdpPacketView::try_from_slice(raw.as_slice())?;
        Ok(view)
    }

    /// Converts a raw SCION packet into a UDP packet view.
    ///
    /// Checks that the payload is large enough for a UDP header and that the expected next header
    /// is set.
    #[inline]
    pub fn try_from_raw_mut(
        raw: &mut ScionRawPacketView,
    ) -> Result<&mut Self, ViewConversionError> {
        if raw.header().next_header() != ProtocolNumber::Udp {
            return Err(ViewConversionError::Other("next header not UDP"));
        }

        // There won't be any trailing bytes, so we can just use from_mut_slice.
        let (view, _) = {
            // SAFETY: ScionUdpPacketView does not offer safe functions to change the size of the
            // buffer or mutable access to fields that would cause out of bounds access.
            unsafe { ScionUdpPacketView::try_from_mut_slice(raw.as_slice_mut())? }
        };
        Ok(view)
    }

    /// Converts a raw SCION packet into a UDP packet view.
    ///
    /// Checks that the payload is large enough for a UDP header and that the expected next header
    /// is set.
    #[inline]
    pub fn try_from_raw_owned(
        raw: Box<ScionRawPacketView>,
    ) -> Result<Box<Self>, ViewConversionError> {
        if raw.header().next_header() != ProtocolNumber::Udp {
            return Err(ViewConversionError::Other("next header not UDP"));
        }

        ScionUdpPacketView::try_from_boxed(raw.as_slice_boxed())
    }

    /// Converts a UDP packet view into a raw SCION packet view.
    #[inline]
    pub fn as_raw(&self) -> &ScionRawPacketView {
        // Safety: The buffer is large enough for a SCION raw packet.
        unsafe { ScionRawPacketView::from_slice_unchecked(self.as_slice()) }
    }

    /// Converts a UDP packet view into a raw SCION packet view.
    #[inline]
    pub fn as_raw_mut(&mut self) -> &mut ScionRawPacketView {
        // Safety: The buffer is large enough for a SCION raw packet.
        unsafe { ScionRawPacketView::from_mut_slice_unchecked(self.as_slice_mut()) }
    }

    /// Converts a UDP packet view into a raw SCION packet view.
    #[inline]
    pub fn into_raw(self: Box<Self>) -> Box<ScionRawPacketView> {
        unsafe { ScionRawPacketView::from_boxed_unchecked(self.as_slice_boxed()) }
    }

    /// Returns a UDP datagram view over packets payload.
    /// This returned view only includes the part of the payload slice that is actually taken up by
    /// the UDP datagram.
    #[inline]
    pub fn udp(&self) -> &UdpDatagramView {
        // The buffer size was already checked when creating the ScionUdpPacketView.
        let (view, _) = UdpDatagramView::try_from_slice(self.payload())
            .expect("udp payload is not large enough for a UDP header");
        view
    }

    /// Returns the source SCION socket address of the packet.
    ///
    /// If a unknown address type is encountered in the source host address, an error is returned.
    #[inline]
    pub fn src_socket_addr(&self) -> Result<ScionSocketAddr, WireHostAddrError> {
        let src_port = self.udp().src_port();
        let isd_asn = self.header().src_ia();
        let scion_addr = self.header().src_host_addr()?.scion_host_addr()?;

        Ok(ScionSocketAddr::new(isd_asn, scion_addr, src_port))
    }

    /// Returns the destination SCION socket address of the packet.
    ///
    /// If a unknown address type is encountered in the destination host address, an error is
    /// returned.
    #[inline]
    pub fn dst_socket_addr(&self) -> Result<ScionSocketAddr, WireHostAddrError> {
        let dst_port = self.udp().dst_port();
        let isd_asn = self.header().dst_ia();
        let scion_addr = self.header().dst_host_addr()?.scion_host_addr()?;

        Ok(ScionSocketAddr::new(isd_asn, scion_addr, dst_port))
    }
}
impl<'a> TryFrom<&'a ScionRawPacketView> for &'a ScionUdpPacketView {
    type Error = ViewConversionError;

    #[inline]
    fn try_from(value: &'a ScionRawPacketView) -> Result<Self, Self::Error> {
        ScionUdpPacketView::try_from_raw(value)
    }
}
impl<'a> TryFrom<&'a mut ScionRawPacketView> for &'a mut ScionUdpPacketView {
    type Error = ViewConversionError;

    #[inline]
    fn try_from(value: &'a mut ScionRawPacketView) -> Result<Self, Self::Error> {
        ScionUdpPacketView::try_from_raw_mut(value)
    }
}
impl TryFrom<Box<ScionRawPacketView>> for Box<ScionUdpPacketView> {
    type Error = ViewConversionError;

    #[inline]
    fn try_from(value: Box<ScionRawPacketView>) -> Result<Self, Self::Error> {
        ScionUdpPacketView::try_from_raw_owned(value)
    }
}
impl<'a> From<&'a ScionUdpPacketView> for &'a ScionRawPacketView {
    #[inline]
    fn from(value: &'a ScionUdpPacketView) -> Self {
        value.as_raw()
    }
}
impl<'a> From<&'a mut ScionUdpPacketView> for &'a mut ScionRawPacketView {
    #[inline]
    fn from(value: &'a mut ScionUdpPacketView) -> Self {
        value.as_raw_mut()
    }
}
impl From<Box<ScionUdpPacketView>> for Box<ScionRawPacketView> {
    #[inline]
    fn from(value: Box<ScionUdpPacketView>) -> Self {
        value.into_raw()
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
    unsafe fn as_slice_mut(&mut self) -> &mut [u8] {
        &mut self.1
    }

    #[inline]
    fn as_slice_boxed(self: Box<Self>) -> Box<[u8]> {
        // SAFETY: repr(transparent) over [u8], identical fat pointer layout
        unsafe { transmute(self) }
    }

    #[inline]
    fn as_slice(&self) -> &[u8] {
        &self.1
    }
}
impl Debug for ScionScmpPacketView {
    #[inline]
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ScionScmpPacketView")
            .field("header", &self.header())
            .field("message", &self.scmp())
            .finish()
    }
}
impl<'a> ScionScmpPacketView {
    /// Converts a raw SCION packet into a SCMP packet view. This only checks that the payload is
    /// large enough for a SCMP header but does not check the packets NextHeader field.
    #[inline]
    pub fn try_from_raw(raw: &'a ScionRawPacketView) -> Result<&'a Self, ViewConversionError> {
        // There won't be any trailing bytes, so we can just use from_slice.
        let (view, _) = ScionScmpPacketView::try_from_slice(raw.as_slice())?;
        Ok(view)
    }

    /// Converts a raw SCION packet into a SCMP packet view. This only checks that the payload is
    /// large enough for a SCMP header but does not check the packets NextHeader field.
    #[inline]
    pub fn try_from_raw_mut(
        raw: &'a mut ScionRawPacketView,
    ) -> Result<&'a mut Self, ViewConversionError> {
        // We disregard any trailing bytes.
        let (view, _) = {
            // SAFETY: ScionScmpPacketView does not offer safe functions to change the size of the
            // buffer or mutable access to fields that would cause out of bounds access.
            unsafe { ScionScmpPacketView::try_from_mut_slice(raw.as_slice_mut())? }
        };
        Ok(view)
    }

    /// Converts a raw SCION packet into a SCMP packet view. This only checks that the payload
    /// is large enough for a SCMP header but does not check the packets NextHeader field.
    #[inline]
    pub fn try_from_raw_owned(
        raw: Box<ScionRawPacketView>,
    ) -> Result<Box<Self>, ViewConversionError> {
        // We disregard any trailing bytes.
        ScionScmpPacketView::try_from_boxed(raw.as_slice_boxed())
    }

    /// Converts a SCMP packet view into a raw SCION packet view.
    #[inline]
    pub fn as_raw(&self) -> &ScionRawPacketView {
        // Safety: The buffer is large enough for a SCION raw packet.
        unsafe { ScionRawPacketView::from_slice_unchecked(self.as_slice()) }
    }

    /// Converts a SCMP packet view into a raw SCION packet view.
    ///
    /// # Safety
    /// The caller must ensure that the buffer is not mutated in a way that would invalidate the
    /// view. e.g. by changing the fields that have an effect on `has_required_size`.
    #[inline]
    pub unsafe fn as_raw_mut(&mut self) -> &mut ScionRawPacketView {
        unsafe { ScionRawPacketView::from_mut_slice_unchecked(self.as_slice_mut()) }
    }

    /// Converts a SCMP packet view into a raw SCION packet view.
    #[inline]
    pub fn into_raw(self: Box<Self>) -> Box<ScionRawPacketView> {
        unsafe { ScionRawPacketView::from_boxed_unchecked(self.as_slice_boxed()) }
    }

    /// Returns a SCMP payload view over packets payload.
    /// This returned view only includes the part of the payload slice that is actually taken up by
    /// the SCMP message.
    #[inline]
    pub fn scmp(&self) -> &ScmpPayloadView {
        // The buffer size was already checked when creating the ScionScmpPacketView.
        let (view, _) = ScmpPayloadView::try_from_slice(self.payload())
            .expect("scmp payload is not large enough for a SCMP header");
        view
    }
}
impl<'a> TryFrom<&'a ScionRawPacketView> for &'a ScionScmpPacketView {
    type Error = ViewConversionError;

    #[inline]
    fn try_from(value: &'a ScionRawPacketView) -> Result<Self, Self::Error> {
        ScionScmpPacketView::try_from_raw(value)
    }
}
impl<'a> TryFrom<&'a mut ScionRawPacketView> for &'a mut ScionScmpPacketView {
    type Error = ViewConversionError;

    #[inline]
    fn try_from(value: &'a mut ScionRawPacketView) -> Result<Self, Self::Error> {
        ScionScmpPacketView::try_from_raw_mut(value)
    }
}
impl TryFrom<Box<ScionRawPacketView>> for Box<ScionScmpPacketView> {
    type Error = ViewConversionError;

    #[inline]
    fn try_from(value: Box<ScionRawPacketView>) -> Result<Self, Self::Error> {
        ScionScmpPacketView::try_from_raw_owned(value)
    }
}
impl<'a> From<&'a ScionScmpPacketView> for &'a ScionRawPacketView {
    #[inline]
    fn from(value: &'a ScionScmpPacketView) -> Self {
        value.as_raw()
    }
}
impl From<Box<ScionScmpPacketView>> for Box<ScionRawPacketView> {
    #[inline]
    fn from(value: Box<ScionScmpPacketView>) -> Self {
        value.into_raw()
    }
}
