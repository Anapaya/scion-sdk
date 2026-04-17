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
//! Encoded SCION path fields.

use std::{iter, num::NonZeroU16, slice::ChunksExact, time::Duration};

use bytes::Buf;
use chrono::{DateTime, Utc};

use crate::path::{HopField, InfoField};

/// A SCION path info field.
///
/// Contains information such as the segment direction and timestamp by which hop fields
/// determine their expiration time.
#[repr(transparent)]
#[derive(Debug, PartialEq, Eq)]
pub struct EncodedInfoField {
    inner: [u8],
}

impl EncodedInfoField {
    /// The length of the info field in bytes.
    pub const LENGTH: usize = InfoField::ENCODED_SIZE;

    /// A view of an InfoField in a SCION standard path.
    ///
    /// This is an unsized type, meaning that it must always be used behind a pointer
    /// like `&` or [`Box`].
    pub fn new(data: &[u8]) -> &Self {
        assert_eq!(data.len(), InfoField::ENCODED_SIZE);
        unsafe { &*(data as *const [u8] as *const Self) }
    }

    /// A mutable view of an InfoField in a SCION standard path.
    ///
    /// This allows modifying the construction direction flag of the info field.
    ///
    /// This is an unsized type, meaning that it must always be used behind a pointer
    /// like `&` or [`Box`].
    pub fn new_mut(data: &mut [u8]) -> &mut Self {
        assert_eq!(data.len(), InfoField::ENCODED_SIZE);
        unsafe { &mut *(data as *mut [u8] as *mut Self) }
    }

    /// Returns true if the segment represented by this field contains a peering hop field.
    pub fn is_peering(&self) -> bool {
        (self.inner[0] & InfoField::FLAGS_PEER) != 0
    }

    /// Returns true if the hop fields in this segment are arranged in the direction
    /// they were constructed in during beaconing.
    pub fn is_constructed_dir(&self) -> bool {
        (self.inner[0] & InfoField::FLAGS_CONS_DIR) != 0
    }

    /// Sets the construction direction flag.
    ///
    /// A value of true indicates that the segment's fields are arranged in their constructed
    /// direction during beaconing. A value of false indicates that they have been reversed.
    pub fn set_constructed_dir(&mut self, is_constructed_dir: bool) {
        if is_constructed_dir {
            self.inner[0] |= InfoField::FLAGS_CONS_DIR;
        } else {
            self.inner[0] &= !InfoField::FLAGS_CONS_DIR;
        }
    }

    /// Gets the timestamp set by the initiator of the corresponding beacon.
    ///
    /// This timestamp can be used to determine the expiration time of each hop field
    /// within the segment corresponding to this info field.
    pub fn timestamp(&self) -> DateTime<Utc> {
        let secs = Buf::get_u32(&mut &self.inner[4..]);
        DateTime::<Utc>::from_timestamp(secs.into(), 0).expect("never out of range")
    }
}

impl AsRef<[u8]> for EncodedInfoField {
    fn as_ref(&self) -> &[u8] {
        &self.inner
    }
}

/// A SCION path hop field.
///
/// Contains information to be processed by SCION routers, such as path interfaces and
/// hop expiration time.
#[repr(transparent)]
#[derive(Debug, PartialEq, Eq)]
pub struct EncodedHopField {
    inner: [u8],
}

impl EncodedHopField {
    /// The length of the hop field in bytes.
    pub const LENGTH: usize = HopField::ENCODED_SIZE;

    /// A view of a HopField in a SCION standard path.
    ///
    /// This is an unsized type, meaning that it must always be used behind a pointer
    /// like `&` or [`Box`].
    pub fn new(data: &[u8]) -> &Self {
        assert_eq!(data.len(), HopField::ENCODED_SIZE);

        unsafe { &*(data as *const [u8] as *const Self) }
    }

    /// A mutable view of a HopField in a SCION standard path.
    ///
    /// This allows modifying the router alert flags present in the hop field.
    ///
    /// This is an unsized type, meaning that it must always be used behind a pointer
    /// like `&` or [`Box`].
    pub fn new_mut(data: &mut [u8]) -> &mut Self {
        assert_eq!(data.len(), HopField::ENCODED_SIZE);
        unsafe { &mut *(data as *mut [u8] as *mut Self) }
    }

    /// Returns true if the ConsIngress Router Alert flag is set.
    ///
    /// When set on the hop field, the ConsIngress Router Alert flag indicates to the processing
    /// ingress router (in the construction/beaconing direction) that it should process the L4
    /// payload in the packet.
    pub fn is_cons_ingress_router_alert(&self) -> bool {
        (self.inner[0] & HopField::FLAGS_INGRESS_ROUTER_ALERT) != 0
    }

    /// Sets (true) or unsets (false) the ConsIngress Router Alert flag.
    ///
    /// See [is_cons_ingress_router_alert][`Self::is_cons_ingress_router_alert`] for a description
    /// of the flag.
    pub fn set_cons_ingress_router_alert(&mut self, enable: bool) {
        if enable {
            self.inner[0] |= HopField::FLAGS_INGRESS_ROUTER_ALERT;
        } else {
            self.inner[0] &= !HopField::FLAGS_INGRESS_ROUTER_ALERT;
        }
    }

    /// Returns true if the ConsEgress Router Alert flag is set.
    ///
    /// When set on the hop field, the ConsEgress Router Alert flag indicates to the processing
    /// egress router (in the construction/beaconing direction) that it should process the L4
    /// payload in the packet.
    pub fn is_cons_egress_router_alert(&self) -> bool {
        (self.inner[0] & HopField::FLAGS_EGRESS_ROUTER_ALERT) != 0
    }

    /// Sets (true) or unsets (false) the ConsEgress Router Alert flag.
    ///
    /// See [is_cons_egress_router_alert][`Self::is_cons_egress_router_alert`] for a description
    /// of the flag.
    pub fn set_cons_egress_router_alert(&mut self, enable: bool) {
        if enable {
            self.inner[0] |= HopField::FLAGS_EGRESS_ROUTER_ALERT;
        } else {
            self.inner[0] &= !HopField::FLAGS_EGRESS_ROUTER_ALERT;
        }
    }

    /// Returns the ingress interface in the construction (beaconing) direction.
    ///
    /// Returns None if the hop field indicates that the ingress interface is the local AS.
    pub fn cons_ingress_interface(&self) -> Option<NonZeroU16> {
        NonZeroU16::new(((self.inner[2] as u16) << 8) | self.inner[3] as u16)
    }

    /// Returns the egress interface in the construction (beaconing) direction.
    ///
    /// Returns None if the hop field indicates that the ingress interface is the local AS.
    pub fn cons_egress_interface(&self) -> Option<NonZeroU16> {
        NonZeroU16::new(((self.inner[4] as u16) << 8) | self.inner[5] as u16)
    }

    /// Returns the ingress interface according to the segment direction.
    ///
    /// This corresponds to the ingress interface if the info field indicates that the segment
    /// has not been reversed, and the egress interface otherwise.
    ///
    /// See [cons_ingress_interface][`Self::cons_ingress_interface`] for the ingress interface in
    /// the constructed direction.
    pub fn ingress_interface(&self, info_field: &EncodedInfoField) -> Option<NonZeroU16> {
        if info_field.is_constructed_dir() {
            self.cons_ingress_interface()
        } else {
            self.cons_egress_interface()
        }
    }

    /// Returns the egress interface according to the segment direction.
    ///
    /// This corresponds to the egress interface if the info field indicates that the segment
    /// has not been reversed, and the ingress interface otherwise.
    ///
    /// See [cons_egress_interface][`Self::cons_egress_interface`] for the egress interface in
    /// the constructed direction.
    pub fn egress_interface(&self, info_field: &EncodedInfoField) -> Option<NonZeroU16> {
        if info_field.is_constructed_dir() {
            self.cons_egress_interface()
        } else {
            self.cons_ingress_interface()
        }
    }

    /// Returns the expiration offset of this hop field.
    ///
    /// This value is the duration after the timestamp in the associated InfoField for which the
    /// hop field will be valid.
    ///
    /// The exact expiry time can be calculated with the [expiry_time][`Self::expiry_time`] method.
    pub fn expiry_offset(&self) -> Duration {
        HopField::DURATION_PER_EXP_UNIT * (1 + self.inner[1] as u32)
    }

    /// Returns the expiration time unit of this hop field.
    pub fn expiration_units(&self) -> u8 {
        self.inner[1]
    }

    /// Returns the expiration time of this hop field.
    ///
    /// This computes the hop field's expiry time relative to the the
    /// [timestamp][`EncodedInfoField::timestamp`] in the provided EncodedInfoField.
    pub fn expiry_time(&self, info_field: &EncodedInfoField) -> DateTime<Utc> {
        info_field.timestamp() + self.expiry_offset()
    }
}

impl AsRef<[u8]> for EncodedHopField {
    fn as_ref(&self) -> &[u8] {
        &self.inner
    }
}

macro_rules! field_iterator {
    (
        $(#[$outer:meta])*
        pub struct $name:ident<$life:lifetime>{field_type: $field:ty}
    ) => {
        $(#[$outer])*
        #[derive(Debug, Clone)]
        pub struct $name<$life> {
            inner: ChunksExact<$life, u8>,
        }

        impl<$life> $name<$life> {
            pub(super) fn new(data: &'a [u8]) -> Self {
                assert_eq!(data.len() % <$field>::LENGTH, 0);
                Self {
                    inner: data.chunks_exact(<$field>::LENGTH),
                }
            }
        }

        impl<$life> Iterator for $name<$life> {
            type Item = &$life $field;

            fn next(&mut self) -> Option<Self::Item> {
                self.inner.next().map(<$field>::new)
            }
        }

        impl<$life> DoubleEndedIterator for $name<$life> {
            fn next_back(&mut self) -> Option<Self::Item> {
                self.inner.next_back().map(<$field>::new)
            }
        }

        impl ExactSizeIterator for $name<'_> {
            fn len(&self) -> usize {
                self.inner.len()
            }
        }

        impl iter::FusedIterator for $name<'_> {}
    };
}

field_iterator! {
    /// Iterator over hop fields in a SCION standard path header.
    pub struct HopFields<'a> {field_type: EncodedHopField}
}

field_iterator! {
    /// Iterator over info fields in a SCION standard path header.
    pub struct InfoFields<'a> {field_type: EncodedInfoField}
}

#[cfg(test)]
mod tests {
    use super::*;

    macro_rules! test_case {
        ($name:ident: $func:ident($arg1:expr$(, $arg:expr)*)) => {
            #[test]
            fn $name() {
                $func($arg1 $(, $arg)*)
            }
        };
    }

    macro_rules! test_flag {
        ($name:ident: {
            field: $field:ty,
            flag_mask: $mask:literal,
            getter: $flag_getter:tt
            $(, setter: $flag_setter:tt)?
        }) => {
            mod $name {
                use super::*;

                #[test]
                fn getter() {
                    let mut backing_array = [0u8; <$field>::LENGTH];

                    let field = <$field>::new(&backing_array);
                    assert!(!field.$flag_getter());

                    backing_array[0] = $mask;

                    let field = <$field>::new(&backing_array);
                    assert!(field.$flag_getter());
                }

                $(
                    #[test]
                    fn setter() {
                        let mut backing_array = [0u8; <$field>::LENGTH];
                        backing_array[0] = !$mask;
                        let field = <$field>::new_mut(&mut backing_array);

                        assert!(!field.$flag_getter());
                        field.$flag_setter(true);
                        assert!(field.$flag_getter());

                        let mut backing_array = [$mask; <$field>::LENGTH];
                        backing_array[0] = $mask;
                        let field = <$field>::new_mut(&mut backing_array);

                        assert!(field.$flag_getter());
                        field.$flag_setter(false);
                        assert!(!field.$flag_getter());
                    }

                    #[test]
                    fn idempotent_set() {
                        let mut backing_array = [0u8; <$field>::LENGTH];
                        backing_array[0] = !$mask;
                        let field = <$field>::new_mut(&mut backing_array);

                        assert!(!field.$flag_getter());
                        field.$flag_setter(false);
                        assert!(!field.$flag_getter());

                        let mut backing_array = [$mask; <$field>::LENGTH];
                        backing_array[0] = $mask;
                        let field = <$field>::new_mut(&mut backing_array);

                        assert!(field.$flag_getter());
                        field.$flag_setter(true);
                        assert!(field.$flag_getter());
                    }

                )?
            }
        };
    }

    mod info_field {
        use super::*;

        #[test]
        fn timestamp_min() {
            let info_data = [0b10_u8, 0, 0, 0, 0, 0, 0, 0];
            let info_field = EncodedInfoField::new(&info_data);
            assert_eq!(
                info_field.timestamp(),
                DateTime::from_timestamp(u32::MIN.into(), 0).unwrap()
            );
        }

        #[test]
        fn timestamp_max() {
            let info_data = [0b10_u8, 0, 0, 0, 0xff, 0xff, 0xff, 0xff];
            let info_field = EncodedInfoField::new(&info_data);
            assert_eq!(
                info_field.timestamp(),
                DateTime::from_timestamp(u32::MAX.into(), 0).unwrap()
            );
        }

        test_flag! {
            peering_flag: {
                field: EncodedInfoField,
                flag_mask: 0b0000_0010,
                getter: is_peering
            }
        }

        test_flag! {
            constructed_dir_flag: {
                field: EncodedInfoField,
                flag_mask: 0b0000_0001,
                getter: is_constructed_dir,
                setter: set_constructed_dir
            }
        }
    }

    mod hop_field {
        use super::*;

        test_flag! {
            cons_ingress_router_alert_flag: {
                field: EncodedHopField,
                flag_mask: 0b0000_0010,
                getter: is_cons_ingress_router_alert,
                setter: set_cons_ingress_router_alert
            }
        }

        test_flag! {
            cons_egress_router_alert_flag: {
                field: EncodedHopField,
                flag_mask: 0b0000_0001,
                getter: is_cons_egress_router_alert,
                setter: set_cons_egress_router_alert
            }
        }

        #[test]
        fn cons_interfaces() {
            let hop_data = [0_u8, 0, 0xfe, 0xed, 0xab, 0xcd, 0, 0, 0, 0, 0, 0];
            let hop_field = EncodedHopField::new(&hop_data);

            assert_eq!(hop_field.cons_ingress_interface(), NonZeroU16::new(0xfeed));
            assert_eq!(hop_field.cons_egress_interface(), NonZeroU16::new(0xabcd));
        }

        #[test]
        fn cons_interfaces_none() {
            let hop_data = [0_u8, 0, 0x00, 0x00, 0x00, 0x00, 0, 0, 0, 0, 0, 0];
            let hop_field = EncodedHopField::new(&hop_data);

            assert_eq!(hop_field.cons_ingress_interface(), None);
            assert_eq!(hop_field.cons_egress_interface(), None);
        }

        #[test]
        fn interfaces() {
            let hop_data = [0_u8, 0, 0xfe, 0xed, 0xab, 0xcd, 0, 0, 0, 0, 0, 0];
            let hop_field = EncodedHopField::new(&hop_data);
            let mut info_data = [0_u8; 8];
            let info = EncodedInfoField::new_mut(&mut info_data);

            info.set_constructed_dir(true);

            assert_eq!(hop_field.ingress_interface(info), NonZeroU16::new(0xfeed));
            assert_eq!(hop_field.egress_interface(info), NonZeroU16::new(0xabcd));

            info.set_constructed_dir(false);

            assert_eq!(hop_field.ingress_interface(info), NonZeroU16::new(0xabcd));
            assert_eq!(hop_field.egress_interface(info), NonZeroU16::new(0xfeed));
        }

        fn test_expiry_time(expiry_value: u8, info_timestamp: u32, expected: DateTime<Utc>) {
            let hop_data = [0u8, expiry_value, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0];
            let hop_field = EncodedHopField::new(&hop_data);
            let info_data = [[0u8, 0, 0, 0], info_timestamp.to_be_bytes()].concat();
            let info = EncodedInfoField::new(&info_data);

            assert_eq!(hop_field.expiry_time(info), expected);
        }

        test_case! {
            expiry_min:
                test_expiry_time(0, 0, DateTime::from_timestamp(337, 500_000_000).unwrap())
        }

        test_case! {
            expiry_min_max:
                test_expiry_time(255, 0, DateTime::UNIX_EPOCH + Duration::from_secs(24 * 60 * 60))
        }

        test_case! {
            expiry_arbitrary:
                test_expiry_time(199, 1_703_462_400, DateTime::from_timestamp(1_703_529_900, 0).unwrap())
        }
    }
}
