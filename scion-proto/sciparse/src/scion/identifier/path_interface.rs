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

//! SCION interface identifier

use crate::scion::identifier::isd_asn::IsdAsn;

/// SCION interface with the AS's ISD-ASN and the interface's ID.
#[derive(Debug, Clone, Copy, PartialOrd, Ord, PartialEq, Eq, Hash)]
#[cfg_attr(feature = "proptest", derive(proptest_derive::Arbitrary))]
pub struct PathInterface {
    /// The ISD-ASN of the AS where the interface is located
    pub isd_asn: IsdAsn,
    /// The AS-local interface ID
    pub id: u16,
}

impl PathInterface {
    /// Creates a new [`PathInterface`] with the given [`IsdAsn`] and interface ID.
    pub const fn new(isd_asn: IsdAsn, id: u16) -> Self {
        PathInterface { isd_asn, id }
    }
}
