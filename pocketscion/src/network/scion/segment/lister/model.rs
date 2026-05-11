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
//! Segment listing utilities

use anyhow::{Ok, bail};
use sciparse::identifier::{isd::Isd, isd_asn::IsdAsn};

/// Helper enum to represent the target of a segment listing request.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum QueryTarget {
    Core(Scope),
    NonCore(IsdAsn),
}

impl QueryTarget {
    pub(crate) fn new(ias: IsdAsn, is_core: bool) -> anyhow::Result<Self> {
        if ias.isd() == Isd::WILDCARD {
            bail!("ISD cannot be a wildcard");
        };

        let res = match ias.is_wildcard() {
            true => QueryTarget::Core(Scope::Wildcard(ias.isd())),
            false if is_core => QueryTarget::Core(Scope::One(ias)),
            false => QueryTarget::NonCore(ias),
        };

        Ok(res)
    }

    pub(crate) fn isd(&self) -> Isd {
        match self {
            QueryTarget::Core(Scope::One(ias)) => ias.isd(),
            QueryTarget::Core(Scope::Wildcard(isd)) => *isd,
            QueryTarget::NonCore(ias) => ias.isd(),
        }
    }

    pub(crate) fn ias(&self) -> IsdAsn {
        match self {
            QueryTarget::Core(Scope::One(ias)) => *ias,
            QueryTarget::Core(Scope::Wildcard(isd)) => IsdAsn::new(*isd, IsdAsn::WILDCARD.asn()),
            QueryTarget::NonCore(ias) => *ias,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Scope {
    // One specific AS
    One(IsdAsn),
    // Any AS
    Wildcard(Isd),
}

impl Scope {
    pub(crate) fn isd(&self) -> Isd {
        match self {
            Scope::One(ias) => ias.isd(),
            Scope::Wildcard(isd) => *isd,
        }
    }

    pub(crate) fn ias(&self) -> IsdAsn {
        match self {
            Scope::One(ias) => *ias,
            Scope::Wildcard(isd) => IsdAsn::new(*isd, IsdAsn::WILDCARD.asn()),
        }
    }
}
