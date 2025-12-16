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
//! Representation of a SCION Topology

use std::{
    collections::{BTreeMap, HashMap, btree_map::Entry},
    fmt::{Display, Formatter},
    str::FromStr,
};

use anyhow::{Context, bail};
use scion_proto::address::{Isd, IsdAsn};

pub mod dto;
pub mod visitor;

/// General representation of a SCION Topology.
#[derive(Eq, PartialEq, Debug, Clone, Default)]
pub struct ScionTopology {
    pub(crate) as_map: BTreeMap<IsdAsn, ScionAs>,
    pub(crate) link_map: BTreeMap<ScionLinkId, ScionLink>,
}

impl ScionTopology {
    /// Creates a new, empty SCION topology.
    pub fn new() -> Self {
        Self {
            as_map: Default::default(),
            link_map: Default::default(),
        }
    }

    /// Add a new AS to the topology.
    ///
    /// Validates that the AS does not already exist.
    pub fn add_as(&mut self, scion_as: ScionAs) -> anyhow::Result<&mut Self> {
        match self.as_map.entry(scion_as.isd_as) {
            Entry::Occupied(occupied_entry) => {
                bail!("AS '{}' already exists", occupied_entry.key())
            }
            Entry::Vacant(vacant_entry) => vacant_entry.insert(scion_as),
        };

        Ok(self)
    }

    /// Add a new link to the topology.
    ///
    /// Validates the link according to the following link rules:
    /// 1. A link is bidirectional. (e.g. AS1#0 is Parent of  AS2#0 implies AS2#0 is Child of AS1#0)
    /// 2. Between two ASes, multiple links are allowed if they are all of the same type, with Peer
    ///    links permitted as exceptions.
    /// 3. One Scion interface can only have one link.
    /// 4. A Peer link is allowed between ANY two ASes
    /// 5. Inter ISD links are only allowed: 5.1 Between Core ASes using a Core link type 5.2
    ///    Between Any ASes using a Peer link Type
    /// 6. Interface ID 0 is invalid and may mean unspecified
    pub fn add_link(&mut self, new_link: ScionLink) -> anyhow::Result<&mut Self> {
        // Ensure ASes exist
        let lower_as = self.as_map.get(&new_link.id.lower.isd_as);
        let higher_as = self.as_map.get(&new_link.id.higher.isd_as);

        let lower_as = lower_as
            .ok_or_else(|| anyhow::anyhow!("A AS {} does not exist", new_link.id.lower.isd_as))?;
        let higher_as = higher_as
            .ok_or_else(|| anyhow::anyhow!("A AS {} does not exist", new_link.id.higher.isd_as))?;

        // Validate link rules
        {
            if new_link.id.lower.if_id == 0 || new_link.id.higher.if_id == 0 {
                bail!("Interface ID 0 is invalid");
            }

            // Validate Link Type usage
            let same_isd_link = lower_as.isd_as.isd() == higher_as.isd_as.isd();
            match same_isd_link {
                true => {
                    // | From AS  | To AS     | Allowed Link Type     |
                    // | -------- | --------- | --------------------- |
                    // | Core     | Core      | `Core`, `Peer`        |
                    // | Core     | Non-Core  | `Parent`, `Peer`      |
                    // | Non-Core | Core      | `Child`, `Peer`       |
                    // | Non-Core | Non-Core  | all Except `Core`     |
                    match (lower_as.core, higher_as.core, new_link.link_type) {
                        //(FromAS, ToAS, LinkType)
                        (true, true, ScionLinkType::Core | ScionLinkType::Peer) => {}
                        (true, false, ScionLinkType::Parent | ScionLinkType::Peer) => {}
                        (false, true, ScionLinkType::Child | ScionLinkType::Peer) => {}
                        (
                            false,
                            false,
                            ScionLinkType::Child | ScionLinkType::Parent | ScionLinkType::Peer,
                        ) => {}
                        (from_is_core, to_is_core, link) => {
                            let left = if from_is_core { "Core AS" } else { "AS" };
                            let right = if to_is_core { "Core AS" } else { "AS" };

                            bail!(
                                "{left} '{}' and {right} '{}' can not be linked with '{link}'",
                                lower_as.isd_as,
                                higher_as.isd_as,
                            );
                        }
                    }
                }
                false => {
                    // | From AS  | To AS     | Allowed Link Type     |
                    // | -------- | --------- | --------------------- |
                    // | Core     | Core      | `Core`, `Peer`        |
                    // | Core     | Non-Core  | `Peer`                |
                    // | Non-Core | Core      | `Peer`                |
                    // | Non-Core | Non-Core  | `Peer`                |
                    match (lower_as.core, higher_as.core, new_link.link_type) {
                        //(FromAS, ToAS, LinkType)
                        (true, true, ScionLinkType::Core | ScionLinkType::Peer) => {}
                        (_, _, ScionLinkType::Peer) => {}
                        (from_is_core, to_is_core, link) => {
                            let left = if from_is_core { "Core AS" } else { "AS" };
                            let right = if to_is_core { "Core AS" } else { "AS" };

                            bail!(
                                "{left} '{}' and {right} '{}' can not be linked across ISDs with '{link}'",
                                lower_as.isd_as,
                                higher_as.isd_as,
                            );
                        }
                    }
                }
            }

            // Rule: One Scion interface can only have one link.
            {
                let lower_as_has_conflict = self
                    .scion_link(&new_link.id.lower.isd_as, new_link.id.lower.if_id)
                    .is_some();

                if lower_as_has_conflict {
                    bail!(
                        "Interface {} of AS '{}' already was assigned to another link",
                        new_link.id.lower.if_id,
                        new_link.id.lower.isd_as
                    );
                };

                let higher_as_has_conflict = self
                    .scion_link(&new_link.id.higher.isd_as, new_link.id.higher.if_id)
                    .is_some();

                if higher_as_has_conflict {
                    bail!(
                        "Interface {} of AS '{}' already was assigned to another link",
                        new_link.id.higher.if_id,
                        new_link.id.higher.isd_as
                    );
                };
            }

            // Rule: Between two ASes, multiple links are allowed if they are all of the same type,
            // with Peer links permitted as exceptions.
            if new_link.link_type != ScionLinkType::Peer {
                for existing_link in self.link_map.values() {
                    // If it's the same link
                    if existing_link.id.higher.isd_as == new_link.id.higher.isd_as
                        && existing_link.id.lower.isd_as == new_link.id.lower.isd_as
                        // But the link type is incompatible
                        && existing_link.link_type != ScionLinkType::Peer
                        && existing_link.link_type != new_link.link_type
                    {
                        // If it is the same link
                        bail!(
                            "Another between '{}' and '{}' already exists and using a different type: '{}'",
                            lower_as.isd_as,
                            higher_as.isd_as,
                            existing_link.link_type
                        );
                    }
                }
            }
        }

        // Add Link to the topology
        match self.link_map.entry(new_link.id) {
            Entry::Occupied(occupied_entry) => {
                bail!("Link {} already exists", occupied_entry.key())
            }
            Entry::Vacant(vacant_entry) => vacant_entry.insert(new_link),
        };

        Ok(self)
    }
}
// Accessor functions
impl ScionTopology {
    /// Returns an iterator over all scion links of the given AS.
    pub fn iter_scion_links_by_as(&self, isd_as: &IsdAsn) -> impl Iterator<Item = &ScionLink> {
        self.link_map
            .values()
            .filter(|link| link.id.lower.isd_as == *isd_as || link.id.higher.isd_as == *isd_as)
    }

    /// Returns the ScionLink for the given AS and interface ID. If none exists, returns None.
    pub fn scion_link(&self, isd_as: &IsdAsn, interface_id: u16) -> Option<&ScionLink> {
        self.iter_scion_links_by_as(isd_as).find(|link| {
            link.id.lower.if_id == interface_id && link.id.lower.isd_as == *isd_as
                || link.id.higher.if_id == interface_id && link.id.higher.isd_as == *isd_as
        })
    }

    /// Returns a mutable iterator over all scion links of the given AS.
    pub fn mut_iter_scion_links_by_as(
        &mut self,
        isd_as: &IsdAsn,
    ) -> impl Iterator<Item = &mut ScionLink> {
        self.link_map
            .values_mut()
            .filter(|link| link.id.lower.isd_as == *isd_as || link.id.higher.isd_as == *isd_as)
    }

    /// Returns a mutable reference to the ScionLink for the given AS and interface ID. If none
    /// exists, returns None.
    pub fn mut_scion_link(&mut self, isd_as: &IsdAsn, interface_id: u16) -> Option<&mut ScionLink> {
        self.mut_iter_scion_links_by_as(isd_as).find(|link| {
            link.id.lower.if_id == interface_id && link.id.lower.isd_as == *isd_as
                || link.id.higher.if_id == interface_id && link.id.higher.isd_as == *isd_as
        })
    }
}
// Visualization
impl ScionTopology {
    /// Generate a mermaid graph representation of the topology.
    pub fn format_mermaid(&self) -> String {
        let mut isd_maps: HashMap<Isd, Vec<IsdAsn>> = HashMap::new();
        let mut isd_core_maps: HashMap<Isd, Vec<IsdAsn>> = HashMap::new();

        // Group ASes by ISD
        for scion_as in self.as_map.values() {
            let isd = scion_as.isd_as.isd();

            isd_maps.entry(isd).or_default().push(scion_as.isd_as);

            if scion_as.core {
                isd_core_maps.entry(isd).or_default().push(scion_as.isd_as);
            };
        }

        let mut result = String::new();
        result.push_str("graph TD\n");

        // Add ISD subgraphs
        for (isd, as_numbers) in isd_maps.iter() {
            result.push_str(&format!("subgraph ISD{isd} \n"));
            result.push_str(" direction BT\n");
            // Add Core ASes as additional subgraph
            if let Some(core_asns) = isd_core_maps.get(isd) {
                result.push_str(&format!(" subgraph CORE{isd} \n"));
                result.push_str("  direction LR\n");
                for core_asn in core_asns {
                    result.push_str(&format!("  {core_asn}{{{{\"{core_asn}\"}}}}\n"));
                }
                result.push_str(" end\n");
            }

            for asn in as_numbers {
                result.push_str(&format!(" {asn}\n"));
            }

            result.push_str("end\n");
        }

        // Add links
        for link in self.link_map.values() {
            let (uplink, downlink) = link.get_up_and_downlink();

            let connector = match link.link_type {
                ScionLinkType::Peer => format!("-.->|{} Peer {}|", uplink.if_id, downlink.if_id),
                ScionLinkType::Core => format!("==>|{} Core {}|", uplink.if_id, downlink.if_id),
                _ => format!("-->|{} Up {}|", uplink.if_id, downlink.if_id),
            };

            result.push_str(&format!(
                "{} {} {}\n",
                uplink.isd_as, connector, downlink.isd_as
            ));
        }

        result
    }
}

/// Representation of a SCION Autonomous System (AS).
#[derive(Hash, Copy, Eq, PartialEq, Debug, Clone)]
pub struct ScionAs {
    /// The ISD-AS number of the SCION AS.
    pub isd_as: IsdAsn,
    /// Whether the AS is a core AS.
    pub core: bool,
    /// Forwarding key for the AS - if not defined, falls back to all 0
    pub forwarding_key: [u8; 16],
}

impl ScionAs {
    /// Creates a new core SCION AS.
    pub fn new_core(isd_as: IsdAsn) -> Self {
        Self {
            isd_as,
            core: true,
            forwarding_key: Self::default_forwarding_key(isd_as),
        }
    }

    /// Creates a new non-core SCION AS.
    pub fn new(isd_as: IsdAsn) -> Self {
        Self {
            isd_as,
            core: false,
            forwarding_key: Self::default_forwarding_key(isd_as),
        }
    }

    /// Sets a custom forwarding key for the AS.
    pub fn with_forwarding_key(mut self, forwarding_key: [u8; 16]) -> Self {
        self.forwarding_key = forwarding_key;
        self
    }

    /// Use the ISD-AS to create the forwarding key.
    fn default_forwarding_key(isd_as: IsdAsn) -> [u8; 16] {
        let mut forwarding_key = [0; 16];
        forwarding_key[..8].copy_from_slice(&isd_as.0.to_be_bytes());
        forwarding_key
    }
}

impl From<IsdAsn> for ScionAs {
    fn from(isd_as: IsdAsn) -> Self {
        Self::new(isd_as)
    }
}

/// Globally unique identifier for a SCION interface.
#[derive(Hash, Copy, Eq, PartialEq, Debug, Clone, PartialOrd, Ord)]
pub struct ScionGlobalInterfaceId {
    pub(crate) isd_as: IsdAsn,
    /// Interface ID within the AS.
    pub(crate) if_id: u16,
}

impl Display for ScionGlobalInterfaceId {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}#{}", self.isd_as, self.if_id)
    }
}

impl FromStr for ScionGlobalInterfaceId {
    type Err = anyhow::Error;

    /// Parses a string representation of a SCION interface ID.
    /// Format: "AS#IF"
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let parts: Vec<&str> = s.split('#').collect();
        if parts.len() != 2 {
            bail!(
                "invalid AS interface format: '{}' expected ISD-AS#IF (1-1#1)",
                s
            );
        }

        let isd_as = IsdAsn::from_str(parts[0])?;

        let if_id = parts[1]
            .parse::<u16>()
            .context("could not convert interface id to number")?;

        Ok(Self { isd_as, if_id })
    }
}

/// Globally unique identifier for a SCION link.
#[derive(Hash, Copy, Eq, PartialEq, Debug, Clone, PartialOrd, Ord)]
#[non_exhaustive]
pub struct ScionLinkId {
    pub(crate) lower: ScionGlobalInterfaceId,
    pub(crate) higher: ScionGlobalInterfaceId,
}

impl ScionLinkId {
    /// Creates a new SCION link ID, ensuring that the lower AS is always first.
    pub fn new(
        from_as: IsdAsn,
        from_interface_id: u16,
        to_as: IsdAsn,
        to_interface_id: u16,
    ) -> anyhow::Result<Self> {
        match from_as.cmp(&to_as) {
            std::cmp::Ordering::Less => {
                Ok(Self {
                    lower: ScionGlobalInterfaceId {
                        isd_as: from_as,
                        if_id: from_interface_id,
                    },
                    higher: ScionGlobalInterfaceId {
                        isd_as: to_as,
                        if_id: to_interface_id,
                    },
                })
            }
            std::cmp::Ordering::Greater => {
                Ok(Self {
                    higher: ScionGlobalInterfaceId {
                        isd_as: from_as,
                        if_id: from_interface_id,
                    },
                    lower: ScionGlobalInterfaceId {
                        isd_as: to_as,
                        if_id: to_interface_id,
                    },
                })
            }
            std::cmp::Ordering::Equal => bail!("Cannot create a link between the same AS"),
        }
    }
}

impl Display for ScionLinkId {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "{} <-> {}", self.lower, self.higher)
    }
}

/// Represents a link between two ASes in the SCION topology.
#[derive(Hash, Eq, PartialEq, Debug, Clone)]
pub struct ScionLink {
    pub(crate) id: ScionLinkId,
    /// Link Type from perspective of the lower AS \
    /// e.g. "Lower AS is {link_type} of Higher AS"
    pub(crate) link_type: ScionLinkType,

    pub(crate) is_up: bool,
}

impl Display for ScionLink {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        match self.link_type {
            ScionLinkType::Peer => write!(f, "{} peer {}", self.id.lower, self.id.higher),
            ScionLinkType::Parent => write!(f, "{} parent_of {}", self.id.lower, self.id.higher),
            ScionLinkType::Child => write!(f, "{} child_of {}", self.id.lower, self.id.higher),
            ScionLinkType::Core => write!(f, "{} core {}", self.id.lower, self.id.higher),
        }
    }
}

impl FromStr for ScionLink {
    type Err = anyhow::Error;

    /// Parses a string representation of a link into a `ScionLink`. \
    /// Format: "AS1#IF1 LinkType AS2#IF2" \
    /// 1 parent_of 2
    fn from_str(string: &str) -> Result<Self, Self::Err> {
        let parts: Vec<&str> = string.split_whitespace().collect();
        if parts.len() != 3 {
            bail!(
                "Invalid link format. Expected 'AS1#IF1 LinkType AS2#IF2' - found '{:?}'",
                parts
            );
        }

        let from_part = parts[0];
        let link_type_str = parts[1];
        let to_part = parts[2];

        let ScionGlobalInterfaceId {
            isd_as: from_as,
            if_id: from_interface_id,
        } = from_part.parse()?;

        let ScionGlobalInterfaceId {
            isd_as: to_as,
            if_id: to_interface_id,
        } = to_part.parse()?;

        let link_type = match link_type_str.to_lowercase().as_str() {
            "peer" => ScionLinkType::Peer,
            "down_to" => ScionLinkType::Parent,
            "parent_of" => ScionLinkType::Parent,
            "up_to" => ScionLinkType::Child,
            "child_of" => ScionLinkType::Child,
            "core" => ScionLinkType::Core,
            _ => bail!("Unknown link type: {}", link_type_str),
        };

        Self::new(
            from_as,
            from_interface_id,
            link_type,
            to_as,
            to_interface_id,
        )
    }
}

impl ScionLink {
    /// Creates a new `ScionLink` with the given parameters.
    ///
    /// `link_type` is from perspective of `from_as`. e.g\
    /// e.g. "from_as is {link_type} of to_as"
    pub fn new(
        from_as: IsdAsn,
        from_interface_id: u16,
        link_type: ScionLinkType,
        to_as: IsdAsn,
        to_interface_id: u16,
    ) -> anyhow::Result<Self> {
        if from_interface_id == 0 || to_interface_id == 0 {
            bail!("Interface ID 0 is invalid for a SCION link");
        }

        let link_id = ScionLinkId::new(from_as, from_interface_id, to_as, to_interface_id)?;

        // Normalize the link type based on the AS order - if from as is the lower as, link type
        // stays the same.
        let normalized_type = match from_as == link_id.lower.isd_as {
            true => link_type,
            false => link_type.into_swapped_direction(),
        };

        Ok(Self {
            id: link_id,
            link_type: normalized_type,
            is_up: true,
        })
    }

    /// Returns the link type from the perspective of the given AS.
    ///
    /// If the ISD-AS Number does not match either the lower or higher AS of the link, returns None.
    ///
    /// E.g. "The given AS is {link_type} of the other AS"
    pub fn get_link_type(&self, asn: &IsdAsn) -> Option<ScionLinkType> {
        if self.id.lower.isd_as == *asn {
            return Some(self.link_type);
        } else if self.id.higher.isd_as == *asn {
            return Some(self.link_type.into_swapped_direction());
        }

        None
    }

    /// Returns the peer for the given AS.
    ///
    /// If the ISD-AS Number does not match either AS of the link, returns None.
    pub fn get_peer(&self, isd_as: &IsdAsn) -> Option<ScionGlobalInterfaceId> {
        self.get_directed_from(isd_as).map(|link| link.to)
    }

    /// Returns the ScionGlobalInterfaceId for the given AS
    ///
    /// If the ISD-AS Number does not match either AS of the link, returns None.
    pub fn get_own(&self, isd_as: &IsdAsn) -> Option<ScionGlobalInterfaceId> {
        self.get_directed_from(isd_as).map(|link| link.from)
    }

    /// Returns the link in directed format from the given AS
    ///
    /// If the ISD-AS Number does not match either AS of the link, returns None.
    pub fn get_directed_from(&self, from_as: &IsdAsn) -> Option<DirectedScionLink> {
        if self.id.lower.isd_as == *from_as {
            Some(DirectedScionLink {
                from: self.id.lower,
                to: self.id.higher,
                link_type: self.link_type,
            })
        } else if self.id.higher.isd_as == *from_as {
            Some(DirectedScionLink {
                from: self.id.higher,
                to: self.id.lower,
                link_type: self.link_type.into_swapped_direction(),
            })
        } else {
            None
        }
    }

    /// Returns the link in directed format to the given AS
    ///
    /// If the ISD-AS Number does not match either AS of the link, returns None.
    pub fn get_directed_to(&self, to_as: &IsdAsn) -> Option<DirectedScionLink> {
        if self.id.higher.isd_as == *to_as {
            Some(DirectedScionLink {
                from: self.id.lower,
                to: self.id.higher,
                link_type: self.link_type,
            })
        } else if self.id.lower.isd_as == *to_as {
            Some(DirectedScionLink {
                from: self.id.higher,
                to: self.id.lower,
                link_type: self.link_type.into_swapped_direction(),
            })
        } else {
            None
        }
    }

    /// Returns the up and downlink interface AS from the Link \
    /// (Uplink, Downlink)
    ///
    /// If Connection is Peer or Core, just returns \
    /// (Lower, Higher)
    pub fn get_up_and_downlink(&self) -> (ScionGlobalInterfaceId, ScionGlobalInterfaceId) {
        match self.link_type {
            ScionLinkType::Parent => (self.id.higher, self.id.lower),
            ScionLinkType::Child => (self.id.lower, self.id.higher),
            _ => (self.id.lower, self.id.higher),
        }
    }

    /// Set whether the link is up or down.
    pub fn set_is_up(&mut self, is_up: bool) {
        self.is_up = is_up;
    }
}

/// Directed Variant of a [ScionLink]
#[derive(Hash, Eq, PartialEq, Debug, Clone)]
pub struct DirectedScionLink {
    pub(crate) from: ScionGlobalInterfaceId,
    /// Link Type - from is `{link_type}` of to
    pub(crate) link_type: ScionLinkType,
    pub(crate) to: ScionGlobalInterfaceId,
}

/// Link type of a SCION link
#[derive(Hash, Eq, PartialEq, Debug, Clone, Copy)]
pub enum ScionLinkType {
    /// ASes are Peers without any parent-child relationship.
    Peer,
    /// AS is the Parent (Uplink) of the Other
    Parent,
    /// AS is the Child (Downlink) of the Other
    Child,
    /// The Link is between Core ASes.
    Core,
}

impl Display for ScionLinkType {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            ScionLinkType::Peer => write!(f, "Peer"),
            ScionLinkType::Parent => write!(f, "Parent"),
            ScionLinkType::Child => write!(f, "Child"),
            ScionLinkType::Core => write!(f, "Core"),
        }
    }
}

impl ScionLinkType {
    /// Returns the opposite direction of the link type.
    pub fn into_swapped_direction(&self) -> Self {
        match self {
            ScionLinkType::Peer => ScionLinkType::Peer,
            ScionLinkType::Parent => ScionLinkType::Child,
            ScionLinkType::Child => ScionLinkType::Parent,
            ScionLinkType::Core => ScionLinkType::Core,
        }
    }
}

/// Helper struct to quickly look up links in a topology.
pub struct FastTopologyLookup<'topo> {
    pub(crate) topology: &'topo ScionTopology,
    pub(crate) as_to_link_map: HashMap<IsdAsn, Vec<&'topo ScionLink>>,

    // Contains all peer links for the given AS
    #[allow(unused)]
    pub(crate) as_to_peer_link_map: HashMap<IsdAsn, Vec<&'topo ScionLink>>,
}

impl<'topo> FastTopologyLookup<'topo> {
    /// Creates a new FastTopologyLookup from the given topology.
    pub fn new(topology: &'topo ScionTopology) -> Self {
        let mut as_to_link_map: HashMap<IsdAsn, Vec<&'topo ScionLink>> = HashMap::new();
        let mut as_to_peer_link_map: HashMap<IsdAsn, Vec<&'topo ScionLink>> = HashMap::new();

        for (link_id, link) in &topology.link_map {
            let left_as = link_id.lower.isd_as;
            as_to_link_map.entry(left_as).or_default().push(link);

            let right_as = link_id.higher.isd_as;
            as_to_link_map.entry(right_as).or_default().push(link);

            if link.link_type == ScionLinkType::Peer {
                as_to_peer_link_map.entry(left_as).or_default().push(link);
            }
        }
        Self {
            topology,
            as_to_link_map,
            as_to_peer_link_map,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    mod scion_link_tests {
        use super::*;

        #[test]
        fn should_parse_and_stringify() -> anyhow::Result<()> {
            let link = ScionLink::from_str("1-1#1 core 1-2#12")?;
            assert_eq!(link.to_string(), "1-1#1 core 1-2#12");

            let link = ScionLink::from_str("1-1#1 parent_of 1-2#12")?;
            assert_eq!(link.to_string(), "1-1#1 parent_of 1-2#12");
            Ok(())
        }

        #[test]
        fn should_hold_correct_data_when_parsed() -> anyhow::Result<()> {
            let link = ScionLink::from_str("1-01#1 core 1-02#12")?;
            assert_eq!(link.link_type, ScionLinkType::Core);
            assert_eq!(link.id.lower.isd_as, IsdAsn::from_str("1-01")?);
            assert_eq!(link.id.lower.if_id, 1);
            assert_eq!(link.id.higher.isd_as, IsdAsn::from_str("1-02")?);
            assert_eq!(link.id.higher.if_id, 12);
            Ok(())
        }

        #[test]
        fn should_correctly_normalize_link_order_and_direction() -> anyhow::Result<()> {
            // Should not touch the order or type
            let isd_as_lower = IsdAsn::from_str("1-01")?;
            let isd_as_higher = IsdAsn::from_str("1-02")?;

            let link = ScionLink::from_str("1-01#1 parent_of 1-02#12")?;
            assert_eq!(link.link_type, ScionLinkType::Parent);
            assert_eq!(link.id.lower.isd_as, isd_as_lower);
            assert_eq!(link.id.lower.if_id, 1);
            assert_eq!(link.id.higher.isd_as, isd_as_higher);
            assert_eq!(link.id.higher.if_id, 12);

            // Should swap the order and type
            let swapped_link = ScionLink::from_str("1-02#12 child_of 1-01#1")?;
            assert_eq!(swapped_link.link_type, ScionLinkType::Parent);
            assert_eq!(swapped_link.id.lower.isd_as, isd_as_lower);
            assert_eq!(swapped_link.id.lower.if_id, 1);
            assert_eq!(swapped_link.id.higher.isd_as, isd_as_higher);
            assert_eq!(swapped_link.id.higher.if_id, 12);

            Ok(())
        }

        #[test]
        fn should_disallow_interface_id_0() -> anyhow::Result<()> {
            // Should not allow interface ID 0
            assert!(ScionLink::from_str("1-01#0 parent_of 1-02#12").is_err());
            assert!(ScionLink::from_str("1-01#1 parent_of 1-02#0").is_err());
            Ok(())
        }
    }
}
