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
//! ScionTopology Data Transfer Objects

use std::{any::type_name, collections::BTreeMap};

use anyhow::Context;
use scion_proto::address::IsdAsn;
use serde::{Deserialize, Serialize};
use serde_with::{base64::Base64, serde_as};
use utoipa::{
    PartialSchema, ToSchema,
    openapi::{Object, Type, schema::SchemaType},
};

use crate::network::scion::{
    topology::{ScionAs, ScionLink, ScionRouter, ScionTopology},
    trust_store::TrustStore,
};

/// Human readable ScionTopology
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct ScionTopologyDto {
    trust_store: TrustStore,
    as_list: Vec<ScionAsDto>,
    links: Vec<ScionLinkDto>,
    routers: BTreeMap<IsdAsn, Vec<ScionRouter>>,
}

impl TryFrom<ScionTopologyDto> for ScionTopology {
    type Error = anyhow::Error;

    fn try_from(value: ScionTopologyDto) -> Result<Self, Self::Error> {
        let mut topo = ScionTopology::default();

        for as_info in value.as_list {
            // Register the AS
            let scion_as: ScionAs = as_info.into();
            topo.add_as(scion_as.clone())
                .with_context(|| format!("error adding AS {:?} to topology", scion_as))?;
        }

        for link in value.links {
            let scion_link: ScionLink = link.0;
            topo.add_link(scion_link)
                .context("error adding link to topology")?;
        }

        topo.set_trust_store(value.trust_store)
            .context("Topology trust store misconfigured")?;

        for (isd_as, routers) in value.routers {
            for router in routers {
                topo.add_router(isd_as, router)
                    .context("error adding router to topology")?;
            }
        }

        Ok(topo)
    }
}

impl From<ScionTopology> for ScionTopologyDto {
    fn from(topo: ScionTopology) -> Self {
        let mut registered_ases = Vec::new();
        let mut links = Vec::new();

        for (_isd_as, scion_as) in topo.as_map.into_iter() {
            registered_ases.push(scion_as.into());
        }

        for scion_link in topo.link_map.into_values() {
            links.push(ScionLinkDto(scion_link));
        }

        Self {
            as_list: registered_ases,
            links,
            trust_store: topo.trust_store,
            routers: topo.router_map,
        }
    }
}

/// Human readable Pocket SCION AS
#[serde_as]
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum ScionAsDto {
    /// AS that is simulated by PocketSCION. Packets to and from this AS will be handled by the
    /// simulator.
    Simulated {
        /// ISD-AS number of the AS
        isd_asn: IsdAsn,
        /// Whether this AS is a core AS
        is_core_as: bool,
        /// Forwarding key of the AS, encoded as base64
        #[serde_as(as = "Base64")]
        forwarding_key: [u8; 16],
    },
    /// AS that is not simulated by PocketSCION, but is still part of the topology. Packets to and
    /// from this AS will be handled by an external implementation.
    External {
        /// ISD-AS number of the AS
        isd_asn: IsdAsn,
        /// Whether this AS is a core AS
        is_core_as: bool,
    },
}

impl From<ScionAs> for ScionAsDto {
    fn from(scion_as: ScionAs) -> Self {
        match scion_as {
            ScionAs::Simulated {
                isd_as,
                core,
                forwarding_key,
            } => {
                Self::Simulated {
                    isd_asn: isd_as,
                    is_core_as: core,
                    forwarding_key,
                }
            }
            ScionAs::External { isd_as, core } => {
                Self::External {
                    isd_asn: isd_as,
                    is_core_as: core,
                }
            }
        }
    }
}

impl From<ScionAsDto> for ScionAs {
    fn from(dto: ScionAsDto) -> Self {
        match dto {
            ScionAsDto::Simulated {
                isd_asn,
                is_core_as,
                forwarding_key,
            } => {
                ScionAs::Simulated {
                    isd_as: isd_asn,
                    core: is_core_as,
                    forwarding_key,
                }
            }
            ScionAsDto::External {
                isd_asn,
                is_core_as,
            } => {
                ScionAs::External {
                    isd_as: isd_asn,
                    core: is_core_as,
                }
            }
        }
    }
}

/// Human readable Pocket SCION Link
#[derive(Debug, Clone)]
pub struct ScionLinkDto(pub ScionLink);

impl<'de> Deserialize<'de> for ScionLinkDto {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let string = String::deserialize(deserializer)?;
        let inner = string.parse().map_err(serde::de::Error::custom)?;
        Ok(Self(inner))
    }
}

impl Serialize for ScionLinkDto {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(&self.0.to_string())
    }
}

impl ToSchema for ScionLinkDto {
    fn name() -> std::borrow::Cow<'static, str> {
        type_name::<Self>().into()
    }
}

impl PartialSchema for ScionLinkDto {
    fn schema() -> utoipa::openapi::RefOr<utoipa::openapi::schema::Schema> {
        Object::builder()
            .schema_type(SchemaType::Type(Type::String))
            .examples(vec![serde_json::json!("1-ff00:0:110 parent_of ff00:0:111")])
            .into()
    }
}

#[cfg(test)]
mod test {
    use std::str::FromStr;

    use super::*;

    #[test]
    fn should_convert_to_from_domain_losslessly() {
        let mut topo = ScionTopology::default();

        let isd_asn1 = IsdAsn::from_str("1-ff00:0:110").unwrap();
        // Add an AS
        topo.add_as(ScionAs::new_core(isd_asn1).with_forwarding_key([1; 16]))
            .unwrap();

        topo.add_as(
            ScionAs::new_core(IsdAsn::from_str("1-ff00:0:111").unwrap())
                .with_forwarding_key([2; 16]),
        )
        .unwrap();

        topo.add_as(ScionAs::External {
            isd_as: IsdAsn::from_str("2-ff00:0:210").unwrap(),
            core: false,
        })
        .unwrap();

        // Add a link
        let link = ScionLink::from_str("1-ff00:0:110#1 core 1-ff00:0:111#1").unwrap();
        topo.add_link(link).expect("adding link to topology");

        // Convert to state and back
        let state: ScionTopologyDto = topo.clone().into();
        let converted_topo: ScionTopology = state.try_into().unwrap();
        assert_eq!(
            topo.as_map, converted_topo.as_map,
            "AS map did not match after conversion"
        );
        assert_eq!(
            topo.link_map, converted_topo.link_map,
            "Link map did not match after conversion"
        );
        assert_eq!(
            topo.trust_store, converted_topo.trust_store,
            "Trust store did not match after conversion"
        );
        assert_eq!(
            topo, converted_topo,
            "Topologies did not match after conversion"
        )
    }
}
