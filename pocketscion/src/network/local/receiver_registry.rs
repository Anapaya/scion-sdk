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
//! Registry for network simulation receivers.

use std::{
    collections::BTreeMap,
    net::{IpAddr, SocketAddr},
    sync::Arc,
};

use anyhow::bail;
use ipnet::IpNet;
use scion_proto::address::{IsdAsn, ServiceAddr};

use crate::network::local::receivers::Receiver;

/// Receivers available to the network simulation.
///
/// Receivers are bound to:
/// 1. Wildcard ISD-AS (all addresses in the ISD-AS)
/// 2. Specific IP ranges within an ISD-AS
#[derive(Default, Debug, Clone, PartialEq)]
pub struct NetworkReceiverRegistry {
    /// The receivers available to the network simulation.
    ///
    /// Receivers are stored in a BTreeMap keyed by ISD-AS. Each ISD-AS can have an optional
    /// wildcard receiver and any number of receivers bound to specific IP ranges. Address-specific
    /// receivers take precedence over the wildcard receiver.
    receivers: BTreeMap<IsdAsn, LocalNetworkReceivers>,
    /// SVC Address mappings available in the network simulation.
    /// Mapping of ISD-AS -> SVC -> Protocol Name -> SocketAddr
    svc_mapping: BTreeMap<IsdAsn, BTreeMap<ServiceAddr, BTreeMap<String, SocketAddr>>>,
}
impl PartialEq for LocalNetworkReceivers {
    fn eq(&self, other: &Self) -> bool {
        // We only compare the presence of a wildcard receiver and the number of address-range
        // receivers, not the actual receivers.
        self.wildcard.is_some() == other.wildcard.is_some()
            && self.ranged_receivers.len() == other.ranged_receivers.len()
    }
}

impl NetworkReceiverRegistry {
    /// Creates a new, empty [`NetworkReceiverRegistry`].
    pub fn new() -> Self {
        Self::default()
    }

    /// Binds a network receiver to an entire ISD-AS.
    ///
    /// Fails if a wildcard receiver for the ISD-AS already exists. Address-range receivers may
    /// coexist with the wildcard receiver.
    pub fn add_wildcard_receiver(
        &mut self,
        ias: IsdAsn,
        receiver: Arc<dyn Receiver>,
    ) -> anyhow::Result<()> {
        let entry = self.receivers.entry(ias).or_default();
        if entry.wildcard.is_some() {
            bail!("A wildcard receiver for ISD-AS {} already exists", ias);
        }

        entry.wildcard = Some(receiver);

        Ok(())
    }

    /// Binds a receiver to a specific IP range within an ISD-AS.
    ///
    /// Fails if an overlapping Receiver already exists. May coexist with a wildcard receiver.
    pub fn add_receiver(
        &mut self,
        ias: IsdAsn,
        ipnet: IpNet,
        receiver: Arc<dyn Receiver>,
    ) -> anyhow::Result<()> {
        let entry = self.receivers.entry(ias).or_default();

        if let Some((overlap_net, _)) = entry
            .ranged_receivers
            .iter()
            .find(|(net, _)| net.contains(&ipnet))
        {
            bail!(
                "ISD-AS {ias} has a receiver with overlapping IP range. existing: {overlap_net} overlaps with {ipnet}",
            );
        };

        entry.ranged_receivers.push((ipnet, receiver));

        Ok(())
    }

    /// Removes the receiver for the given ISD-AS and IP range, if it exists.
    ///
    /// Otherwise, returns an error.
    pub fn remove_receiver(&mut self, ias: IsdAsn, ipnet: IpNet) -> anyhow::Result<()> {
        let entry = self.receivers.get_mut(&ias).ok_or_else(|| {
            anyhow::anyhow!(
                "No receivers found for ISD-AS {}, cannot remove receiver",
                ias
            )
        })?;

        if let Some(pos) = entry
            .ranged_receivers
            .iter()
            .position(|(net, _)| *net == ipnet)
        {
            entry.ranged_receivers.remove(pos);
            if entry.is_empty() {
                self.receivers.remove(&ias);
            }
            Ok(())
        } else {
            bail!(
                "No receiver found for ISD-AS {} with IP range {}, cannot remove",
                ias,
                ipnet
            );
        }
    }

    /// Removes the wildcard receiver for the given ISD-AS, if it exists.
    ///
    /// Otherwise, returns an error.
    pub fn remove_wildcard_receiver(&mut self, ias: IsdAsn) -> anyhow::Result<()> {
        let entry = self.receivers.get_mut(&ias).ok_or_else(|| {
            anyhow::anyhow!(
                "No receivers found for ISD-AS {}, cannot remove wildcard receiver",
                ias
            )
        })?;

        if entry.wildcard.take().is_none() {
            bail!(
                "Receiver for ISD-AS {} is not a wildcard receiver, cannot remove",
                ias
            );
        }

        if entry.is_empty() {
            self.receivers.remove(&ias);
        }

        Ok(())
    }

    /// Returns the receiver for the given address, if one exists.
    ///
    /// Address-specific receivers take precedence; if none matches, the wildcard receiver (if any)
    /// is returned.
    pub fn by_addr(&self, ia: IsdAsn, dst_ip: IpAddr) -> Option<&Arc<dyn Receiver>> {
        let entry = self.receivers.get(&ia)?;
        entry
            .ranged_receivers
            .iter()
            .find_map(|(ipnet, receiver)| ipnet.contains(&dst_ip).then_some(receiver))
            .or(entry.wildcard.as_ref())
    }

    /// Adds an Service Address mapping for the given ISD-AS, SVC and protocol.
    ///
    /// Service Addresses can be resolved, but not dispatched to, so the mapping is only used for
    /// incoming packets. The mapping is used to determine the socket address to which incoming
    /// packets for a given SVC and protocol should be dispatched.
    pub fn add_svc_mapping(
        &mut self,
        ia: IsdAsn,
        dst_svc: ServiceAddr,
        transport: String,
        socket_addr: SocketAddr,
    ) -> anyhow::Result<()> {
        let transport = self
            .svc_mapping
            .entry(ia)
            .or_default()
            .entry(dst_svc)
            .or_default()
            .entry(transport);

        match transport {
            std::collections::btree_map::Entry::Vacant(v) => {
                v.insert(socket_addr);
                Ok(())
            }
            std::collections::btree_map::Entry::Occupied(_) => {
                bail!(
                    "SVC mapping for ISD-AS {}, SVC {} and protocol {} already exists",
                    ia,
                    dst_svc,
                    transport.key()
                )
            }
        }
    }

    /// Returns the SVC mapping for the given ISD-AS, if one exists.
    pub fn svc_mappings(
        &self,
        ia: IsdAsn,
        dst_svc: &ServiceAddr,
    ) -> Option<&BTreeMap<String, SocketAddr>> {
        if dst_svc.is_multicast() {
            // Multicast is deprecated and not supported here
            return None;
        }

        self.svc_mapping.get(&ia)?.get(dst_svc)
    }
}

/// Receivers registered for a specific ISD-AS.
///
/// An ISD-AS may have an optional wildcard receiver and any number of receivers bound to specific
/// IP ranges. Address-specific receivers take precedence over the wildcard receiver.
#[derive(Clone, Default)]
struct LocalNetworkReceivers {
    /// A single receiver registered for the entire ISD-AS, used as a fallback when no
    /// address-range receiver matches.
    wildcard: Option<Arc<dyn Receiver>>,
    /// Receivers registered for specific address ranges.
    ranged_receivers: Vec<(IpNet, Arc<dyn Receiver>)>,
}

impl LocalNetworkReceivers {
    /// Returns true if neither a wildcard receiver nor any address-range receivers are registered.
    fn is_empty(&self) -> bool {
        self.wildcard.is_none() && self.ranged_receivers.is_empty()
    }
}

impl std::fmt::Debug for LocalNetworkReceivers {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("LocalNetworkReceivers")
            .field("wildcard", &self.wildcard.is_some())
            .field("ranges", &self.ranged_receivers.len())
            .finish()
    }
}

#[cfg(test)]
mod tests {
    use std::{net::Ipv4Addr, str::FromStr};

    use scion_proto::packet::ScionPacketRaw;

    use super::*;
    #[test]
    fn should_get_wildcard_receiver_by_isd_as() {
        let mut receivers = NetworkReceiverRegistry::new();
        let ias = IsdAsn::from_str("1-2").unwrap();
        let receiver: Arc<dyn Receiver> = Arc::new(MockReceiver);
        receivers
            .add_wildcard_receiver(ias, receiver.clone())
            .unwrap();

        let addr = Ipv4Addr::from_str("10.0.0.1").unwrap().into();
        let found = receivers.by_addr(ias, addr).unwrap();
        assert!(Arc::ptr_eq(found, &receiver));
    }

    #[test]
    fn should_get_receiver_by_ip() {
        let mut receivers = NetworkReceiverRegistry::new();
        let ias = IsdAsn::from_str("1-2").unwrap();
        let ipnet: IpNet = "10.0.0.0/24".parse().unwrap();
        let receiver: Arc<dyn Receiver> = Arc::new(MockReceiver);
        receivers
            .add_receiver(ias, ipnet, receiver.clone())
            .unwrap();

        let addr = Ipv4Addr::from_str("10.0.0.42").unwrap().into();
        let found = receivers.by_addr(ias, addr).unwrap();
        assert!(Arc::ptr_eq(found, &receiver));
    }

    #[test]
    fn should_get_receiver_by_ip_multiple_ranges() {
        let mut receivers = NetworkReceiverRegistry::new();
        let ias = IsdAsn::from_str("1-2").unwrap();
        let ipnet1: IpNet = "10.0.0.0/24".parse().unwrap();
        let ipnet2: IpNet = "10.0.1.0/24".parse().unwrap();
        let receiver1: Arc<dyn Receiver> = Arc::new(MockReceiver);
        let receiver2: Arc<dyn Receiver> = Arc::new(MockReceiver);
        receivers
            .add_receiver(ias, ipnet1, receiver1.clone())
            .unwrap();
        receivers
            .add_receiver(ias, ipnet2, receiver2.clone())
            .unwrap();

        let addr1 = Ipv4Addr::from_str("10.0.0.42").unwrap().into();
        let addr2 = Ipv4Addr::from_str("10.0.1.99").unwrap().into();
        let found1 = receivers.by_addr(ias, addr1).unwrap();
        let found2 = receivers.by_addr(ias, addr2).unwrap();
        assert!(Arc::ptr_eq(found1, &receiver1));
        assert!(Arc::ptr_eq(found2, &receiver2));
    }

    #[test]
    fn should_return_none_for_ip_with_no_receiver() {
        let mut receivers = NetworkReceiverRegistry::new();
        let ias = IsdAsn::from_str("1-2").unwrap();
        let ipnet: IpNet = "10.0.0.0/24".parse().unwrap();
        let receiver: Arc<dyn Receiver> = Arc::new(MockReceiver);
        receivers.add_receiver(ias, ipnet, receiver).unwrap();

        let addr = Ipv4Addr::from_str("10.0.1.42").unwrap().into(); // Not in 10.0.0.0/24
        let found = receivers.by_addr(ias, addr);
        assert!(found.is_none());
    }

    #[test]
    fn should_fail_to_add_receiver_with_overlapping_ip_ranges() {
        let mut receivers = NetworkReceiverRegistry::new();
        let ias = IsdAsn::from_str("1-2").unwrap();
        let ipnet1: IpNet = "10.0.0.0/24".parse().unwrap();
        let ipnet2: IpNet = "10.0.0.128/25".parse().unwrap(); // Overlaps with ipnet1

        let receiver1: Arc<dyn Receiver> = Arc::new(MockReceiver);
        let receiver2: Arc<dyn Receiver> = Arc::new(MockReceiver);

        receivers.add_receiver(ias, ipnet1, receiver1).unwrap();
        let result = receivers.add_receiver(ias, ipnet2, receiver2);
        assert!(result.is_err());
    }

    #[test]
    fn should_fail_to_add_second_wildcard_receiver() {
        let mut receivers = NetworkReceiverRegistry::new();
        let ias = IsdAsn::from_str("1-2").unwrap();
        let receiver1: Arc<dyn Receiver> = Arc::new(MockReceiver);
        let receiver2: Arc<dyn Receiver> = Arc::new(MockReceiver);
        receivers.add_wildcard_receiver(ias, receiver1).unwrap();
        let result = receivers.add_wildcard_receiver(ias, receiver2);
        assert!(result.is_err());
    }

    #[test]
    fn should_allow_wildcard_and_range_receivers_to_coexist() {
        let mut receivers = NetworkReceiverRegistry::new();
        let ias = IsdAsn::from_str("1-2").unwrap();
        let ipnet: IpNet = "10.0.0.0/24".parse().unwrap();
        let wildcard: Arc<dyn Receiver> = Arc::new(MockReceiver);
        let range: Arc<dyn Receiver> = Arc::new(MockReceiver);

        receivers
            .add_wildcard_receiver(ias, wildcard.clone())
            .unwrap();
        receivers.add_receiver(ias, ipnet, range.clone()).unwrap();
    }

    #[test]
    fn should_prefer_range_receiver_over_wildcard() {
        let mut receivers = NetworkReceiverRegistry::new();
        let ias = IsdAsn::from_str("1-2").unwrap();
        let ipnet: IpNet = "10.0.0.0/24".parse().unwrap();
        let wildcard: Arc<dyn Receiver> = Arc::new(MockReceiver);
        let range: Arc<dyn Receiver> = Arc::new(MockReceiver);

        receivers
            .add_wildcard_receiver(ias, wildcard.clone())
            .unwrap();
        receivers.add_receiver(ias, ipnet, range.clone()).unwrap();

        // Address inside the range resolves to the range receiver.
        let in_range = Ipv4Addr::from_str("10.0.0.42").unwrap().into();
        let found = receivers.by_addr(ias, in_range).unwrap();
        assert!(Arc::ptr_eq(found, &range));

        // Address outside the range falls back to the wildcard receiver.
        let out_of_range = Ipv4Addr::from_str("10.0.1.42").unwrap().into();
        let found = receivers.by_addr(ias, out_of_range).unwrap();
        assert!(Arc::ptr_eq(found, &wildcard));
    }

    #[derive(Default)]
    struct MockReceiver;
    impl Receiver for MockReceiver {
        fn receive_packet(&self, _packet: ScionPacketRaw) {
            // No-op
        }
    }
}
