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

//! Shared types for path policy predicates and hops.

use std::{fmt::Display, str::FromStr};

use crate::{
    identifier::{asn::Asn, isd::Isd, isd_asn::IsdAsn},
    path::ScionPath,
};

/// A predicate to check a hop interface against.
///
/// Is either a wildcard (0) or a specific value.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct InterfacePredicate(u16);
impl InterfacePredicate {
    /// Creates a new hop interface predicate.
    ///
    /// 0 is deemed as a wildcard, all other values have to match exactly.
    #[inline]
    pub const fn new(interface: u16) -> Self {
        Self(interface)
    }

    /// Checks if the given interface matches the predicate.
    #[inline]
    pub const fn matches(&self, interface: u16) -> bool {
        self.is_wildcard() || self.0 == interface
    }

    /// Checks if any item in the given collection matches the predicate.
    #[inline]
    pub fn matches_any_in<'c>(&self, collection: impl IntoIterator<Item = &'c u16>) -> bool {
        collection.into_iter().any(|h| self.matches(*h))
    }

    /// Returns true if this is a wildcard and matches against any interface.
    #[inline]
    pub const fn is_wildcard(&self) -> bool {
        self.0 == 0
    }

    /// Returns the contained value as a u16.
    #[inline]
    pub const fn into_inner(self) -> u16 {
        self.0
    }
}
impl From<u16> for InterfacePredicate {
    #[inline]
    fn from(value: u16) -> Self {
        Self::new(value)
    }
}
impl From<InterfacePredicate> for u16 {
    #[inline]
    fn from(value: InterfacePredicate) -> Self {
        value.into_inner()
    }
}

/// Predicate to check SCION segment hops against.
///
/// String Format:
/// - "1"       - Just Match ISD
/// - "1-2"     - Match ISD and ASN
/// - "1-2#3"   - Match ISD, ASN and either ingress or egress interface
/// - "1-2#3,4" - Match ISD, ASN and exact ingress and egress interface
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct HopPredicate {
    /// The Isd predicate to match against
    pub isd: Isd,
    /// The Asn predicate to match against, none = wildcard
    pub asn: Option<Asn>,
    /// The Interface predicate to match against
    pub interfaces: InterfacesPredicate,
}
impl HopPredicate {
    /// Creates a new hop predicate.
    #[inline]
    pub fn new(
        isd: impl Into<Isd>,
        asn: Option<impl Into<Asn>>,
        interfaces: InterfacesPredicate,
    ) -> Self {
        Self {
            isd: isd.into(),
            asn: asn.map(Into::into),
            interfaces,
        }
    }

    /// Checks if the hop predicate matches the given hop.
    #[inline]
    pub fn matches(&self, hop_isd_asn: IsdAsn, hop_ingress: u16, hop_egress: u16) -> bool {
        self.isd.matches(hop_isd_asn.isd())
            && self
                .asn
                .map(|asn| asn.matches(hop_isd_asn.asn()))
                .unwrap_or(true)
            && self.interfaces.matches(hop_ingress, hop_egress)
    }

    /// Returns true if this is a wildcard predicate which matches any hop.
    #[inline]
    pub fn is_wildcard(&self) -> bool {
        self.isd.is_wildcard()
            && (self.asn.map(|a| a.is_wildcard()).unwrap_or(true))
            && self.interfaces.is_wildcard()
    }
}
impl FromStr for HopPredicate {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let mut iter = s.splitn(2, "-");

        let isd = iter.next().expect("First next can't be none");
        let isd = Isd::from_str(isd).map_err(|e| e.to_string())?;
        let Some(more) = iter.next() else {
            return Ok(Self {
                isd,
                asn: None,
                interfaces: InterfacesPredicate::Any,
            });
        };

        let mut iter = more.splitn(2, "#");
        let asn = iter.next().expect("First next can't be none");

        let asn = Asn::from_str(asn).map_err(|e| e.to_string())?;
        let Some(more) = iter.next() else {
            return Ok(Self {
                isd,
                asn: Some(asn),
                interfaces: InterfacesPredicate::Any,
            });
        };

        let interfaces = InterfacesPredicate::from_str(more)?;

        Ok(Self {
            isd,
            asn: Some(asn),
            interfaces,
        })
    }
}
impl Display for HopPredicate {
    #[inline]
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.isd)?;
        if let Some(asn) = &self.asn {
            write!(f, "-{asn}")?;
        }
        match &self.interfaces {
            InterfacesPredicate::Any => {}
            interfaces => write!(f, "#{interfaces}")?,
        }
        Ok(())
    }
}

/// Predicate to check the ingress and egress interface of a SCION hop.
///
/// String Format: \
/// "1" - Any interface must be 1
/// "1,2" - Ingress must be 1, egress must be 2
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum InterfacesPredicate {
    /// No Predicate
    Any,
    /// Either ingress or egress interface matches the hop interface
    Either(InterfacePredicate),
    /// Both ingress and egress interfaces have to match
    Both {
        /// Predicate to check ingress interface against
        ingress: InterfacePredicate,
        /// Predicate to check egress interface against
        egress: InterfacePredicate,
    },
}
impl InterfacesPredicate {
    /// Creates a new `Any` predicate.
    #[inline]
    pub const fn any() -> Self {
        Self::Any
    }
    /// Creates a new `Either` predicate.
    #[inline]
    pub fn either(any: impl Into<InterfacePredicate>) -> Self {
        Self::Either(any.into())
    }
    /// Creates a new `Both` predicate.
    #[inline]
    pub fn both(
        ingress: impl Into<InterfacePredicate>,
        egress: impl Into<InterfacePredicate>,
    ) -> Self {
        Self::Both {
            ingress: ingress.into(),
            egress: egress.into(),
        }
    }

    /// Checks if the given ingress and egress matches the predicate.
    #[inline]
    pub const fn matches(&self, hop_ingress: u16, hop_egress: u16) -> bool {
        match self {
            InterfacesPredicate::Either(any) => any.matches(hop_ingress) || any.matches(hop_egress),
            InterfacesPredicate::Both { ingress, egress } => {
                ingress.matches(hop_ingress) && egress.matches(hop_egress)
            }
            InterfacesPredicate::Any => true,
        }
    }

    /// Returns true if this is a wildcard and matches against any interface.
    #[inline]
    pub const fn is_wildcard(&self) -> bool {
        match self {
            InterfacesPredicate::Any => true,
            InterfacesPredicate::Either(pred) => pred.is_wildcard(),
            InterfacesPredicate::Both { ingress, egress } => {
                ingress.is_wildcard() && egress.is_wildcard()
            }
        }
    }
}
impl FromStr for InterfacesPredicate {
    type Err = String;

    #[inline]
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let mut iter = s.splitn(2, ",");

        let split = (iter.next().expect("First next can't be none"), iter.next());

        let res = match split {
            (any, None) => {
                let any = u16::from_str(any).map_err(|e| e.to_string())?;
                Self::Either(InterfacePredicate(any))
            }
            (ingress, Some(egress)) => {
                let ingress = u16::from_str(ingress).map_err(|e| e.to_string())?;
                let egress = u16::from_str(egress).map_err(|e| e.to_string())?;
                Self::Both {
                    ingress: InterfacePredicate(ingress),
                    egress: InterfacePredicate(egress),
                }
            }
        };

        Ok(res)
    }
}
impl Display for InterfacesPredicate {
    #[inline]
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            InterfacesPredicate::Any => Ok(()),
            InterfacesPredicate::Either(any) => write!(f, "{}", any.0),
            InterfacesPredicate::Both { ingress, egress } => {
                write!(f, "{},{}", ingress.0, egress.0)
            }
        }
    }
}

/// Path hop used to match against a path policy.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct PathPolicyHop {
    /// The ISD-ASN of the hop
    pub isd_asn: IsdAsn,
    /// The ingress interface of the hop
    pub ingress: u16,
    /// The egress interface of the hop
    pub egress: u16,
}
impl PathPolicyHop {
    /// Checks if the hop matches the given predicate.
    #[inline]
    pub fn matches(&self, pred: &HopPredicate) -> bool {
        pred.matches(self.isd_asn, self.ingress, self.egress)
    }

    /// Converts a SCION path into a vector of [`PathPolicyHop`]s.
    pub fn hops_from_path(path: &ScionPath) -> Result<Vec<Self>, &'static str> {
        let Some(metadata) = &path.metadata else {
            // If there is no metadata, we cannot apply any policy
            return Err("Path has no metadata");
        };

        let Some(interfaces) = &metadata.interfaces else {
            // If there are no interfaces, we cannot apply any policy
            return Err("Path metadata has no interfaces");
        };

        let first_hop = interfaces
            .first()
            .ok_or("Path metadata has no interfaces")?;

        let mut path_hops: Vec<PathPolicyHop> = Vec::with_capacity(interfaces.len() + 2);
        path_hops.push(PathPolicyHop {
            isd_asn: first_hop.interface.isd_asn,
            ingress: 0,
            egress: first_hop.interface.id,
        });

        let (interfaces, remainder) = interfaces[1..].as_chunks::<2>();
        let [last_hop] = remainder else {
            // There must be one left over interface for the last hop
            return Err("Path contains an odd number of hop interfaces");
        };

        for [ingress, egress] in interfaces {
            if ingress.interface.isd_asn != egress.interface.isd_asn {
                return Err("Path contains a hop with interfaces in different Isd-Asn's");
            }

            path_hops.push(PathPolicyHop {
                isd_asn: ingress.interface.isd_asn,
                ingress: ingress.interface.id,
                egress: egress.interface.id,
            });
        }

        path_hops.push(PathPolicyHop {
            isd_asn: last_hop.interface.isd_asn,
            ingress: last_hop.interface.id,
            egress: 0,
        });

        Ok(path_hops)
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::path::{
        ScionPath,
        metadata::{PathMetadata, path_interface::PathInterface},
    };

    fn policy_hops(data: Vec<(IsdAsn, u16, u16)>) -> Vec<PathPolicyHop> {
        data.into_iter()
            .map(|(isd_asn, ingress, egress)| {
                PathPolicyHop {
                    isd_asn,
                    ingress,
                    egress,
                }
            })
            .collect()
    }
    /// Helper to create a Path with given PathPolicyHops
    ///
    /// Path is mostly a stub, just 'metadata.interfaces' is correct
    fn make_path(path_hops: Vec<PathPolicyHop>) -> ScionPath {
        let mut path_interfaces: Vec<PathInterface> = vec![];
        for hop in path_hops {
            if hop.ingress != 0 {
                path_interfaces.push(PathInterface {
                    isd_asn: hop.isd_asn,
                    id: hop.ingress,
                });
            }
            if hop.egress != 0 {
                path_interfaces.push(PathInterface {
                    isd_asn: hop.isd_asn,
                    id: hop.egress,
                });
            }
        }

        let source = path_interfaces
            .first()
            .expect("path_hops must contain at least one hop")
            .isd_asn;
        let destination = path_interfaces
            .last()
            .expect("path_hops must contain at least one hop")
            .isd_asn;

        ScionPath::new(
            source,
            destination,
            crate::dataplane_path::view::ScionDpPathView::Empty,
            Some(PathMetadata::new_minimal(0, 0, path_interfaces)),
            None,
        )
    }

    mod path_policy_hop {
        use super::*;

        #[test]
        fn should_correctly_load_path() {
            let path_hops = policy_hops(vec![
                (IsdAsn::from_str("1-ff00:0:1").unwrap(), 0, 10),
                (IsdAsn::from_str("1-ff00:0:2").unwrap(), 10, 20),
                (IsdAsn::from_str("2-ff00:0:2").unwrap(), 20, 30),
                (IsdAsn::from_str("2-ff00:0:3").unwrap(), 30, 0),
            ]);

            let path = make_path(path_hops.clone());
            let loaded_hops = PathPolicyHop::hops_from_path(&path).unwrap();

            assert_eq!(path_hops, loaded_hops);

            let path_hops = policy_hops(vec![
                (IsdAsn::from_str("1-ff00:0:1").unwrap(), 0, 10),
                (IsdAsn::from_str("2-ff00:0:3").unwrap(), 30, 0),
            ]);

            let path = make_path(path_hops.clone());
            let loaded_hops = PathPolicyHop::hops_from_path(&path).unwrap();

            assert_eq!(path_hops, loaded_hops);
        }

        #[test]
        fn should_fail_on_invalid_path() {
            // Odd number of interfaces
            let path_hops = policy_hops(vec![
                (IsdAsn::from_str("1-ff00:0:1").unwrap(), 0, 10), // First hop
                // 0 doesn't insert an interface
                (IsdAsn::from_str("2-ff00:0:2").unwrap(), 20, 0),
                (IsdAsn::from_str("3-ff00:0:3").unwrap(), 30, 0), // Last hop
            ]);

            let path = make_path(path_hops.clone());
            let res = PathPolicyHop::hops_from_path(&path);
            assert!(res.is_err(), "Expected error on odd number of interfaces");

            // Different Isd-Asns in one hop
            let path_hops = policy_hops(vec![
                (IsdAsn::from_str("1-ff00:0:1").unwrap(), 0, 10),
                (IsdAsn::from_str("2-ff00:0:2").unwrap(), 10, 0),
                (IsdAsn::from_str("2-ff00:0:3").unwrap(), 0, 20),
                (IsdAsn::from_str("3-ff00:0:4").unwrap(), 30, 0),
            ]);

            let path = make_path(path_hops.clone());
            let res = PathPolicyHop::hops_from_path(&path);
            assert!(
                res.is_err(),
                "Expected error on different Isd-Asns in one hop"
            );
        }
    }
}
