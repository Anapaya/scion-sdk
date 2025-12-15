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

use std::str::FromStr;

use super::types::{HopPredicate, PathPolicyHop};
use crate::path::policy::PathPolicy;

/// ACL Policy filters segments based on if they contain certain hops
///
/// ## Examples
///```
/// use scion_proto::address::{Asn, Isd};
/// use scion_proto::path::policy::{
///     acl::{AclEntry, AclEntryOperator, AclPolicy},
///     types::{HopPredicate, InterfacesPredicate},
/// };
///
/// // Only allow paths that go through ISD 1 AS 1
///
/// let mut acl = AclPolicy::new(AclEntryOperator::Deny);
/// let entry1 = AclEntry::new(
///     AclEntryOperator::Allow,
///     HopPredicate::new(Isd(1), Some(Asn(1)), InterfacesPredicate::Any),
/// );
///
/// // Deny all paths that go through ISD 1
/// let acl = AclPolicy::parse("- 1 +").unwrap();
///
/// // Deny all paths that go through ISD 2 or IsdAsn 3-1 using ingress interface 1 and egress interface 2
/// let acl = AclPolicy::parse("- 2 - 3-1#1,2 +").unwrap();
/// ```
#[derive(Debug, PartialEq, Eq, Clone)]
pub struct AclPolicy {
    /// ACL entries to evaluate in order
    pub entries: Vec<AclEntry>,
    /// Default action if no entries match
    pub default: AclEntryOperator,
}
impl AclPolicy {
    /// Creates a new empty AclPolicy
    ///
    /// - `default` defines the action to take if no entries match
    pub fn new(default: AclEntryOperator) -> Self {
        Self {
            entries: Vec::new(),
            default,
        }
    }

    /// Creates a new AclPolicy from entries
    ///
    /// - `default` defines the action to take if no entries match
    /// - `entries` defines the ACL entries to evaluate in order
    pub fn new_from_entries(
        default: AclEntryOperator,
        entries: impl IntoIterator<Item = AclEntry>,
    ) -> Self {
        Self {
            entries: entries.into_iter().collect(),
            default,
        }
    }

    /// Parses an AclPolicy from a string
    ///
    /// format:
    /// - "{operator} {hop-predicate} {operator} {hop-predicate} {default-operator}"
    pub fn parse(s: &str) -> Result<Self, String> {
        let mut entries = Vec::new();
        let mut split = s.split_whitespace();

        let mut first_op = split.next();
        let mut second_op = split.next();

        while let (Some(first), Some(second)) = (first_op, second_op) {
            let op = AclEntryOperator::parse(first)?;
            let hop = HopPredicate::from_str(second)?;

            if hop.is_wildcard() {
                if split.next().is_some() {
                    return Err("Wildcard hop predicate must be the last entry".into());
                }

                break;
            }

            entries.push(AclEntry::new(op, hop));

            first_op = split.next();
            second_op = split.next();
        }

        let Some(first) = first_op else {
            return Err("Missing default operator".into());
        };

        let default = AclEntryOperator::parse(first)?;

        Ok(Self { entries, default })
    }

    /// Adds a new entry to the ACL policy
    ///
    /// - `operator` defines if the entry allows or denies a path matching the hop predicate
    /// - `hop` defines the hop predicate to match against
    pub fn add_entry(mut self, operator: AclEntryOperator, hop: HopPredicate) -> Self {
        self.entries.push(AclEntry::new(operator, hop));
        self
    }

    /// Checks if the ACL policy allows the given path
    ///
    /// Returns true if the path is allowed
    pub fn matches(&self, path: &[PathPolicyHop]) -> bool {
        // If path is empty, or no acl  entries exist, use default
        if path.is_empty() || self.entries.is_empty() {
            return self.default == AclEntryOperator::Allow;
        }

        for hop in path {
            let mut hop_matched = false;

            for entry in &self.entries {
                match entry.matches(hop) {
                    // Allowed, continue to next hop
                    AclMatchResult::Allow => {
                        hop_matched = true;
                        break;
                    }
                    // Denied, deny the path
                    AclMatchResult::Deny => return false,
                    // No match, continue to next entry
                    AclMatchResult::Impartial => continue,
                };
            }

            // If hop was not matched and default is deny, deny the path
            if !hop_matched && self.default == AclEntryOperator::Deny {
                return false;
            }
        }

        // No entry denied the path, allow
        true
    }
}
impl FromStr for AclPolicy {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Self::parse(s)
    }
}
impl PathPolicy for AclPolicy {
    fn path_allowed<T>(
        &self,
        path: &crate::path::Path<T>,
    ) -> Result<bool, std::borrow::Cow<'static, str>> {
        let path_hops = PathPolicyHop::hops_from_path(path)?;
        Ok(self.matches(&path_hops))
    }
}

/// Access control list entry
///
/// Will either allow or deny a segment if any of its hop matches the predicate
///
/// String Format:
/// - {operator} {hop-predicate}
/// - "- 1"   - Disallow Isd 1
/// - "+ 1-2" - Allow IsdAsn 1-2
/// - "- 13-21#1,2" - Disallow IsdAsn 13-21 ingress 1 egress 2
#[derive(Debug, PartialEq, Eq, Clone)]
pub struct AclEntry {
    /// Operator to apply if predicate matches
    pub operator: AclEntryOperator,
    /// Hop predicate
    pub hop_predicate: HopPredicate,
}
impl AclEntry {
    /// Creates a new AclEntry
    pub fn new(operator: AclEntryOperator, hop: HopPredicate) -> Self {
        Self {
            operator,
            hop_predicate: hop,
        }
    }

    /// Parses an AclEntry from a string
    pub fn parse(s: &str) -> Result<Self, String> {
        let mut iter = s.splitn(2, ' ');

        let operator = iter
            .next()
            .ok_or_else(|| "Missing operator".to_string())
            .and_then(AclEntryOperator::parse)?;

        let hop = iter
            .next()
            .ok_or_else(|| "Missing hop predicate".to_string())
            .and_then(HopPredicate::from_str)?;

        Ok(Self {
            operator,
            hop_predicate: hop,
        })
    }

    /// Checks if the AclEntry matches the given hop
    /// Returns Allow, Deny or Impartial
    /// If Impartial, the next entry should be checked
    fn matches(&self, hop: &PathPolicyHop) -> AclMatchResult {
        if hop.matches(&self.hop_predicate) {
            match self.operator {
                AclEntryOperator::Allow => AclMatchResult::Allow,
                AclEntryOperator::Deny => AclMatchResult::Deny,
            }
        } else {
            AclMatchResult::Impartial
        }
    }
}
impl FromStr for AclEntry {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Self::parse(s)
    }
}

/// Result of matching an ACL entry against a hop
#[derive(Debug, PartialEq, Eq, Clone)]
enum AclMatchResult {
    /// The hop matched and the entry allows it
    Allow,
    /// The hop matched and the entry denies it
    Deny,
    /// The hop did not match the entry
    Impartial,
}

/// Access control list entry operator
///
/// Defines operation to apply on a hop matching the [AclEntry]
#[derive(Debug, PartialEq, Eq, Clone)]
pub enum AclEntryOperator {
    /// Allows the usage of this segment
    Allow,
    /// Denies the usage of this segment
    Deny,
}
impl AclEntryOperator {
    /// Parses an AclEntryOperator from a string
    pub fn parse(s: &str) -> Result<Self, String> {
        match s {
            "+" => Ok(AclEntryOperator::Allow),
            "-" => Ok(AclEntryOperator::Deny),
            _ => Err(format!("Invalid operator: {s}")),
        }
    }
}
impl FromStr for AclEntryOperator {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Self::parse(s)
    }
}

#[cfg(test)]
mod test {
    use super::*;
    mod acl_policy {
        use super::*;

        fn expect_parse(s: &str) -> AclPolicy {
            AclPolicy::parse(s).unwrap_or_else(|_| panic!("Should parse: {s}"))
        }

        #[test]
        fn parse_valid_acl_succeeds() {
            expect_parse("- 1 +");
            expect_parse("- 1 + 0");
            expect_parse("- 1 + 0-0");
            expect_parse("- 1 + 0-0#0");
            expect_parse("- 1 + 0-0#0,0");
            expect_parse("- 1-2 +");
            expect_parse("- 2 - 3-1#1,2 +");
            expect_parse("- 1-2#1,2 +");
            expect_parse("- 1 +");
            expect_parse("- 1 - 2-2#1 +");
            expect_parse("- 1 - 2-2#1,2 +");
        }

        fn expect_parse_fail(s: &str) -> String {
            AclPolicy::parse(s).expect_err(&format!("Should fail with: {s}"))
        }
        #[test]
        fn parse_invalid_acl_returns_error() {
            expect_parse_fail(""); // Empty string
            expect_parse_fail("- 1"); // Missing default operator
            expect_parse_fail("1"); // Missing operator
            expect_parse_fail("+ +"); // Missing hop predicate
            expect_parse_fail("- 1 + -"); // Missing hop predicate
            expect_parse_fail("- 0-0 + 2 +"); // Wildcard not last
        }

        #[test]
        fn should_make_correct_decision() {
            // Empty path: should use default operator
            expect_decision("+", true, &[]); // default allow
            expect_decision("-", false, &[]); // default deny
            expect_decision("- 1 +", true, &[]); // default allow

            // Blanket allow/deny
            expect_decision("+", true, &[hop(0, "1-3", 0)]); // allow all paths
            expect_decision("-", false, &[hop(0, "1-3", 0)]); // deny all paths

            expect_decision("- 1-1 + 1 -", true, &[hop(0, "1-3", 0)]); // first entry is impartial, second matches and allows.
            expect_decision("+ 1-3 - 1 +", true, &[hop(0, "1-3", 0)]); // first entry matches and allows, therefore should be allowed. Later entries and default should not be used.

            // "- 1 +" : deny ISD 1, default allow
            expect_decision("- 1 +", false, &[hop(0, "1-1", 0)]); // matches deny
            expect_decision("- 1 +", true, &[hop(0, "2-1", 0)]); // does not match, default allow

            // "- 1-2 +" : deny ISD-AS 1-2, default allow
            expect_decision("- 1-2 +", false, &[hop(0, "1-2", 0)]); // matches deny
            expect_decision("- 1-2 +", true, &[hop(0, "1-3", 0)]); // does not match

            // "- 2 - 3-1#1,2 +" : deny ISD 2, deny 3-1 with ifaces 1,2, default allow
            expect_decision("- 2 - 3-1#1,2 +", false, &[hop(1, "2-7", 2)]); // matches first deny
            expect_decision("- 2 - 3-1#1,2 +", false, &[hop(1, "3-1", 2)]); // matches second deny
            expect_decision("- 2 - 3-1#1,2 +", true, &[hop(2, "3-1", 1)]); // default allow

            expect_decision("+ 2 + 1 -", true, &[hop(1, "2-7", 2)]); // matches first allow
            expect_decision("+ 2 + 1 -", true, &[hop(1, "1-7", 2)]); // matches second allow
            expect_decision("+ 2 + 1 -", false, &[hop(2, "3-1", 1)]); // default deny
            expect_decision("+ 2 + 1 -", true, &[hop(2, "1-7", 1), hop(2, "2-7", 1)]); // all hops match allow
            expect_decision("+ 2 + 1 -", false, &[hop(2, "1-7", 1), hop(2, "3-1", 1)]); // not all hops match allow - deny

            // "- 1-2#1,2 +" : deny 1-2 with ifaces 1,2, default allow
            expect_decision("- 1-2#1,2 +", false, &[hop(1, "1-2", 2)]); // matches deny
            expect_decision("- 1-2#1,2 +", true, &[hop(2, "1-2", 1)]); // does not match - allow

            // duplicate "- 1 +" in list
            expect_decision("- 1 +", false, &[hop(0, "1-9", 0)]); // deny
            expect_decision("- 1 +", true, &[hop(0, "9-1", 0)]); // allow

            // "- 1 - 2-2#1 +" : deny ISD 1, deny 2-2 with ingress 1, default allow
            expect_decision("- 1 - 2-2#1 +", false, &[hop(0, "1-3", 0)]); // first deny
            expect_decision("- 1 - 2-2#1 +", false, &[hop(1, "2-2", 0)]); // second deny
            expect_decision("- 1 - 2-2#1 +", true, &[hop(2, "2-2", 3)]); // does not match any deny

            // "- 1 - 2-2#1,2 +" : deny ISD 1, deny 2-2 with ifaces 1,2, default allow
            expect_decision("- 1 - 2-2#1,2 +", false, &[hop(0, "1-3", 0)]); // first deny
            expect_decision("- 1 - 2-2#1,2 +", false, &[hop(1, "2-2", 2)]); // second deny
            expect_decision("- 1 - 2-2#1,2 +", true, &[hop(2, "2-2", 1)]); // different iface order -> allow

            // Multiple hops in path
            expect_decision("- 1 +", false, &[hop(0, "2-1", 0), hop(0, "1-1", 0)]); // one hop matches deny
            expect_decision("- 1 +", true, &[hop(0, "2-1", 0), hop(0, "3-1", 0)]); // no hop matches deny

            expect_decision("+ 1 -", true, &[hop(0, "1-1", 0), hop(0, "1-2", 0)]); // all hop match allow
            expect_decision("+ 1 -", false, &[hop(0, "1-1", 0), hop(0, "2-1", 0)]); // only one hop matches allow - deny
            expect_decision("+ 1 -", false, &[hop(0, "2-1", 0), hop(0, "3-1", 0)]); // no hop matches allow
            expect_decision(
                "- 1 +",
                false,
                &[hop(0, "1-1", 0), hop(0, "2-1", 0), hop(0, "3-1", 0)],
            ); // one hop matches deny - deny
            expect_decision(
                "- 4 +",
                true,
                &[hop(0, "1-1", 0), hop(0, "2-1", 0), hop(0, "3-1", 0)],
            ); // no hop matches deny - allow

            fn hop(isg: u16, isd_asn: &'static str, egress: u16) -> PathPolicyHop {
                PathPolicyHop {
                    isd_asn: isd_asn.parse().unwrap(),
                    ingress: isg,
                    egress,
                }
            }

            fn expect_decision(s: &str, expected: bool, path_hops: &[PathPolicyHop]) {
                let acl = expect_parse(s);
                let decision = acl.matches(path_hops);
                assert_eq!(
                    decision, expected,
                    "ACL: {s}, Hops: {:?}, Expected: {}, Got: {}",
                    path_hops, expected, decision
                );
            }
        }
    }
}
