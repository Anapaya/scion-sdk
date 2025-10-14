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

//! SCION Path Policies
//! Implements the [SCION Path Policy Language](https://docs.scion.org/en/latest/dev/design/PathPolicy.html)

use std::{borrow::Cow, collections::BTreeMap};

use crate::path::{
    Path,
    policy::{acl::AclPolicy, hop_pattern::HopPatternPolicy},
};

/// ACL Policy filtering segments or paths based on contained hops
pub mod acl;
/// Hop Pattern Policy to filter paths based on a required hop pattern
pub mod hop_pattern;
/// Types shared in the path policy module
pub mod types;

/// A Path Policy allows or disallows a path based on its hops
pub trait PathPolicy: Send + Sync + 'static {
    /// Returns true if the path should be considered for selection.
    ///
    /// Returns an error if the path cannot be evaluated by the policy e.g. because metadata is
    /// missing
    fn path_allowed<T>(&self, path: &Path<T>) -> Result<bool, Cow<'static, str>>;
}

/// A Segment Policy combining ACL's and a Hop pattern
pub struct Policy {
    /// ACL Policy filters segments based on if they contain certain hops
    pub acl: Option<AclPolicy>,
    /// Hop pattern required by this policy
    pub hop_pattern: Option<HopPatternPolicy>,
}
impl Policy {
    /// Creates a new Policy
    pub fn new(acl: Option<AclPolicy>, hop_pattern: Option<HopPatternPolicy>) -> Self {
        Self { acl, hop_pattern }
    }

    /// Merges another policy into this one
    ///
    /// If a field is already set, it will not be overwritten
    pub fn merge_from(mut self, other: Policy) -> Self {
        Self {
            acl: self.acl.take().or(other.acl),
            hop_pattern: self.hop_pattern.take().or(other.hop_pattern),
        }
    }

    /// Checks if the policy matches the given path
    ///
    /// Returns true if the path is allowed by this policy
    pub fn matches(&self, path: &[types::PathPolicyHop]) -> bool {
        self.hop_pattern
            .as_ref()
            .map(|seq| seq.matches(path))
            .unwrap_or(true)
            && self
                .acl
                .as_ref()
                .map(|acl| acl.matches(path))
                .unwrap_or(true)
    }
}
impl PathPolicy for Policy {
    fn path_allowed<T>(&self, path: &Path<T>) -> Result<bool, Cow<'static, str>> {
        let path_hops = types::PathPolicyHop::hops_from_path(path).map_err(Cow::from)?;
        Ok(self.matches(&path_hops))
    }
}

/// A set of Policies with associated weights
///
/// The weights are u8 values (0-255) where higher values indicate a higher preference
///
/// When selecting segments, the policy with the highest weight that matches at least one segment
/// will be chosen
pub struct WeightedPolicies {
    /// Policies with their associated weight
    pub policies: BTreeMap<u8, Policy>,
}
impl WeightedPolicies {
    /// Creates a new WeightedPolicies
    pub fn new(policies: impl IntoIterator<Item = (u8, Policy)>) -> Self {
        Self {
            policies: policies.into_iter().collect(),
        }
    }

    /// Adds a new policy with the given weight
    ///
    /// If a policy with the same weight already exists, it will be replaced and returned
    pub fn add_policy(&mut self, policy: Policy, weight: u8) -> Option<Policy> {
        self.policies.insert(weight, policy)
    }

    /// Finds the highest weighted policy that matches the given path
    ///
    /// Returns None if no policy matches
    pub fn match_highest(&self, path: &[types::PathPolicyHop]) -> Option<&Policy> {
        self.policies
            .values()
            .rev()
            .find(|&policy| policy.matches(path))
    }
}
