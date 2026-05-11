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
//! DNS resolution helpers for SCION addresses.

pub mod txt;

use async_trait::async_trait;
use scion_proto::address::ScionAddr;
use thiserror::Error;

/// DNS resolver trait for SCION address discovery.
///
/// Implementations return zero or more `ScionAddr` values for a given domain
/// name. The resolver is expected to be async and safe to share across tasks.
///
/// # Error handling
///
/// Implementations SHOULD return `ResolveError::NoValidEntries` only when a
/// lookup succeeds but yields no valid SCION TXT entries. Partial failures
/// SHOULD return the valid addresses and log warnings for invalid entries.
#[async_trait]
pub trait ScionDnsResolver: Send + Sync {
    /// Resolve a domain into SCION addresses.
    ///
    /// Implementations SHOULD return only valid addresses and log warnings for
    /// invalid TXT entries. Errors are reserved for lookup failures or when no
    /// valid addresses can be produced.
    async fn resolve(&self, domain: &str) -> Result<Vec<ScionAddr>, ResolveError>;
}

/// Errors returned by SCION DNS resolution.
#[derive(Debug, Error, PartialEq)]
pub enum ResolveError {
    /// DNS lookup failed.
    #[error("dns lookup failed: {0}")]
    DnsLookup(String),
    /// No valid TSAR entries were found.
    #[error("no valid TSAR TXT entries for {domain}")]
    NoValidEntries {
        /// Domain name that was looked up.
        domain: String,
        /// Invalid entries encountered during parsing or TXT decoding.
        invalid_entries: Vec<InvalidEntry>,
    },
}

/// Metadata for a TXT entry that could not be parsed.
#[derive(Debug, Clone, PartialEq)]
pub struct InvalidEntry {
    raw: String,
    reason: String,
}

impl InvalidEntry {
    pub(crate) fn new(raw: impl Into<String>, reason: impl Into<String>) -> Self {
        Self {
            raw: raw.into(),
            reason: reason.into(),
        }
    }

    /// Return the raw TXT entry that failed parsing.
    pub fn raw(&self) -> &str {
        &self.raw
    }

    /// Return the reason this TXT entry failed parsing.
    pub fn reason(&self) -> &str {
        &self.reason
    }
}
