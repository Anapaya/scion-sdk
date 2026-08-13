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
use sciparse::address::ip_addr::ScionIpAddr;
use thiserror::Error;

/// DNS resolver trait for SCION address discovery.
///
/// Implementations return zero or more `ScionAddr` values for a given domain
/// name. The resolver is expected to be async and safe to share across tasks.
///
/// # Error handling
///
/// Implementations SHOULD return `ResolveError::NoValidEntries` when a lookup
/// completes but yields no valid SCION TXT entries, which includes a name that
/// has no TXT records at all and a name that does not exist. Lookups that never
/// complete (timeout, network error, server failure) SHOULD return
/// `ResolveError::DnsLookup`, the only outcome a retry can change; callers
/// branch on that with [`ResolveError::is_transient`] rather than on the
/// variants. Partial failures SHOULD return the valid addresses and log
/// warnings for invalid entries.
#[async_trait]
pub trait ScionDnsResolver: Send + Sync {
    /// Resolve a domain into SCION addresses.
    ///
    /// Implementations SHOULD return only valid addresses and log warnings for
    /// invalid TXT entries. Errors are reserved for lookup failures or when no
    /// valid addresses can be produced.
    async fn resolve(&self, domain: &str) -> Result<Vec<ScionIpAddr>, ResolveError>;
}

/// Errors returned by SCION DNS resolution.
// Derives `PartialEq` for testability; as a consequence, `DnsLookup` carries a formatted message
// rather than the underlying (non-`PartialEq`) DNS error. See API_CONVENTIONS.md.
#[derive(Debug, Error, PartialEq)]
#[non_exhaustive]
pub enum ResolveError {
    /// The lookup itself failed, for example on a timeout, a network error, or
    /// a server failure. A retry may succeed.
    #[error("dns lookup failed: {0}")]
    DnsLookup(String),
    /// The lookup completed without producing a usable SCION address: the TXT
    /// records that exist do not parse as TSAR entries, the name has no TXT
    /// records, or the name does not exist. A retry does not help for as long
    /// as the answer stays valid.
    #[error("no valid TSAR TXT entries for {domain}")]
    NoValidEntries {
        /// Domain name that was looked up.
        domain: String,
        /// Invalid entries encountered during parsing or TXT decoding. Empty
        /// when the lookup returned no TXT records to parse.
        invalid_entries: Vec<InvalidEntry>,
    },
}

impl ResolveError {
    /// Returns whether the failure is transient, so that a retry may help.
    ///
    /// Prefer this over matching the variants: the enum is `#[non_exhaustive]`,
    /// and a new variant would silently fall into a caller's wildcard arm.
    #[must_use]
    pub fn is_transient(&self) -> bool {
        match self {
            Self::DnsLookup(_) => true,
            Self::NoValidEntries { .. } => false,
        }
    }
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
