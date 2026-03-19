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
//! TXT-based SCION address resolution (TSAR).
//!
//! TSAR encodes SCION addresses in DNS TXT records to support dual-stack
//! resolution. The record format is defined as:
//!
//! ```text
//! scion-txt     = "scion=" version separator address-list
//! version       = "v1"          ; Versioning for future extensibility
//! separator     = ";"
//! address-list  = address *( "," address )
//! address       = "[" isd-as "," host "]"
//! isd-as        = 1*DIGIT "-" 1*HEXDIG ":" 1*HEXDIG ":" 1*HEXDIG
//! host          = ipv4-address / ipv6-address
//! ipv4-address  = 1*3DIGIT "." 1*3DIGIT "." 1*3DIGIT "." 1*3DIGIT
//! ipv6-address  = <RFC5952 compliant string>
//! ```
//!
//! Example records:
//!
//! ```text
//! example.com. IN TXT "scion=v1;[19-ff00:0:110,192.0.2.1]"
//! example.com. IN TXT "scion=v1;[19-ff00:0:110,2001:db8::1]"
//! example.com. IN TXT "scion=v1;[19-ff00:0:110,192.0.2.1],[19-ff00:0:111,203.0.113.5]"
//! ```

use std::{net::IpAddr, str::FromStr};

use async_trait::async_trait;
use hickory_resolver::{
    ResolverBuilder, TokioResolver, name_server::TokioConnectionProvider, proto::rr::rdata::TXT,
};
use scion_proto::address::{HostAddr, IsdAsn, ScionAddr};
use thiserror::Error;

use super::{InvalidEntry, ResolveError, ScionDnsResolver};

const SCION_TXT_PREFIX: &str = "scion=v1;";

/// Resolver that interprets TXT records using the TSAR format.
///
/// Use this resolver to look up `scion=v1;...` TXT records and translate them
/// into `ScionAddr` values. Construction errors are reported via
/// `TxtResolverError`, while lookup failures and parsing outcomes are reported
/// through `ResolveError` from `ScionDnsResolver::resolve`.
#[derive(Clone, Debug)]
pub struct ScionTxtDnsResolver {
    resolver: TokioResolver,
}

impl ScionTxtDnsResolver {
    /// Create a resolver using the system DNS configuration.
    ///
    /// This uses the OS resolver configuration (for example `/etc/resolv.conf`)
    /// and then applies the default hickory-dns options for lookups.
    ///
    /// # Errors
    ///
    /// Returns `TxtResolverError` if the system configuration cannot be loaded.
    pub fn new() -> Result<Self, TxtResolverError> {
        let builder = Self::builder()?;
        Self::from_builder(builder)
    }

    /// Construct a resolver from a pre-configured hickory `ResolverBuilder`.
    ///
    /// This allows callers to customize resolver options (timeouts, retries,
    /// name servers) via hickory-dns before constructing the resolver.
    ///
    /// # Errors
    ///
    /// This function is currently infallible, but returns `Result` for future
    /// compatibility with hickory-dns builder changes.
    pub fn from_builder(
        builder: ResolverBuilder<TokioConnectionProvider>,
    ) -> Result<Self, TxtResolverError> {
        Ok(Self {
            resolver: builder.build(),
        })
    }

    /// Create a builder for configuring resolver options.
    ///
    /// On Linux/macOS the builder is initialized from the system DNS
    /// configuration (`/etc/resolv.conf`). On Android and iOS, which do not
    /// expose `/etc/resolv.conf`, Google Public DNS is used as a fallback.
    ///
    /// The returned builder can be adjusted before calling
    /// `ScionTxtDnsResolver::from_builder`.
    ///
    /// # Errors
    ///
    /// Returns `TxtResolverError` if system configuration cannot be loaded
    /// (non-Android/iOS platforms only).
    pub fn builder() -> Result<ResolverBuilder<TokioConnectionProvider>, TxtResolverError> {
        #[cfg(any(target_os = "android", target_os = "ios"))]
        {
            use hickory_resolver::config::ResolverConfig;
            // Android and iOS do not have /etc/resolv.conf.
            // Fall back to Google Public DNS for SCION TXT record resolution.
            Ok(TokioResolver::builder_with_config(
                ResolverConfig::google(),
                TokioConnectionProvider::default(),
            ))
        }
        #[cfg(not(any(target_os = "android", target_os = "ios")))]
        {
            Ok(TokioResolver::builder_tokio()?)
        }
    }
}

#[async_trait]
impl ScionDnsResolver for ScionTxtDnsResolver {
    async fn resolve(&self, domain: &str) -> Result<Vec<ScionAddr>, ResolveError> {
        let lookup = self
            .resolver
            .txt_lookup(domain)
            .await
            .map_err(|err| ResolveError::DnsLookup(err.to_string()))?;

        let mut txt_records = Vec::new();
        let mut invalid_entries = Vec::new();
        for txt in lookup.iter() {
            match txt_record_to_string(txt) {
                Ok(txt_record) => txt_records.push(txt_record),
                Err(err) => invalid_entries.push(err),
            }
        }

        resolve_txt_records_with_invalid(domain, txt_records, invalid_entries)
    }
}

/// Errors returned while constructing a TXT resolver.
#[derive(Debug, Error)]
pub enum TxtResolverError {
    /// DNS resolver configuration failed.
    #[error("dns resolver configuration failed: {0}")]
    DnsConfig(#[from] hickory_resolver::ResolveError),
}

impl PartialEq for TxtResolverError {
    fn eq(&self, other: &Self) -> bool {
        match (self, other) {
            (Self::DnsConfig(a), Self::DnsConfig(b)) => a.to_string() == b.to_string(),
        }
    }
}

#[derive(Debug, Error)]
enum TxtParseError {
    #[error("missing TXT address list")]
    MissingAddressList,
    #[error("expected '[' at: {0}")]
    ExpectedOpenBracket(String),
    #[error("missing closing ']' in: {0}")]
    MissingCloseBracket(String),
    #[error("expected comma separator in: {0}")]
    MissingSeparator(String),
    #[error("invalid ISD-AS: {0}")]
    InvalidIsdAsn(#[from] scion_proto::address::AddressParseError),
    #[error("invalid host address: {0}")]
    InvalidHost(#[from] std::net::AddrParseError),
    #[error("expected ',' after entry in: {0}")]
    ExpectedComma(String),
}

#[cfg(test)]
fn resolve_txt_records(
    domain: &str,
    records: impl IntoIterator<Item = String>,
) -> Result<Vec<ScionAddr>, ResolveError> {
    resolve_txt_records_with_invalid(domain, records, Vec::new())
}

fn resolve_txt_records_with_invalid(
    domain: &str,
    records: impl IntoIterator<Item = String>,
    mut invalid: Vec<InvalidEntry>,
) -> Result<Vec<ScionAddr>, ResolveError> {
    let mut valid = Vec::new();

    for record in records {
        let Some(payload) = record.strip_prefix(SCION_TXT_PREFIX) else {
            continue;
        };

        match parse_txt_payload(payload) {
            Ok(mut addresses) => valid.append(&mut addresses),
            Err(err) => invalid.push(InvalidEntry::new(record, err.to_string())),
        }
    }

    if valid.is_empty() {
        return Err(ResolveError::NoValidEntries {
            domain: domain.to_string(),
            invalid_entries: invalid,
        });
    }

    if !invalid.is_empty() {
        let details = format_invalid_entries(&invalid);
        tracing::info!(
            domain,
            invalid_entries = invalid.len(),
            details = ?details,
            "Ignoring invalid SCION TXT entries"
        );
    }

    Ok(valid)
}

fn parse_txt_payload(payload: &str) -> Result<Vec<ScionAddr>, TxtParseError> {
    let mut remaining = payload.trim();
    if remaining.is_empty() {
        return Err(TxtParseError::MissingAddressList);
    }

    let mut addresses = Vec::new();
    while !remaining.is_empty() {
        if !remaining.starts_with('[') {
            return Err(TxtParseError::ExpectedOpenBracket(remaining.to_string()));
        }

        let close_idx = remaining
            .find(']')
            .ok_or_else(|| TxtParseError::MissingCloseBracket(remaining.to_string()))?;
        let entry = remaining[1..close_idx].trim();
        let rest = remaining[close_idx + 1..].trim();

        let (isd_asn_str, host_str) = entry
            .split_once(',')
            .ok_or_else(|| TxtParseError::MissingSeparator(entry.to_string()))?;

        let isd_asn = IsdAsn::from_str(isd_asn_str.trim())?;
        let host = IpAddr::from_str(host_str.trim())?;

        addresses.push(ScionAddr::new(isd_asn, HostAddr::from(host)));

        if rest.is_empty() {
            break;
        }

        if !rest.starts_with(',') {
            return Err(TxtParseError::ExpectedComma(rest.to_string()));
        }

        remaining = rest[1..].trim();
    }

    Ok(addresses)
}

fn txt_record_to_string(txt: &TXT) -> Result<String, InvalidEntry> {
    let bytes: Vec<u8> = txt
        .txt_data()
        .iter()
        .flat_map(|chunk| chunk.iter())
        .copied()
        .collect();

    String::from_utf8(bytes)
        .map_err(|_| InvalidEntry::new("<invalid-utf8>", "TXT entry is not valid UTF-8"))
}

fn format_invalid_entries(entries: &[InvalidEntry]) -> Vec<String> {
    entries
        .iter()
        .map(|entry| format!("{} ({})", entry.raw(), entry.reason()))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_txt_payload_single() {
        let addrs = parse_txt_payload("[19-ff00:0:110,192.0.2.1]").expect("valid payload");
        assert_eq!(addrs.len(), 1);
        assert_eq!(
            addrs[0],
            ScionAddr::from_str("19-ff00:0:110,192.0.2.1").unwrap()
        );
    }

    #[test]
    fn parse_txt_payload_multiple() {
        let addrs = parse_txt_payload("[19-ff00:0:110,192.0.2.1],[19-ff00:0:111,2001:db8::1]")
            .expect("valid payload");
        assert_eq!(addrs.len(), 2);
    }

    #[test]
    fn resolve_txt_records_mixed_validity() {
        let records = vec![
            "scion=v1;[19-ff00:0:110,192.0.2.1]".to_string(),
            "scion=v1;[bad,192.0.2.2]".to_string(),
        ];

        let resolved = resolve_txt_records("example.com", records).expect("valid addresses");
        assert_eq!(resolved.len(), 1);
    }

    #[test]
    fn resolve_txt_records_no_valid_entries() {
        let records = vec!["scion=v1;[bad,192.0.2.2]".to_string()];

        let err = resolve_txt_records("example.com", records).expect_err("no valid entries");
        match err {
            ResolveError::NoValidEntries { domain, .. } => {
                assert_eq!(domain, "example.com");
            }
            other => panic!("unexpected error: {other:?}"),
        }
    }

    #[test]
    fn parse_txt_payload_allows_whitespace_between_entries() {
        let addrs = parse_txt_payload("[19-ff00:0:110,192.0.2.1] , [19-ff00:0:111,2001:db8::1]")
            .expect("valid payload");
        assert_eq!(addrs.len(), 2);
    }
}
