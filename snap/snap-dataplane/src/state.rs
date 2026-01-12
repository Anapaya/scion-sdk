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
//! SNAP data plane state.

use std::{fmt::Display, sync::LazyLock};

use regex::Regex;
use serde::{Deserialize, Serialize};
use thiserror::Error;
use utoipa::ToSchema;

/// Generic identifier trait.
pub trait Id {
    /// Creates an identifier from a `usize`.
    fn from_usize(val: usize) -> Self;
    /// Returns the identifier as a `usize`.
    fn as_usize(&self) -> usize;
}

/// SNAP node hostname.
#[derive(Debug, Clone, Hash, PartialEq, Eq, PartialOrd, Ord, ToSchema, Serialize)]
#[serde(transparent)]
pub struct Hostname(String);

/// Hostname validation error.
#[derive(Debug, Error)]
pub enum HostnameError {
    /// Empty hostname.
    #[error("Hostname is empty")]
    Empty,
    /// Hostname too long.
    #[error("Hostname is too long: {0} characters (maximum is 253)")]
    TooLong(usize),
    /// Invalid hostname.
    #[error("Invalid hostname: {0}")]
    Invalid(String),
}

/// Regular expression for validating hostnames according to RFC 1123.
pub const HOSTNAME_REGEX: &str = r"^([a-zA-Z0-9]|[a-zA-Z0-9][a-zA-Z0-9-]{0,61}[a-zA-Z0-9])(\\.([a-zA-Z0-9]|[a-zA-Z0-9][a-zA-Z0-9-]{0,61}[a-zA-Z0-9]))*$";

impl Hostname {
    /// Initialize a valid hostname according to RFC 1123.
    ///
    /// A valid hostname must:
    /// - Be at most 253 characters long
    /// - Match the pattern: [`HOSTNAME_REGEX`]
    pub fn new(hostname: String) -> Result<Self, HostnameError> {
        Self::validate(&hostname)?;
        Ok(Self(hostname))
    }

    fn validate(hostname: &str) -> Result<(), HostnameError> {
        if hostname.len() > 253 {
            return Err(HostnameError::TooLong(hostname.len()));
        }

        static RE: LazyLock<Regex> =
            LazyLock::new(|| Regex::new(HOSTNAME_REGEX).expect("valid regex"));
        if !RE.is_match(hostname) {
            return Err(HostnameError::Invalid(hostname.to_string()));
        }

        Ok(())
    }
}

impl Display for Hostname {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl From<Hostname> for String {
    fn from(value: Hostname) -> Self {
        value.0
    }
}

impl TryFrom<String> for Hostname {
    type Error = HostnameError;

    fn try_from(value: String) -> Result<Self, Self::Error> {
        Self::new(value)
    }
}

impl TryFrom<&str> for Hostname {
    type Error = HostnameError;

    fn try_from(value: &str) -> Result<Self, Self::Error> {
        Self::new(value.to_string())
    }
}

// Custom deserializer that validates the hostname
impl<'de> Deserialize<'de> for Hostname {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let s = String::deserialize(deserializer)?;
        Hostname::new(s).map_err(serde::de::Error::custom)
    }
}
