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

//! The `host:port` target of a `CONNECT` tunnel.

use std::{fmt, str::FromStr};

/// The `host:port` target of a `CONNECT` tunnel.
///
/// The host is a DNS name or an IP literal (IPv6 in brackets) and is stored in
/// lowercase. The port is never zero.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct Authority {
    host: String,
    port: u16,
}

impl Authority {
    /// Creates an authority from a host and a non-zero port.
    pub fn new(host: impl Into<String>, port: u16) -> Result<Authority, InvalidAuthority> {
        let host = host.into();
        if port == 0 {
            return Err(InvalidAuthority::InvalidPort);
        }
        if host.is_empty() {
            return Err(InvalidAuthority::MissingHost);
        }
        if host.contains('@') {
            return Err(InvalidAuthority::UserinfoNotAllowed);
        }
        let parsed = http::uri::Authority::from_str(&format!("{host}:{port}"))
            .map_err(|_| InvalidAuthority::InvalidHost)?;
        if parsed.host() != host {
            return Err(InvalidAuthority::InvalidHost);
        }
        Ok(Authority {
            host: host.to_ascii_lowercase(),
            port,
        })
    }

    /// The host, in lowercase.
    #[must_use]
    pub fn host(&self) -> &str {
        &self.host
    }

    /// The port.
    #[must_use]
    pub fn port(&self) -> u16 {
        self.port
    }
}

impl FromStr for Authority {
    type Err = InvalidAuthority;

    /// Parses `host:port`.
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let (host, port) = match s.rsplit_once(':') {
            Some(split) if !s.ends_with(']') => split,
            _ => return Err(InvalidAuthority::MissingPort),
        };
        let port = port.parse().map_err(|_| InvalidAuthority::InvalidPort)?;
        Authority::new(host, port)
    }
}

impl TryFrom<&str> for Authority {
    type Error = InvalidAuthority;

    fn try_from(s: &str) -> Result<Self, Self::Error> {
        s.parse()
    }
}

impl fmt::Display for Authority {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}:{}", self.host, self.port)
    }
}

/// An [`Authority`] could not be built.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum InvalidAuthority {
    /// The authority has no `:port`.
    #[error("authority has no port")]
    MissingPort,
    /// The port is not a number from 1 to 65535.
    #[error("port is not a number from 1 to 65535")]
    InvalidPort,
    /// The host is empty.
    #[error("authority has no host")]
    MissingHost,
    /// The host is not a DNS name or an IP literal.
    #[error("host is not a DNS name or an IP literal")]
    InvalidHost,
    /// The authority contains `user@`.
    #[error("authority must not contain userinfo")]
    UserinfoNotAllowed,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_and_normalizes() {
        let authority: Authority = "Example.org:8443".parse().unwrap();
        assert_eq!(authority.host(), "example.org");
        assert_eq!(authority.port(), 8443);
        assert_eq!(authority.to_string(), "example.org:8443");

        let v6: Authority = "[::1]:443".parse().unwrap();
        assert_eq!(v6.host(), "[::1]");
        assert_eq!(v6, Authority::new("[::1]", 443).unwrap());
    }

    #[test]
    fn rejects_invalid_input() {
        let cases = [
            ("example.org", InvalidAuthority::MissingPort),
            ("[::1]", InvalidAuthority::MissingPort),
            ("example.org:0", InvalidAuthority::InvalidPort),
            ("example.org:65536", InvalidAuthority::InvalidPort),
            ("example.org:http", InvalidAuthority::InvalidPort),
            (":443", InvalidAuthority::MissingHost),
            ("user@example.org:443", InvalidAuthority::UserinfoNotAllowed),
            ("a b:443", InvalidAuthority::InvalidHost),
            ("a/b:443", InvalidAuthority::InvalidHost),
        ];
        for (input, expected) in cases {
            assert_eq!(input.parse::<Authority>(), Err(expected), "{input}");
        }
        assert_eq!(
            Authority::new("example.org", 0),
            Err(InvalidAuthority::InvalidPort)
        );
        assert_eq!(
            Authority::new("a:b", 443),
            Err(InvalidAuthority::InvalidHost)
        );
    }
}
