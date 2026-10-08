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

//! The records and the error that Gobley generates into Kotlin.
//!
//! A change here changes the Kotlin API.

#[derive(uniffi::Record)]
pub struct CoreHeader {
    pub name: String,
    pub value: String,
}

/// Resolves `host` to fixed SCION addresses, for a host without TSAR records.
#[derive(uniffi::Record)]
pub struct CoreDnsOverride {
    pub host: String,
    /// Each in the form `<isd>-<as>,<ip>`, without a port.
    pub addresses: Vec<String>,
}

#[derive(uniffi::Enum)]
pub enum CoreUnderlay {
    Snap,
    Udp,
}

/// Where the token for the endhost API and the SNAP control plane comes from.
#[derive(uniffi::Enum)]
pub enum CoreTokenSource {
    /// Gets the token from the Anapaya AA and renews it.
    AnapayaAa {
        api_key: String,
        url: Option<String>,
        device_id: Option<String>,
    },
    /// A fixed token. This is only suitable for testing.
    Static { token: String },
}

/// Sends each request through a `CONNECT` tunnel to a PathGuard WebGateway.
///
/// The Rust library dials the request host at [`port`](Self::port) and sends
/// the request host and port as the `CONNECT` authority.
#[derive(uniffi::Record)]
pub struct CoreWebGateway {
    /// The port of the gateway.
    pub port: u16,
}

/// An absent value keeps the default of the engine config.
// Note: this uses signed integers to ensure similar error handling.
#[derive(uniffi::Record)]
pub struct CoreConfig {
    /// A fixed endhost API. If absent, the Rust library discovers the endhost
    /// APIs: through the URL that the AA sends, else through the global
    /// discovery service.
    pub endhost_api_url: Option<String>,
    /// If absent, the Rust library sends no token.
    pub token_source: Option<CoreTokenSource>,
    /// What SCION underlay to prefer if possible.
    pub preferred_underlay: Option<CoreUnderlay>,
    /// Trust anchors for origin certificates, as a PEM bundle.
    ///
    /// If absent, the Rust library uses the platform verifier.
    pub ca_certificates_pem: Option<Vec<u8>>,
    /// Trust anchors for the AA, the discovery service, the endhost API, and
    /// the SNAP control plane, as a PEM bundle.
    ///
    /// If absent, the Rust library uses the platform verifier.
    pub control_plane_ca_certificates_pem: Option<Vec<u8>>,
    pub accept_invalid_certs: bool,
    pub dns_overrides: Vec<CoreDnsOverride>,
    pub connect_timeout_ms: Option<i64>,
    pub request_timeout_ms: Option<i64>,
    pub idle_timeout_ms: Option<i64>,
    pub max_origins: Option<i32>,
    pub connection_attempt_delay_ms: Option<i64>,
    pub max_response_body_bytes: Option<i64>,
    /// If absent, requests go over HTTP/3 to the origin.
    pub web_gateway: Option<CoreWebGateway>,
}

#[derive(uniffi::Record)]
pub struct CoreRequest {
    pub method: String,
    pub url: String,
    pub headers: Vec<CoreHeader>,
    pub body: Vec<u8>,
    /// Total time budget. 0 uses the client default.
    pub timeout_ms: u64,
}

#[derive(uniffi::Enum)]
pub enum CoreHttpVersion {
    Http11,
    Http3,
}

/// A response with its body collected.
#[derive(uniffi::Record)]
pub struct CoreResponse {
    pub status: u16,
    pub version: CoreHttpVersion,
    pub headers: Vec<CoreHeader>,
    pub body: Vec<u8>,
}

/// `flat_error` keeps the variants free of fields. A field named `message`
/// collides with `Throwable.message` in the generated Kotlin.
#[derive(Debug, thiserror::Error, uniffi::Error)]
#[uniffi(flat_error)]
pub enum CoreError {
    #[error("invalid argument: {message}")]
    InvalidArgument { message: String },
    #[error("cannot build SCION connectivity: {message}")]
    Connectivity { message: String },
    #[error("cannot resolve: {message}")]
    Resolution { message: String },
    #[error("cannot connect: {message}")]
    Connect { message: String },
    #[error("TLS failure: {message}")]
    Tls { message: String },
    #[error("connect timed out: {message}")]
    ConnectTimeout { message: String },
    #[error("timed out: {message}")]
    Timeout { message: String },
    #[error("HTTP failure: {message}")]
    Protocol { message: String },
    #[error("response body too large: {message}")]
    BodyTooLarge { message: String },
    #[error("client is closed")]
    Closed,
    #[error("cancelled")]
    Cancelled,
    #[error("{message}")]
    Internal { message: String },
}

impl CoreError {
    pub(crate) fn invalid(message: String) -> Self {
        CoreError::InvalidArgument { message }
    }
}
