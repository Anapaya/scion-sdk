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

//! Builds the transport that a [`Config`] describes.

use std::sync::Arc;

use anapaya_aa_client::AnapayaAaTokenSource;
use scion_http3::{
    Client, Config as ClientConfig,
    scion_quic::quic::config::{QuicConfig, QuicConfigBuilder},
    scion_stack::ea_source::StaticEndhostApiDiscovery,
};

use super::{
    config::{Config, TokenSource, Trust},
    platform,
    transport::{
        Transport,
        connect::{ConnectTransport, OriginTrust},
        http3::Http3Transport,
    },
};
use crate::ffi::types::CoreError;

/// Builds the transport without waiting on the network.
///
/// Call it inside the runtime context. Some parts spawn a task at once, for
/// example the AA token source its refresh task.
pub(crate) fn transport(config: Config) -> Result<Arc<dyn Transport>, CoreError> {
    // rustls refuses to build a TLS config before a provider is installed.
    scion_sdk_utils::rustls::select_ring_crypto_provider();

    // With a gateway, the origin trust moves to the TLS session inside the
    // tunnel. The QUIC connection to the gateway skips the peer check.
    let (quic, gateway) = match &config.web_gateway {
        None => (quic_config(&config.origin_trust), None),
        Some(gateway) => {
            let trust = match config.origin_trust.clone() {
                Trust::Platform => OriginTrust::Platform(platform::cert_verifier()),
                Trust::Anchors(pem) => OriginTrust::Anchors(pem),
                Trust::None => OriginTrust::None,
            };
            (
                QuicConfig::builder().verify_peer(false),
                Some((gateway.clone(), trust)),
            )
        }
    };

    // Build the transport.
    let max_body_bytes = config.max_response_body_bytes;
    let idle_timeout = config.idle_timeout;
    let request_timeout = config.request_timeout;
    let client = Arc::new(Client::new(client_config(config, quic)?));
    let transport: Arc<dyn Transport> = match gateway {
        None => Arc::new(Http3Transport::new(client, max_body_bytes)),
        Some((gateway, trust)) => {
            Arc::new(ConnectTransport::new(
                client,
                gateway,
                trust,
                idle_timeout,
                request_timeout,
                max_body_bytes,
            )?)
        }
    };
    return Ok(transport);

    fn quic_config(trust: &Trust) -> QuicConfigBuilder {
        match trust {
            Trust::Platform => platform::quic_config(),
            Trust::Anchors(pem) => QuicConfig::builder().ca_certs_pem(pem.clone()),
            Trust::None => QuicConfig::builder().verify_peer(false),
        }
    }
}

enum Auth {
    Static(String),
    AnapayaAa(AnapayaAaTokenSource),
}

/// The scion-http3 config.
fn client_config(config: Config, quic: QuicConfigBuilder) -> Result<ClientConfig, CoreError> {
    let control_plane = config.control_plane;
    let cp_client = control_plane.as_ref().map(|trust| trust.client.clone());

    // Set up authentication.
    let auth = match config.token_source {
        None => None,
        Some(TokenSource::Static(token)) => Some(Auth::Static(token)),
        Some(TokenSource::AnapayaAa {
            url,
            api_key,
            device_id,
        }) => {
            let source = match &control_plane {
                Some(trust) => {
                    AnapayaAaTokenSource::new_with_client_builder(
                        api_key,
                        &url,
                        device_id,
                        trust.builder(),
                    )
                }
                None => AnapayaAaTokenSource::new(api_key, &url, device_id),
            };
            Some(Auth::AnapayaAa(source.map_err(|error| {
                CoreError::invalid(format!("bad AA config: {error:#}"))
            })?))
        }
    };
    let aa = match &auth {
        Some(Auth::AnapayaAa(aa)) => Some(aa),
        _ => None,
    };

    // Without a fixed endhost API, discover through the AA, else globally.
    let mut out = match config.endhost_api {
        Some(url) => ClientConfig::new(url),
        None => {
            match (aa, cp_client.clone()) {
                (Some(aa), Some(client)) => {
                    ClientConfig::from_endhost_api_source(
                        aa.endhost_api_source().with_http_client(client),
                    )
                }
                (Some(aa), None) => ClientConfig::from_endhost_api_source(aa.endhost_api_source()),
                (None, Some(client)) => {
                    ClientConfig::from_endhost_api_source(
                        StaticEndhostApiDiscovery::global().with_http_client(client),
                    )
                }
                (None, None) => {
                    ClientConfig::from_endhost_api_source(StaticEndhostApiDiscovery::global())
                }
            }
        }
    };

    out = out
        .with_quic_config(quic.build())
        .with_connect_timeout(config.connect_timeout)
        .with_request_timeout(config.request_timeout)
        .with_idle_connection_timeout(config.idle_timeout)
        .with_max_origins(config.max_origins)
        .with_connection_attempt_delay(config.connection_attempt_delay);
    if let Some(underlay) = config.preferred_underlay {
        out = out.with_preferred_underlay(underlay);
    }

    for (host, addresses) in config.dns_overrides {
        out = out.with_dns_override(host, addresses);
    }

    out = match auth {
        Some(Auth::Static(token)) => out.with_auth_token(token),
        Some(Auth::AnapayaAa(aa)) => out.with_auth_token_source(aa),
        None => out,
    };

    // Use the anchors for the control plane.
    if let Some(client) = cp_client {
        out = out.with_stack_customizer(move |builder| builder.with_crpc_client(client.clone()));
    }

    Ok(out)
}
