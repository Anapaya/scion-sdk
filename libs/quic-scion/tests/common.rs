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

//! Shared test utilities.

use anyhow::Context;
use pocketscion::topologies::{IA132, IA212, PocketScionHandle};
use scion_sdk_quic_scion::quic::config::QuicConfig;
use scion_stack::scionstack::{ScionStackBuilder, SocketConfig, UdpScionSocket};
use snap_tokens::v0::dummy_snap_token;
use tempfile::NamedTempFile;

/// Setup a client and server socket in two different ASes in the pocket SCION topology.
pub async fn setup_sockets(
    ps_handle: &PocketScionHandle,
) -> anyhow::Result<(UdpScionSocket, UdpScionSocket)> {
    // Client
    let client_stack = ScionStackBuilder::new()
        .with_endhost_api(ps_handle.endhost_api(IA132).await.unwrap())
        .with_auth_token(dummy_snap_token())
        .build()
        .await
        .context("build client SCION stack")?;

    let client_socket = client_stack
        .bind_with_config(None, SocketConfig::default())
        .await
        .context("bind client SCION socket")?;

    // Server
    let server_stack = ScionStackBuilder::new()
        .with_endhost_api(ps_handle.endhost_api(IA212).await.unwrap())
        .with_auth_token(dummy_snap_token())
        .build()
        .await
        .context("build server SCION stack")?;

    let server_socket = server_stack
        .bind_with_config(None, SocketConfig::default())
        .await
        .context("bind server SCION socket")?;

    Ok((client_socket, server_socket))
}

/// Generates a self-signed certificate and corresponding private key for testing purposes.
pub fn generate_server_config() -> (squiche::Config, NamedTempFile, NamedTempFile) {
    let config = QuicConfig::builder().verify_peer(false).build();

    let mut config = config.to_quiche_config().unwrap();

    let cert = rcgen::generate_simple_self_signed(vec!["localhost".to_string()]).unwrap();
    let cert_pem = cert.cert.pem();
    let key_pem = cert.signing_key.serialize_pem();

    let mut cert_file = tempfile::NamedTempFile::new().unwrap();
    let mut key_file = tempfile::NamedTempFile::new().unwrap();

    use std::io::Write;
    cert_file
        .as_file_mut()
        .write_all(cert_pem.as_bytes())
        .unwrap();
    key_file
        .as_file_mut()
        .write_all(key_pem.as_bytes())
        .unwrap();

    config
        .load_cert_chain_from_pem_file(cert_file.path().to_str().unwrap())
        .unwrap();
    config
        .load_priv_key_from_pem_file(key_file.path().to_str().unwrap())
        .unwrap();

    (config, cert_file, key_file)
}
