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
//! SNAP tunnel management.

use std::{net::SocketAddr, sync::Arc, time::Duration};

use bytes::Bytes;
use quinn::{TransportConfig, crypto::rustls::QuicClientConfig};
use rustls::ClientConfig;
use scion_proto::address::EndhostAddr;
use snap_control::{client::ControlPlaneApi, crpc_api::api_service::model::SessionGrant};
use snap_tun::client::{
    AutoSessionRenewal, DEFAULT_RENEWAL_WAIT_THRESHOLD, SnapTunError, TokenRenewError,
};
use tracing::{debug, instrument};

/// Default SNAP data plane session token renewer.
pub struct DefaultTokenRenewer {
    snap_cp_client: Arc<dyn ControlPlaneApi>,
    snap_dp_addr: SocketAddr,
}

impl DefaultTokenRenewer {
    /// Creates a new token renewer.
    pub fn new(snap_cp_client: Arc<dyn ControlPlaneApi>, snap_dp_addr: SocketAddr) -> Self {
        DefaultTokenRenewer {
            snap_cp_client,
            snap_dp_addr,
        }
    }

    /// Renews the SNAP data plane session token.
    pub async fn renew(&self) -> Result<String, TokenRenewError> {
        let grant = self
            .snap_cp_client
            .renew_data_plane_session(self.snap_dp_addr)
            .await
            .map_err(|e| Box::new(e) as TokenRenewError)?;
        Ok(grant.token)
    }
}

/// Configuration for automatic session renewal.
#[derive(Clone)]
pub struct SessionRenewal {
    renewal_wait_threshold: std::time::Duration,
}

impl Default for SessionRenewal {
    fn default() -> Self {
        SessionRenewal {
            renewal_wait_threshold: DEFAULT_RENEWAL_WAIT_THRESHOLD,
        }
    }
}

impl SessionRenewal {
    /// Creates a new session renewal configuration.
    pub fn new(renewal_wait_threshold: std::time::Duration) -> Self {
        SessionRenewal {
            renewal_wait_threshold,
        }
    }
}

/// SNAP tunnel.
pub struct SnapTunnel {
    sender: snap_tun::client::Sender,
    receiver: snap_tun::client::Receiver,
    ctrl: snap_tun::client::Control,
}

impl SnapTunnel {
    /// Creates a new SNAP tunnel.
    ///
    /// # Arguments
    ///
    /// * `session_grant` - The session grant for the SNAP data plane.
    /// * `api_client` - The SNAP control plane API client.
    /// * `requested_addresses` - The addresses to request from the SNAP server. If empty, the SNAP
    ///   server will assign an address.
    /// * `auto_session_renewal` - If set, the SNAP data plane session will be automatically
    ///   renewed.
    #[instrument(name = "snap_tunnel", skip_all, fields(target_addr = %session_grant.address))]
    pub async fn new(
        session_grant: &SessionGrant,
        api_client: Arc<dyn ControlPlaneApi>,
        requested_addresses: Vec<EndhostAddr>,
        auto_session_renewal: Option<SessionRenewal>,
    ) -> Result<Self, SnapTunnelError> {
        let (cert_der, _config) = scion_sdk_utils::test::generate_cert(
            [42u8; 32],
            vec!["localhost".into()],
            vec![b"snaptun".to_vec()],
        );
        let mut roots = rustls::RootCertStore::empty();
        roots.add(cert_der).unwrap();
        let mut client_crypto = ClientConfig::builder()
            .with_root_certificates(roots)
            .with_no_client_auth();
        client_crypto.alpn_protocols = vec![b"snaptun".to_vec()];

        let mut transport_config = TransportConfig::default();
        // 5 secs == 1/6 default idle timeout
        transport_config.keep_alive_interval(Some(Duration::from_secs(5)));

        // XXX: on windows, GSO is known to cause trouble depending on the
        // combination of network drivers, configuration, etc.
        #[cfg(target_os = "windows")]
        transport_config.enable_segmentation_offload(false);

        let transport_config_arc = Arc::new(transport_config);
        let mut client_config =
            quinn::ClientConfig::new(Arc::new(QuicClientConfig::try_from(client_crypto).unwrap()));
        client_config.transport_config(transport_config_arc);

        // Create a client endpoint.
        let mut client_endpoint = quinn::Endpoint::client("0.0.0.0:0".parse().unwrap())?;
        client_endpoint.set_default_client_config(client_config);

        // Connect to the server.
        let conn = client_endpoint
            .connect(session_grant.address, "localhost")?
            .await?;

        let mut client_builder = snap_tun::client::ClientBuilder::new(session_grant.token.clone())
            .with_desired_addresses(requested_addresses);

        // Use automatic session renewal.
        if let Some(auto_session_renewal) = auto_session_renewal {
            let addr = session_grant.address;
            let token_renewer_fn: snap_tun::client::TokenRenewFn = Box::new(move || {
                let token_renewer = DefaultTokenRenewer::new(api_client.clone(), addr);
                Box::pin(async move { token_renewer.renew().await })
            });
            client_builder = client_builder.with_auto_session_renewal(AutoSessionRenewal::new(
                auto_session_renewal.renewal_wait_threshold,
                token_renewer_fn,
            ));
        }

        let (sender, receiver, ctrl) = client_builder.connect(conn).await?;

        debug!(
            addr=%ctrl.assigned_addresses().iter().map(|a| a.to_string()).collect::<Vec<String>>().join(", "),
            "Snap tunnel established.",
        );

        Ok(Self {
            sender,
            receiver,
            ctrl,
        })
    }

    /// Sends a datagram.
    pub fn send_datagram(&self, data: Bytes) -> Result<(), quinn::SendDatagramError> {
        self.sender.send_datagram(data)
    }

    /// Sends a datagram and waits for it to be sent.
    pub async fn send_datagram_wait(&self, data: Bytes) -> Result<(), quinn::SendDatagramError> {
        self.sender.send_datagram_wait(data).await
    }

    /// Reads a datagram from the SNAP tunnel.
    pub async fn read_datagram(&self) -> Result<Bytes, SnapTunnelError> {
        self.receiver
            .read_datagram()
            .await
            .map_err(SnapTunnelError::from)
    }

    /// Returns the addresses assigned by the SNAP tunnel.
    pub fn assigned_addresses(&self) -> Vec<EndhostAddr> {
        self.ctrl.assigned_addresses()
    }

    /// Returns when the underlying connection is closed.
    pub async fn closed(&self) {
        let _ = self.ctrl.closed().await;
    }

    /// This is a helper function that returns a debug-printable object
    /// containing metrics about the underlying QUIC-connection.
    // XXX(dsd): We are overcautious here and do not want to commit to an
    // implementation-specific type.
    pub fn debug_path_stats(&self) -> impl std::fmt::Debug {
        self.ctrl.debug_path_stats()
    }
}

/// SNAP tunnel errors.
#[derive(thiserror::Error, Debug)]
pub enum SnapTunnelError {
    // TODO: quinn uses many different error types, need a better abstraction
    // here.
    /// QUIC connect error.
    #[error("connect error: {0}")]
    QuicConnectError(#[from] quinn::ConnectError),
    /// QUIC connection error.
    #[error("connection error: {0}")]
    QuicConnectionError(#[from] quinn::ConnectionError),
    /// QUIC connect timeout.
    #[error("connecting timeout")]
    QuicConnectTimeout,
    /// SNAP tunnel client error.
    #[error("SNAP tunnel client error: {0}")]
    ClientError(#[from] SnapTunError),
    /// I/O error.
    #[error("i/o error: {0}")]
    IoError(#[from] std::io::Error),
}
