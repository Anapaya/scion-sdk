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

use std::{collections::HashSet, net::SocketAddr, sync::Arc, time::Duration};

use bytes::Bytes;
use quinn::{TransportConfig, crypto::rustls::QuicClientConfig};
use rustls::ClientConfig;
use scion_proto::address::EndhostAddr;
use scion_sdk_utils::backoff::ExponentialBackoff;
use snap_control::{client::ControlPlaneApi, crpc_api::api_service::model::SessionGrant};
use snap_tun::client::{
    AutoSessionRenewal, ClientBuilder, DEFAULT_RENEWAL_WAIT_THRESHOLD, SnapTunError,
    TokenRenewError,
};
use tracing::instrument;

const MINIMUM_DELAY_SECS: f32 = 0.1;
const MAXIMUM_DELAY_SECS: f32 = 10.0;
const FACTOR: f32 = 1.2;
const JITTER_SECS: f32 = 0.1;

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
    /// Threshold for waiting for the next renewal of the session token.
    pub renewal_wait_threshold: std::time::Duration,
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

struct SnapTunConnection {
    sender: snap_tun::client::Sender,
    receiver: snap_tun::client::Receiver,
    ctrl: snap_tun::client::Control,
}

/// SNAP tunnel.
pub struct SnapTunnel {
    state: tokio::sync::watch::Receiver<SnapTunConnection>,
    conn_driver: Option<tokio::task::JoinHandle<()>>,
}

struct ConnFactory {
    data_plane_addr: SocketAddr,
    data_plane_server_name: String,
    endpoint: quinn::Endpoint,
    auto_session_renewal: AutoSessionRenewal,
}

impl ConnFactory {
    pub async fn new_connection(
        &self,
        desired_addresses: Vec<EndhostAddr>,
    ) -> Result<SnapTunConnection, SnapTunnelError> {
        let conn = self
            .endpoint
            .connect(self.data_plane_addr, &self.data_plane_server_name)?
            .await?;
        // XXX(uniquefine): We always request a new session token here.
        // We should refactor this to only request a new token when the last connection attempt
        // failed due to an expired session token.
        let session_token = (self.auto_session_renewal.token_renewer)()
            .await
            .map_err(|e| SnapTunnelError::ClientError(SnapTunError::InitialTokenError(e)))?;
        let client_builder = ClientBuilder::new(session_token)
            .with_desired_addresses(desired_addresses)
            .with_auto_session_renewal(self.auto_session_renewal.clone());
        let (sender, receiver, ctrl) = client_builder.connect(conn).await?;
        Ok(SnapTunConnection {
            sender,
            receiver,
            ctrl,
        })
    }
}

struct SnapTunnelDriver<F> {
    /// Function to create a new SNAP tunnel connection.
    new_connection_func: F,
    /// The addresses that were requested by the user.
    requested_addresses: Vec<EndhostAddr>,
    /// Union of all addresses that were ever assigned by the SNAP server.
    assigned_addresses: Vec<EndhostAddr>,
    current_connection: tokio::sync::watch::Sender<SnapTunConnection>,
}

impl<F: AsyncFn(Vec<EndhostAddr>) -> Result<SnapTunConnection, SnapTunnelError> + Send + Sync>
    SnapTunnelDriver<F>
{
    /// Creates a new SNAP tunnel driver. This will establish the initial connection to the SNAP
    /// server.
    pub async fn new(
        requested_addresses: Vec<EndhostAddr>,
        new_connection: F,
    ) -> Result<(Self, tokio::sync::watch::Receiver<SnapTunConnection>), SnapTunnelError> {
        let initial_connection = new_connection(requested_addresses.clone()).await?;
        let assigned_addresses = initial_connection.ctrl.assigned_addresses();
        let (sender, receiver) = tokio::sync::watch::channel(initial_connection);
        Ok((
            Self {
                new_connection_func: new_connection,
                requested_addresses,
                assigned_addresses,
                current_connection: sender,
            },
            receiver,
        ))
    }

    /// Main loop to drive the SNAP tunnel reconnection logic.
    /// The main loop will never exit on it's own.
    /// If the connection is interrupted, the main loop will attempt to reconnect indefinitely.
    pub async fn main_loop(self) {
        let backoff =
            ExponentialBackoff::new(MINIMUM_DELAY_SECS, MAXIMUM_DELAY_SECS, FACTOR, JITTER_SECS);
        loop {
            // Wait for the current connection to be closed.
            // It's fine to keep the ref around for a while. This task is the only writer.
            let conn = self.current_connection.borrow().ctrl.inner_conn();
            let _ = conn.closed().await;
            let mut attempt = 0;
            let new_connection = loop {
                match (self.new_connection_func)(self.addresses_to_request()).await {
                    Ok(new_connection) => {
                        break new_connection;
                    }
                    Err(e) => {
                        tracing::debug!(error=%e,%attempt, "failed to reconnect snaptun");
                    }
                };
                tokio::time::sleep(backoff.duration(attempt)).await;
                attempt += 1;
            };
            self.current_connection.send_replace(new_connection);
        }
    }

    /// We need to request both user requested addresses and the
    /// addresses that were assigned by the SNAP server once.
    fn addresses_to_request(&self) -> Vec<EndhostAddr> {
        HashSet::<EndhostAddr>::from_iter(
            self.requested_addresses
                .iter()
                .chain(self.assigned_addresses.iter())
                .cloned(),
        )
        .into_iter()
        .collect()
    }
}

/// Send handle for the SNAP tunnel.
#[derive(Clone)]
pub struct SnapTunnelSender {
    current_connection: tokio::sync::watch::Receiver<SnapTunConnection>,
}

impl SnapTunnelSender {
    /// Sends a datagram to the SNAP tunnel. This function will attempt to send a datagram
    /// immediately. If the underlying connection is closed, the function will return an error.
    pub fn send_datagram(&self, data: Bytes) -> Result<(), quinn::SendDatagramError> {
        self.current_connection
            .borrow()
            .sender
            .clone()
            .send_datagram(data)
    }

    /// Sends a datagram to the SNAP tunnel and waits for the datagram to be sent.
    /// If the underlying connection is closed, the function will return an error.
    pub async fn send_datagram_wait(&self, data: Bytes) -> Result<(), quinn::SendDatagramError> {
        let sender = self.current_connection.borrow().sender.clone();
        sender.send_datagram_wait(data).await
    }
}

/// Receive handle for the SNAP tunnel.
#[derive(Clone)]
pub struct SnapTunnelReceiver {
    current_connection: tokio::sync::watch::Receiver<SnapTunConnection>,
}

impl SnapTunnelReceiver {
    /// Reads a datagram from the SNAP tunnel. This function will block until a datagram is
    /// received. If the underlying connection is closed, the function will wait for it
    /// to be re-established.
    /// This function must take a mutable reference to update the current_connection.
    /// Clone to share it with multiple receivers.
    pub async fn read_datagram(&mut self) -> Result<Bytes, quinn::ConnectionError> {
        loop {
            let receiver = self.current_connection.borrow_and_update().receiver.clone();
            match receiver.read_datagram().await {
                Ok(data) => return Ok(data),
                Err(
                    e @ (quinn::ConnectionError::ApplicationClosed(_)
                    | quinn::ConnectionError::ConnectionClosed(_)),
                ) => {
                    tracing::debug!("Snaptun connection is closed, reconnecting");
                    if self.current_connection.changed().await.is_err() {
                        return Err(e);
                    };
                    continue;
                }
                Err(e) => return Err(e),
            }
        }
    }
}

impl SnapTunnel {
    /// Creates a new SNAP tunnel and establishes an initial connection.
    ///
    /// # Arguments
    ///
    /// * `session_grant` - The session grant for the SNAP data plane.
    /// * `api_client` - The SNAP control plane API client.
    /// * `requested_addresses` - The addresses to request from the SNAP server. If empty, the SNAP
    ///   server will assign an address.
    /// * `auto_session_renewal` - If set, the SNAP data plane session will be automatically
    ///   renewed.
    #[instrument(name = "snaptun", skip_all, fields(target_addr = %initial_session_grant.address))]
    pub async fn new(
        initial_session_grant: &SessionGrant,
        api_client: Arc<dyn ControlPlaneApi>,
        requested_addresses: Vec<EndhostAddr>,
        auto_session_renewal: SessionRenewal,
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

        let conn_factory = ConnFactory {
            data_plane_addr: initial_session_grant.address,
            data_plane_server_name: "localhost".to_string(),
            endpoint: client_endpoint,
            auto_session_renewal: {
                let addr = initial_session_grant.address;
                let token_renewer_fn: snap_tun::client::TokenRenewFn = Arc::new(move || {
                    let token_renewer = DefaultTokenRenewer::new(api_client.clone(), addr);
                    Box::pin(async move { token_renewer.renew().await })
                });
                AutoSessionRenewal::new(
                    auto_session_renewal.renewal_wait_threshold,
                    token_renewer_fn,
                )
            },
        };

        let (conn_driver, conn_receiver) = SnapTunnelDriver::new(
            requested_addresses,
            Box::new(async move |desired_addresses| {
                conn_factory.new_connection(desired_addresses).await
            }),
        )
        .await?;

        tracing::debug!(
            addr=%conn_driver.assigned_addresses.iter().map(|a| a.to_string()).collect::<Vec<String>>().join(", "),
            "Snap tunnel established.",
        );
        let driver_handle = tokio::spawn(async move { conn_driver.main_loop().await });

        Ok(Self {
            state: conn_receiver,
            conn_driver: Some(driver_handle),
        })
    }

    /// Returns a sender for the SNAP tunnel.
    pub fn sender(&self) -> SnapTunnelSender {
        SnapTunnelSender {
            current_connection: self.state.clone(),
        }
    }

    /// Returns a receiver for the SNAP tunnel.
    pub fn receiver(&self) -> SnapTunnelReceiver {
        SnapTunnelReceiver {
            current_connection: self.state.clone(),
        }
    }

    /// Returns the addresses assigned to the current snap tunnel.
    /// This could change when the SNAP tunnel is re-established.
    pub fn assigned_addresses(&self) -> Vec<EndhostAddr> {
        self.state.borrow().ctrl.assigned_addresses()
    }

    /// This is a helper function that returns a debug-printable object
    /// containing metrics about the underlying QUIC-connection.
    // XXX(dsd): We are overcautious here and do not want to commit to an
    // implementation-specific type.
    pub fn debug_path_stats(&self) -> impl std::fmt::Debug + 'static + use<> {
        self.state.borrow().ctrl.debug_path_stats()
    }
}

impl Drop for SnapTunnel {
    fn drop(&mut self) {
        if let Some(driver_handle) = self.conn_driver.take() {
            driver_handle.abort();
        }
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
