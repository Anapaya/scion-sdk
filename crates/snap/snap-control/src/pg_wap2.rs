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

//! PathGuard WAP SNAP extension.
//!
//! The WAP control plane is assembled from four components:
//!
//! * [`auth::AuthService`] - Manages which client IPs are authorized for which targets and
//!   segments, and when those authorizations expire.
//! * [`segments::SegmentManager`] -  Keeps public segments for the (src, dst) pairs in use fresh.
//! * [`paths::PathManager`] -  Combines public and granted segments into the single best path, and
//!   reports which segments it used.
//! * [`uplinks::UplinkManager`] - Creates and manages one uplink per (path, WAG) pair, multiplexes
//!   SNI streams over it, refreshes its path, cleans it when unused or closed.
//!
//! ## Time
//!
//! Every operation that depends on the current time takes it as a `now: SystemTime` argument, so
//! all the decisions taken while serving one connection can be made against a single timestamp
//! instead of drifting apart as the clock moves under them.
//!
//! The `run` maintenance loops are the exception: they own their cadence, so they read the wall
//! clock themselves.

pub mod auth;
pub mod paths;
pub mod segments;
pub mod sni;
pub mod uplinks;

#[cfg(test)]
mod test_util;

/// Sketch of how the Control Plane should be used in a single client connection.
/// Can be removed when everything is implemented
#[allow(dead_code)]
#[allow(clippy::unit_arg)]
mod sketch {

    use crate::pg_wap2::{
        auth::AuthService,
        paths::PathManager,
        segments::SegmentManager,
        sni::WapSNI,
        uplinks::{GenericUplink, UplinkEstablisher, UplinkManager},
    };

    /// The WAP control plane
    pub struct WAPControlPlane<Establisher: UplinkEstablisher> {
        /// Decides which client IP may reach which target over which private segments.
        pub auth: AuthService,
        /// Public segments for all (src, dst) pairs currently in use.
        pub segments: SegmentManager,
        /// Combines public and granted segments into paths.
        pub paths: PathManager,
        /// Uplinks towards the WAGs, keyed by the (path, WAG) pair they were established for.
        pub uplinks: UplinkManager<Establisher>,
    }

    use std::{net::IpAddr, time::SystemTime};

    use anyhow::Context;
    use sciparse::{
        address::{ip_socket_addr::ScionSocketIpAddr, socket_addr::ScionSocketAddr},
        identifier::isd_asn::IsdAsn,
        path::ScionPath,
    };
    use tokio::select;
    use tokio_util::sync::CancellationToken;

    /// Sketch of how the primitives fit together for a single client connection.
    async fn main_loop_proto(cp: &WAPControlPlane<MockDataplane>) -> anyhow::Result<()> {
        const CFG_LOCAL_AS: IsdAsn = IsdAsn(1);

        let client_tcp_stream = ();
        let client_ip = IpAddr::V4(std::net::Ipv4Addr::new(192, 168, 1, 1));

        // One timestamp for the whole setup, so every decision below is taken against the same
        // view of what is authorized and what has expired.
        let now = SystemTime::now();

        if !cp.auth.ip_is_authorized(client_ip, now) {
            anyhow::bail!("Client IP {} is not authorized", client_ip);
        }

        let sni = tls_extract_sni_from_connection(client_tcp_stream)
            .await
            .context("Failed to extract SNI from connection")?;

        let gateway_domain = sni.gateway_domain();
        let dst_addr: ScionSocketIpAddr = resolve_tsar(gateway_domain.as_str())
            .await
            .context("Failed to resolve TSAR for SNI")?
            .try_to_scion_sock_ip_addr()
            .context("TSAR did not resolve to a SCION socket IP address")?;

        // Select the path this client should take
        let used_path = cp
            .paths
            .best_path(client_ip, &sni, CFG_LOCAL_AS, dst_addr.isd_asn(), now)
            .await
            .context("Failed to get best path")?
            .context("No path found")?;

        // Establish the uplink stream to the WAG for this client.
        let mut up_stream = cp
            .uplinks
            .establish_stream(client_ip, &sni, used_path, dst_addr, now)
            .await
            .context("Failed to establish uplink stream")?;

        let forward_future = start_forwarding(
            client_ip,
            &sni,
            up_stream
                .take_stream()
                .expect("stream has already been taken"),
            client_tcp_stream,
        );

        select! {
            // Forwarding future completes, e.g. because the client closed the connection.
            _ = forward_future => {
                tracing::info!("Forwarding future completed");
            }
            // Must close when any of the grants that authorize the path expire, so the client cannot use it anymore.
            _ = up_stream.grant_expired() => {
                tracing::info!(%client_ip, %sni, "Authorization lost, closing connection");
            }
            // Must close when the uplink is closed, so the client cannot use it anymore.
            _ = up_stream.uplink_closed() => {
                tracing::info!(%client_ip, %sni, "Uplink was closed, closing connection");
            }
        }

        Ok(())
    }

    async fn resolve_tsar(_sni: &str) -> anyhow::Result<ScionSocketAddr> {
        todo!()
    }

    async fn tls_extract_sni_from_connection(_client_tcp_stream: ()) -> anyhow::Result<WapSNI> {
        todo!()
    }

    async fn start_forwarding(
        _client_ip: IpAddr,
        _sni: &WapSNI,
        _uplink_stream: <MockUplink as GenericUplink>::StreamType,
        _client_stream: (),
    ) -> anyhow::Result<()> {
        todo!()
    }
    /// A stand-in for whatever the dataplane opens uplinks on.
    struct MockDataplane;

    #[async_trait::async_trait]
    impl UplinkEstablisher for MockDataplane {
        type Uplink = MockUplink;

        async fn establish_connection(
            &self,
            _path: ScionPath,
            _dst_addr: ScionSocketIpAddr,
            _closed: CancellationToken,
        ) -> anyhow::Result<Self::Uplink> {
            todo!("Implement the uplink connection establishment")
        }
    }

    /// A stand-in for the dataplane uplink, used to sketch out the control plane flow.
    struct MockUplink;

    #[async_trait::async_trait]
    impl GenericUplink for MockUplink {
        type StreamType = ();

        async fn establish_stream(&self, _dst_sni: &WapSNI) -> anyhow::Result<Self::StreamType> {
            todo!("Implement the uplink stream establishment")
        }

        fn replace_path(&self, _new_path: ScionPath) -> anyhow::Result<()> {
            todo!("Implement the uplink path replacement")
        }
    }
}
