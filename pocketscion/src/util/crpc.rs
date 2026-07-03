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

//! CRCP helpers for PocketSCION.

pub mod client {
    //! CRPC client helper for PocketSCION.

    use std::{sync::Arc, time::Duration};

    use anyhow::{Context, bail};
    use scion_sdk_quic_scion::quic::config::QuicConfig;
    use scion_sdk_scion_connect_rpc::client::CrpcClient;
    use sciparse::{address::ip_socket_addr::ScionSocketIpAddr, identifier::isd_asn::IsdAsn};

    use crate::{
        comp::sim_network_stack::{NetSimPathProvider, NetSimStack},
        network::scion::trust_store::StoreCertificateDer,
        util::cert_tmp_dir::CertificateTempDir,
    };

    /// Helper to create a CRPC client working within the network simulator
    pub struct PsCrpcClient;
    impl PsCrpcClient {
        /// Connects to a CRPC server at the given destination ISD-AS and socket address, using the
        /// provided network stack, path provider, and certificate chain.
        pub async fn connect(
            timeout: Duration,
            network_stack: &NetSimStack,
            dst_ia: IsdAsn,
            dst_addr: std::net::SocketAddr,
            path_provider: impl NetSimPathProvider,
            cert_chain: &[StoreCertificateDer],
            cert_temp_dir: &CertificateTempDir,
        ) -> anyhow::Result<CrpcClient> {
            // Create cert chain file for destination AS
            let _ = cert_temp_dir
                .get_or_create_cert_file(cert_chain)
                .context("Failed to get certificate path for destination ISD-AS")?;

            let quic_config = QuicConfig {
                // Peer validation is disabled in general
                verify_peer: false,
                ca_certs_directory: Some(
                    cert_temp_dir
                        .temp_dir_path()
                        .to_str()
                        .context("Failed to convert certificate temp directory path to string")?
                        .to_owned(),
                ),
                ..Default::default()
            };

            let socket = network_stack
                .bind_udp(0)
                .context("Failed to bind UDP socket for CRPC client")?
                .into_path_aware(path_provider);

            let socket = Arc::new(socket);

            let client_fut = CrpcClient::with_quic_config(
                ScionSocketIpAddr::new(dst_ia, dst_addr.ip(), dst_addr.port()),
                socket,
                None, // XXX: Peer validation is disabled
                None,
                quic_config,
            );

            let client = match tokio::time::timeout(timeout, client_fut).await {
                Ok(Ok(client)) => client,
                Ok(Err(e)) => bail!("Failed to create CRPC client: {e}"),
                Err(_) => bail!("Timed out while creating CRPC client"),
            };

            Ok(client)
        }
    }
}
