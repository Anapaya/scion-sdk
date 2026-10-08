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

//! The Kotlin API: one [`TestNetwork`] per topology.
//!
//! Each network owns a tokio runtime of its own, so [`TestNetwork::stop`]
//! stops every task of the topology. The calls block. A test starts a network
//! once, so a blocking start costs nothing there.

use std::{
    collections::HashMap,
    net::SocketAddr,
    sync::{Mutex, PoisonError},
    time::Duration,
};

use pocketscion::util::topologies::UnderlayType;
use tokio::runtime::Runtime;

use crate::topology::{Options, Topology};

/// How long [`TestNetwork::stop`] waits for the tasks of the topology.
const SHUTDOWN_TIMEOUT: Duration = Duration::from_secs(5);

/// How the client and the server enter the network. Each AS gets a router
/// that they reach over UDP, or a SNAP.
#[derive(uniffi::Enum)]
pub enum TestUnderlay {
    Udp,
    Snap,
}

/// What a network starts with.
#[derive(uniffi::Record)]
pub struct TestNetworkOptions {
    pub underlay: TestUnderlay,
    /// `CONNECT` authorities, as `host` or `host:port`, to TCP backends as
    /// `ip:port`.
    pub gateway_backends: HashMap<String, String>,
}

/// What a client and a server of the user need to reach the network.
#[derive(Clone, uniffi::Record)]
pub struct TestNetworkDescription {
    /// The endhost API of AS 1-ff00:0:132, for the client.
    pub endhost_api_url: String,
    /// The endhost API of AS 2-ff00:0:212, for a server of the user.
    pub server_endhost_api_url: String,
    /// The token for both endhost APIs and the SNAP control plane.
    pub auth_token: String,
    /// The SCION address of every server in AS 2-ff00:0:212 on this host,
    /// without a port.
    pub server_address: String,
    /// The port of the built-in server, and of the gateway in it.
    pub gateway_port: u16,
    /// `https://localhost:<port>`, the built-in test API.
    pub test_api_url: String,
    /// The CA of the built-in server.
    pub test_api_ca_pem: String,
    /// A CA that signs no certificate of the network.
    pub untrusted_ca_pem: String,
}

// `flat_error` keeps the variants free of fields. A field named `message`
// collides with `Throwable.message` in the generated Kotlin.
#[derive(Debug, thiserror::Error, uniffi::Error)]
#[uniffi(flat_error)]
pub enum TestNetworkError {
    #[error("invalid options: {message}")]
    InvalidOptions { message: String },
    #[error("cannot start the network: {message}")]
    Start { message: String },
}

/// A running topology.
#[derive(uniffi::Object)]
pub struct TestNetwork {
    running: Mutex<Option<Running>>,
    description: TestNetworkDescription,
}

struct Running {
    runtime: Runtime,
    topology: Topology,
}

#[uniffi::export]
impl TestNetwork {
    /// Starts the topology and returns once it serves.
    #[uniffi::constructor]
    pub fn start(options: TestNetworkOptions) -> Result<Self, TestNetworkError> {
        let options = Options {
            underlay: match options.underlay {
                TestUnderlay::Udp => UnderlayType::Udp,
                TestUnderlay::Snap => UnderlayType::Snap,
            },
            gateway_backends: parse_backends(options.gateway_backends)?,
        };

        // Start the topology on its own runtime.
        let runtime = tokio::runtime::Builder::new_multi_thread()
            .enable_all()
            .thread_name("ktor-scion-testing")
            .build()
            .map_err(|error| start_error(&error))?;
        let topology = runtime
            .block_on(Topology::start(options))
            .map_err(|error| start_error(&*error))?;

        // Describe it for Kotlin.
        let description = TestNetworkDescription {
            endhost_api_url: topology.endhost_api_url().to_owned(),
            server_endhost_api_url: topology.server_endhost_api_url().to_owned(),
            auth_token: topology.auth_token(),
            server_address: topology.target().to_owned(),
            gateway_port: topology.port(),
            test_api_url: topology.base_url(),
            test_api_ca_pem: topology.ca_pem().to_owned(),
            untrusted_ca_pem: topology.wrong_ca_pem().to_owned(),
        };
        return Ok(TestNetwork {
            running: Mutex::new(Some(Running { runtime, topology })),
            description,
        });

        fn parse_backends(
            backends: HashMap<String, String>,
        ) -> Result<HashMap<String, SocketAddr>, TestNetworkError> {
            backends
                .into_iter()
                .map(|(authority, target)| {
                    let parsed = target.parse().map_err(|error| {
                        TestNetworkError::InvalidOptions {
                            message: format!(
                                "bad backend address {target} for {authority}: {error}"
                            ),
                        }
                    })?;
                    Ok((authority, parsed))
                })
                .collect()
        }

        fn start_error(error: &dyn std::error::Error) -> TestNetworkError {
            // Append each cause.
            let mut message = error.to_string();
            let mut source = error.source();
            while let Some(cause) = source {
                message.push_str(": ");
                message.push_str(&cause.to_string());
                source = cause.source();
            }

            TestNetworkError::Start { message }
        }
    }

    pub fn description(&self) -> TestNetworkDescription {
        self.description.clone()
    }

    /// Stops the topology. A second call does nothing.
    pub fn stop(&self) {
        let running = self
            .running
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .take();
        if let Some(Running { runtime, topology }) = running {
            // The topology drops its tasks, and that needs the runtime.
            let entered = runtime.enter();
            drop(topology);
            drop(entered);
            runtime.shutdown_timeout(SHUTDOWN_TIMEOUT);
        }
    }
}

impl Drop for TestNetwork {
    fn drop(&mut self) {
        self.stop();
    }
}
