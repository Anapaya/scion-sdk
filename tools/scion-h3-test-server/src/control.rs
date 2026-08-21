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

//! The control API: plain HTTP over TCP, beside the HTTP/3 server rather than on it.
//!
//! It is deliberately not SCION and not HTTP/3, so that a client being tested never has to reach it
//! through the code under test. A harness asks it what the server has seen and tells it to do
//! things the client cannot provoke.

use std::{net::SocketAddr, sync::Arc};

use axum::{
    Router,
    extract::State,
    http::StatusCode,
    response::{IntoResponse, Response},
    routing::{get, post},
};
use pocketscion::io_config::IoConfig;
use tokio::net::TcpListener;
use tokio_util::sync::CancellationToken;

use crate::{app::Counters, server::Http3Server};

/// A bound control API, before it serves anything.
///
/// Binding and serving are separate because the address is part of what `GET /info` reports, and
/// that description cannot be assembled until the port is known.
pub struct ControlListener {
    listener: TcpListener,
    url: String,
}

/// Binds the control API on `port`, which may be zero for an ephemeral one.
///
/// It binds where the topology's components bind, and reports that address unchanged. The
/// advertised addresses belong to an AS and this belongs to none: it is not part of the topology,
/// and a harness on another host reaches it by whatever route it was told to, which is not this
/// process's to guess.
pub async fn bind(io_config: &IoConfig, port: u16) -> std::io::Result<ControlListener> {
    let listener = TcpListener::bind(SocketAddr::new(io_config.default_bind_ip(), port)).await?;
    let url = format!("http://{}", listener.local_addr()?);
    Ok(ControlListener { listener, url })
}

impl ControlListener {
    /// Where a harness reaches the control API.
    pub fn url(&self) -> &str {
        &self.url
    }

    /// Starts serving, in a task of its own, until `shutdown` is cancelled.
    pub fn serve(
        self,
        counters: Arc<Counters>,
        server: Arc<Http3Server>,
        description: serde_json::Value,
        shutdown: CancellationToken,
    ) {
        let state = Arc::new(ControlState {
            counters,
            server,
            description,
        });
        let app = Router::new()
            .route("/stats", get(stats))
            .route("/info", get(info))
            .route("/restart-server", post(restart_server))
            .with_state(state);

        tokio::spawn(async move {
            let served = axum::serve(self.listener, app)
                .with_graceful_shutdown(async move { shutdown.cancelled().await })
                .await;
            if let Err(error) = served {
                tracing::error!(%error, "The control server stopped");
            }
        });
    }
}

struct ControlState {
    counters: Arc<Counters>,
    server: Arc<Http3Server>,
    description: serde_json::Value,
}

async fn stats(State(state): State<Arc<ControlState>>) -> Response {
    axum::Json(state.counters.snapshot()).into_response()
}

/// The same object the process prints on standard output when it starts.
///
/// Reading it here rather than from that line is what lets a harness that did not start the process
/// discover it: an instrumented test on a device has no standard output to read, only an address
/// and a port it was told at build time.
async fn info(State(state): State<Arc<ControlState>>) -> Response {
    axum::Json(state.description.clone()).into_response()
}

async fn restart_server(State(state): State<Arc<ControlState>>) -> Response {
    match state.server.restart().await {
        Ok(()) => {
            state.counters.record_restart();
            StatusCode::OK.into_response()
        }
        Err(error) => {
            tracing::error!(%error, "Failed to restart the HTTP/3 server");
            (StatusCode::INTERNAL_SERVER_ERROR, error.to_string()).into_response()
        }
    }
}
