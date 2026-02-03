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

//! HTTP/3 client over SCION transport.

pub mod driver;
pub mod request;

use std::{borrow::Cow, sync::Arc};

use scion_proto::address::SocketAddr;
use scion_stack::scionstack::UdpScionSocket;
use thiserror::Error;
use tokio::sync::Mutex;

use crate::{
    client::{QuicConfig, QuicConnection, QuicConnectionError},
    h3::client::{
        driver::{H3Connection, H3Driver, H3Reply},
        request::{H3Request, H3Response},
    },
};

/// HTTP/3 client.
#[derive(Clone)]
pub struct H3Client {
    // QUIC connection information
    remote: SocketAddr,
    server_name: Option<String>,
    socket: Arc<UdpScionSocket>,

    // H3 connection if established
    connection: Arc<Mutex<Option<H3Connection>>>,
}

/// Request error
#[derive(Debug, Error)]
pub enum RequestError {
    /// Connection error
    #[error("connection error: {0}")]
    H3ConnectionError(#[from] H3ConnectionError),
    /// Error sending the request.
    #[error("send request error: {0}")]
    H3RequestError(#[from] driver::H3SendRequestError),
    /// Connection closed
    #[error("connection closed")]
    ConnectionClosed,
    /// Connection reset
    #[error("connection reset: {0}")]
    ConnectionReset(u64),
    /// Internal error
    #[error("internal error: {0}")]
    InternalError(Cow<'static, str>),
}

impl H3Client {
    /// Creates a new HTTP/3 client.
    pub async fn new(
        remote: SocketAddr,
        socket: Arc<UdpScionSocket>,
        server_name: Option<String>,
    ) -> Result<Self, H3ConnectionError> {
        let client = Self {
            remote,
            server_name,
            socket,
            connection: Arc::new(Mutex::new(None)),
        };

        client.get_connection().await?;

        Ok(client)
    }

    /// Send an HTTP/3 request.
    ///
    /// If the connection is closed or missing, it will attempt to re-establish it automatically.
    pub async fn request(&self, req: H3Request) -> Result<H3Response, RequestError> {
        // Attempt to get a valid connection
        let conn = self.get_connection().await?;

        // Try the request with the current connection
        match self.perform_request_attempt(&conn, req.clone()).await {
            Ok(res) => Ok(res),
            Err(RequestError::ConnectionClosed) => {
                // Establish a new connection
                let new_conn = self.get_connection().await?;

                // Re-try the request
                self.perform_request_attempt(&new_conn, req).await
            }
            Err(e) => Err(e),
        }
    }

    async fn perform_request_attempt(
        &self,
        conn: &H3Connection,
        req: H3Request,
    ) -> Result<H3Response, RequestError> {
        let reply_rx = conn.send_h3_request(req).await?;

        // Await the response from the H3 driver.
        match reply_rx.await {
            Ok(rep) => {
                match rep {
                    H3Reply::Result { response } => Ok(response),
                    H3Reply::ConnectionReset(err_code) => {
                        Err(RequestError::ConnectionReset(err_code))
                    }
                    H3Reply::ConnectionClosed => Err(RequestError::ConnectionClosed),
                }
            }
            Err(err) => {
                // XXX(bunert): This should not happen unless the H3 driver task exited
                // unexpectedly.
                tracing::warn!(?err, "Failed to receive response from H3 driver");
                Err(RequestError::InternalError(Cow::Owned(format!(
                    "Failed to receive H3 response: {}",
                    err
                ))))
            }
        }
    }

    /// Gets the current connection or establishes a new one if none exists.
    async fn get_connection(&self) -> Result<H3Connection, H3ConnectionError> {
        let mut guard = self.connection.lock().await;

        // Return existing connection if existing and not closed.
        if let Some(conn) = &*guard
            && !conn.is_closed().await
        {
            return Ok(conn.clone());
        }

        // Establish a new connection
        let active_conn = self.establish_connection().await?;
        *guard = Some(active_conn.clone());
        Ok(active_conn)
    }

    /// Establishes a new HTTP/3 connection.
    async fn establish_connection(&self) -> Result<H3Connection, H3ConnectionError> {
        let config = QuicConfig::default()
            .to_quiche_config()
            .expect("default config is valid");
        let conn = QuicConnection::new(
            self.server_name.clone(),
            self.remote,
            self.socket.clone(),
            config,
        )
        .await?;

        let h3_driver = H3Driver::new(conn.clone()).await?;
        let h3_connection = h3_driver.h3_connection();

        // Spawn the driver task
        tokio::spawn(h3_driver.run());

        Ok(h3_connection)
    }
}

/// HTTP/3 connection error.
#[derive(Debug, Error)]
pub enum H3ConnectionError {
    /// QUIC connection error.
    #[error("QUIC connection error: {0}")]
    QuicConnectionError(#[from] QuicConnectionError),
    /// H3 driver error.
    #[error("HTTP/3 driver error: {0}")]
    H3DriverError(#[from] squiche::h3::Error),
}
