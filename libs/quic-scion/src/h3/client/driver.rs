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

//! HTTP/3 driver for H3 requests and events.

use std::{collections::HashMap, ops::Deref, sync::Arc};

use squiche::h3::NameValue;
use thiserror::Error;
use tokio::sync::{Mutex, oneshot};

use crate::{
    client::QuicConnection,
    h3::client::request::{H3Request, H3Response},
};

/// UDP packet buffer size.
const UDP_PACKET_BUFFER_SIZE: usize = 65535;

/// Maximum body buffer size.
const MAX_BODY_BUFFER_SIZE: usize = 16 * 1024 * 1024; // 16 MB

/// State for a pending H3 request.
pub struct PendingRequest {
    response_tx: oneshot::Sender<H3Reply>,
    status: Option<http::StatusCode>,
    headers: Vec<(String, String)>,
    body: Vec<u8>,
}

/// H3 reply sent back to the requester.
#[derive(Debug)]
pub enum H3Reply {
    /// Successful result.
    Result {
        /// The HTTP/3 response.
        response: H3Response,
    },
    /// Underlying connection was closed.
    ConnectionClosed,
    /// Underlying connection was reset with an error code.
    ConnectionReset(u64),
}

/// Shared state for the H3 connection.
pub struct H3State {
    /// The HTTP/3 connection.
    pub h3_conn: squiche::h3::Connection,
    /// Pending requests mapped by stream ID.
    pub pending_requests: HashMap<u64, PendingRequest>,
}

/// The HTTP/3 driver processing requests and handling h3 events.
#[derive(Clone)]
pub struct H3Connection {
    state: Arc<Mutex<H3State>>,
    quic_conn: QuicConnection,
}

/// Error sending an H3 request.
#[derive(Debug, Error, PartialEq, Eq)]
pub enum H3SendRequestError {
    /// Failed to send H3 request.
    #[error("failed to send request: {0}")]
    SendRequestError(squiche::h3::Error),
    /// Failed to send H3 body.
    #[error("failed to send body: {0}")]
    SendBodyError(squiche::h3::Error),
}

impl H3Connection {
    /// Checks if the underlying QUIC connection is closed.
    pub async fn is_closed(&self) -> bool {
        let conn = self.quic_conn.conn.lock().await;
        conn.is_closed()
    }

    /// Sends an H3 request over this active connection.
    pub async fn send_h3_request(
        &self,
        request: H3Request,
    ) -> Result<oneshot::Receiver<H3Reply>, H3SendRequestError> {
        let headers = request.to_quiche_headers();
        let has_body = request.body.is_some();

        let stream_id = {
            let mut conn = self.quic_conn.conn.lock().await;
            let mut state = self.state.lock().await;
            state
                .h3_conn
                .send_request(&mut conn, &headers, !has_body)
                .map_err(H3SendRequestError::SendRequestError)?
        };

        tracing::trace!(
            stream_id,
            method = %request.method,
            path = %request.path,
            "Sent H3 request"
        );

        if let Some(ref body) = request.body {
            let mut sent_bytes = 0;
            while sent_bytes < body.len() {
                let res = {
                    let mut conn = self.quic_conn.conn.lock().await;
                    let mut state = self.state.lock().await;
                    state
                        .h3_conn
                        .send_body(&mut conn, stream_id, &body[sent_bytes..], true)
                };

                match res {
                    Ok(written) => sent_bytes += written,
                    Err(squiche::h3::Error::Done) => break,
                    Err(e) => return Err(H3SendRequestError::SendBodyError(e)),
                }
            }
        }

        let (tx, rx) = oneshot::channel();
        let mut state = self.state.lock().await;
        state.pending_requests.insert(
            stream_id,
            PendingRequest {
                response_tx: tx,
                status: None,
                headers: vec![],
                body: vec![],
            },
        );

        Ok(rx)
    }
}

/// The HTTP/3 driver handling h3 events and dispatching replies back to the requester.
#[derive(Clone)]
pub struct H3Driver(H3Connection);

impl Deref for H3Driver {
    type Target = H3Connection;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl H3Driver {
    /// Creates a new H3Driver.
    pub async fn new(quic_conn: QuicConnection) -> Result<Self, squiche::h3::Error> {
        let config = squiche::h3::Config::new().expect("no fail");

        let h3_conn = {
            let mut conn = quic_conn.conn.lock().await;
            squiche::h3::Connection::with_transport(&mut conn, &config)?
        };

        let state = Arc::new(Mutex::new(H3State {
            h3_conn,
            pending_requests: HashMap::new(),
        }));

        let h3_connection = H3Connection {
            state: state.clone(),
            quic_conn,
        };

        Ok(Self(h3_connection))
    }

    /// Returns the underlying H3Connection.
    pub fn h3_connection(&self) -> H3Connection {
        self.0.clone()
    }

    /// Run the event handler loop.
    pub async fn run(self) {
        loop {
            tokio::select! {
                // Received QUIC packet, try polling H3 events
                _ = self.quic_conn.waiter.notified() => {
                    self.handle_h3_events().await;
                }
            }

            // Check if the underlying QUIC connection is closed
            {
                let conn = self.0.quic_conn.conn.lock().await;
                if conn.is_closed() {
                    tracing::warn!(stats=?conn.stats(),"Connection closed, shutting down H3 driver");
                    break;
                }
            }
        }

        let mut state = self.state.lock().await;
        for (_, pending) in state.pending_requests.drain() {
            let _ = pending.response_tx.send(H3Reply::ConnectionClosed);
        }
    }

    async fn handle_h3_events(&self) {
        loop {
            let res = {
                let mut conn = self.quic_conn.conn.lock().await;
                let mut state = self.state.lock().await;
                state.h3_conn.poll(&mut conn)
            };

            match res {
                Ok((stream_id, event)) => {
                    tracing::trace!(?stream_id, ?event, "Received H3 event");
                    self.handle_h3_event(stream_id, event).await;
                }
                Err(squiche::h3::Error::Done) => break,
                Err(err) => {
                    tracing::warn!(?err, "Failed to poll H3 events");
                    break;
                }
            }
        }
    }

    async fn handle_h3_event(&self, stream_id: u64, event: squiche::h3::Event) {
        match event {
            squiche::h3::Event::Headers { list, .. } => {
                let mut state = self.state.lock().await;
                if let Some(pending) = state.pending_requests.get_mut(&stream_id) {
                    for header in &list {
                        let name = String::from_utf8_lossy(header.name()).to_string();
                        let value = String::from_utf8_lossy(header.value()).to_string();

                        if name == ":status" {
                            pending.status = value.parse().ok();
                        } else if !name.starts_with(':') {
                            pending.headers.push((name, value));
                        }
                    }
                }
            }
            squiche::h3::Event::Data => {
                let mut state = self.state.lock().await;
                let H3State {
                    ref mut h3_conn,
                    ref mut pending_requests,
                } = *state;

                if let Some(pending) = pending_requests.get_mut(&stream_id) {
                    let mut buf = [0u8; UDP_PACKET_BUFFER_SIZE];
                    loop {
                        let res = {
                            let mut conn = self.quic_conn.conn.lock().await;
                            h3_conn.recv_body(&mut conn, stream_id, &mut buf)
                        };

                        match res {
                            Ok(len) => {
                                if pending.body.len() + len > MAX_BODY_BUFFER_SIZE {
                                    tracing::warn!(
                                        stream_id,
                                        "Response body too large, truncating"
                                    );
                                    break;
                                }
                                // XXX(bunert): This forces the entire body to be buffered in
                                // memory. For large responses we need a streaming body interface.
                                pending.body.extend_from_slice(&buf[..len]);
                            }
                            Err(squiche::h3::Error::Done) => break,
                            Err(err) => {
                                tracing::warn!(?err, stream_id, "Failed to receive H3 body");
                                break;
                            }
                        }
                    }
                }
            }
            squiche::h3::Event::Finished => {
                let mut state = self.state.lock().await;
                if let Some(pending) = state.pending_requests.remove(&stream_id) {
                    let response = H3Response {
                        status: pending
                            .status
                            .unwrap_or(http::StatusCode::INTERNAL_SERVER_ERROR),
                        headers: pending.headers,
                        body: pending.body,
                    };
                    if let Err(err) = pending.response_tx.send(H3Reply::Result { response }) {
                        // The receiver might have been dropped.
                        tracing::debug!(?err, "Failed to send H3 response to requester");
                    }
                }
            }
            squiche::h3::Event::Reset(error_code) => {
                let mut state = self.state.lock().await;
                if let Some(pending) = state.pending_requests.remove(&stream_id)
                    && let Err(err) = pending
                        .response_tx
                        .send(H3Reply::ConnectionReset(error_code))
                {
                    tracing::debug!(?err, "Failed to send connection reset to the requester");
                }
            }
            squiche::h3::Event::GoAway => {
                tracing::warn!("Received connection go away event");
            }
            squiche::h3::Event::PriorityUpdate => {
                tracing::debug!(stream_id, "Received priority update event, ignoring");
            }
        }
    }
}
