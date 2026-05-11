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

//! HTTP/3 server over SCION transport.

use std::{collections::HashMap, sync::Arc};

use tokio::sync::{Mutex, Notify};

use crate::{
    UDP_PACKET_BUFFER_SIZE,
    h3::request::{H3Headers, H3Request},
    quic::server::{QuicServer, QuicServerConnection},
};

/// HTTP/3 server.
pub struct H3Server {
    quic_server: QuicServer,
}

impl H3Server {
    /// Creates a new HTTP/3 server.
    pub fn new(quic_server: QuicServer) -> Self {
        Self { quic_server }
    }

    /// Accepts the next incoming H3 connection.
    pub async fn accept(&mut self) -> Option<H3ServerConnection> {
        let conn = match self.quic_server.accept().await {
            Some(quic_conn) => quic_conn,
            None => return None,
        };

        let h3_conn = {
            // Wait until the connection is established
            let mut conn_locked = loop {
                let guard = conn.conn.lock().await;

                if guard.is_established() {
                    break guard;
                }
                drop(guard);
                tokio::task::yield_now().await;
            };

            // Check ALPN
            let alpn = conn_locked.application_proto().to_vec();

            // Check if the the application protocol of the connection is H3
            if alpn != b"h3" {
                // TODO: close connection?
                tracing::error!(?alpn, "Connection ALPN is not h3");
                return None;
            }

            // Create H3 config
            let h3_config = squiche::h3::Config::new().expect("default H3 config should be valid");
            match squiche::h3::Connection::with_transport(&mut conn_locked, &h3_config) {
                Ok(c) => c,
                Err(err) => {
                    tracing::error!(?err, "Failed to create H3 connection");
                    return None;
                }
            }
        };

        Some(H3ServerConnection {
            quic_conn: conn,
            h3_conn: Arc::new(Mutex::new(h3_conn)),
            partial_requests: HashMap::new(),
            buffer: vec![0u8; UDP_PACKET_BUFFER_SIZE],
        })
    }
}

/// A connection on the HTTP/3 server.
pub struct H3ServerConnection {
    quic_conn: QuicServerConnection,
    h3_conn: Arc<Mutex<squiche::h3::Connection>>,
    partial_requests: HashMap<u64, H3Request>,
    buffer: Vec<u8>,
}

impl H3ServerConnection {
    /// Polls the H3 connection until a new H3 request is received.
    pub async fn handle_request(&mut self) -> Option<(H3Request, H3ResponseSender)> {
        loop {
            // Process H3
            let event = {
                let mut quic = self.quic_conn.conn.lock().await;
                let mut h3 = self.h3_conn.lock().await;

                h3.poll(&mut quic)
            };

            match event {
                Ok((
                    stream_id,
                    squiche::h3::Event::Headers {
                        list: headers,
                        more_frames,
                    },
                )) => {
                    tracing::debug!(?stream_id, "Received H3 request headers");

                    let headers: H3Headers = match headers.try_into() {
                        Ok(headers) => headers,
                        Err(err) => {
                            tracing::warn!(?err, ?stream_id, "Failed to parse H3 request headers");
                            continue;
                        }
                    };
                    let req = H3Request {
                        headers,
                        body: None,
                    };

                    match more_frames {
                        true => {
                            self.partial_requests.insert(stream_id, req);
                            continue;
                        }
                        false => {
                            let sender = H3ResponseSender {
                                stream_id,
                                quic_conn: self.quic_conn.conn.clone(),
                                h3_conn: self.h3_conn.clone(),
                                waker: self.quic_conn.quic_rx_notifier.clone(),
                            };
                            return Some((req, sender));
                        }
                    }
                }
                Ok((stream_id, squiche::h3::Event::Data)) => {
                    tracing::debug!(?stream_id, "Receiving H3 request body");
                    if let Some(req) = self.partial_requests.get_mut(&stream_id) {
                        let res = {
                            let mut quic = self.quic_conn.conn.lock().await;
                            let mut h3 = self.h3_conn.lock().await;
                            h3.recv_body(&mut quic, stream_id, &mut self.buffer)
                        };
                        match res {
                            Ok(read) => {
                                // XXX(bunert): This forces the entire body to be buffered in
                                // memory. For large responses we need a streaming body interface
                                // and send the inbound body frames to the handler similar to
                                // tokio-quiche InboundFrame.
                                req.body
                                    .get_or_insert_with(Vec::new)
                                    .extend_from_slice(&self.buffer[..read]);
                            }
                            Err(squiche::h3::Error::Done) => continue,
                            Err(err) => {
                                tracing::warn!(
                                    ?err,
                                    ?stream_id,
                                    "Error receiving H3 request body on stream"
                                );
                                return None;
                            }
                        }
                    }
                }
                Ok((stream_id, squiche::h3::Event::Finished)) => {
                    tracing::debug!(?stream_id, "Finished receiving H3 request");
                    if let Some(req) = self.partial_requests.remove(&stream_id) {
                        let sender = H3ResponseSender {
                            stream_id,
                            quic_conn: self.quic_conn.conn.clone(),
                            h3_conn: self.h3_conn.clone(),
                            waker: self.quic_conn.quic_rx_notifier.clone(),
                        };
                        return Some((req, sender));
                    }
                }
                Ok((_stream_id, squiche::h3::Event::GoAway)) => {
                    tracing::warn!("Received GOAWAY from client, closing H3 connection");
                    return None;
                }
                Ok((stream_id, squiche::h3::Event::Reset(_))) => {
                    self.partial_requests.remove(&stream_id);
                }
                Ok((_stream_id, squiche::h3::Event::PriorityUpdate)) => {
                    tracing::warn!("Received PRIORITY_UPDATE, ignoring");
                }
                Err(squiche::h3::Error::Done) => {
                    tokio::task::yield_now().await;
                }
                Err(err) => {
                    tracing::error!(?err, "H3 connection error, closing connection");
                    return None;
                }
            }
        }
    }
}

/// Sender for HTTP/3 response.
pub struct H3ResponseSender {
    stream_id: u64,
    quic_conn: Arc<Mutex<squiche::Connection>>,
    h3_conn: Arc<Mutex<squiche::h3::Connection>>,
    waker: Arc<Notify>,
}

impl H3ResponseSender {
    /// Sends the response.
    pub async fn send_response(
        &mut self,
        status: http::StatusCode,
        body: &[u8],
    ) -> Result<(), squiche::h3::Error> {
        let headers = vec![squiche::h3::Header::new(
            b":status",
            status.as_u16().to_string().as_bytes(),
        )];

        let mut h3 = self.h3_conn.lock().await;
        let mut quic = self.quic_conn.lock().await;

        h3.send_response(&mut quic, self.stream_id, &headers, false)?;
        h3.send_body(&mut quic, self.stream_id, body, true)?;

        // Notify that there is new data to send. Can we get rid of that?
        self.waker.notify_one();

        Ok(())
    }
}
