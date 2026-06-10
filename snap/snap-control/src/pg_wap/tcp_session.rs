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
//! Pathguard WAP TCP session management.

use std::{borrow::Cow, net::SocketAddr};

/// TCP session commands that can be sent to a [TcpSessionHandle] to control the session.
pub enum TcpSessionCommand {
    /// Terminate the TCP session.
    Terminate {
        /// Reason for the termination, used for logging and debugging purposes.
        reason: Cow<'static, str>,
    },
}

/// Handle to a TCP session, allowing to send commands to the session and observe its shared state.
pub struct TcpSessionHandle {
    /// Source address of the TCP session, used for logging and debugging purposes.
    pub src_addr: SocketAddr,
    /// Channel to send commands to the TCP session task.
    pub tx: tokio::sync::mpsc::Sender<TcpSessionCommand>,
    /// Watch channel to observe the shared state of the TCP session.
    pub shared: tokio::sync::watch::Receiver<TcpSessionSharedState>,
}

impl TcpSessionHandle {
    /// Send a command to terminate the TCP session with the given reason.
    pub fn close(&self, reason: impl Into<Cow<'static, str>>) {
        // Terminate only improves the error message, so try is good enough here.
        let _ = self.tx.try_send(TcpSessionCommand::Terminate {
            reason: reason.into(),
        });
    }
}
impl std::fmt::Debug for TcpSessionHandle {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "TcpSessionHandle {{ ... }}")
    }
}

/// Shared state of a TCP session.
pub enum TcpSessionSharedState {
    /// The session is waiting for the TLS handshake to complete.
    WaitingForTlsHandshake,
    /// The session is in the process of establishing the uplink connection.
    EstablishingUplink {
        /// The SNI extracted from the TLS ClientHello.
        sni: String,
    },
    /// The session has successfully established the uplink connection and is now proxying data.
    Established {
        /// The SNI extracted from the TLS ClientHello.
        sni: String,
    },
    /// The session has been closed, either by the client or by the server, or due to an error.
    Closed {
        /// Reason for the session closure.
        reason: Cow<'static, str>,
    },
}
