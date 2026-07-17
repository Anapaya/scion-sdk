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
//! SCION stack SCMP handlers.

#[cfg(test)]
use mockall::automock;

pub mod echo;
pub mod error;

pub use echo::DefaultEchoHandler;
pub(crate) use error::ScmpErrorHandler;
use sciparse::{
    dataplane_path::view::ScionDpPathViewRef,
    packet::{model::ScionRawPacket, view::ScionRawPacketView},
    payload::scmp::model::ScmpErrorMessage,
};

/// Trait for SCMP handlers that can process incoming raw SCION packets and optionally return a
/// reply packet.
/// Sending of the reply is best effort (`try_send`).
pub trait ScmpHandler: Send + Sync {
    /// Handles an incoming SCMP packet and returns a reply packet if applicable.
    fn handle(&self, pkt: &ScionRawPacketView) -> Option<ScionRawPacket>;
}

/// Trait for reporting path issues.
#[cfg_attr(test, automock)]
pub trait ScmpErrorReceiver: Send + Sync {
    /// Reports a SCMP error. This function must return immediately and not block.
    ///
    /// # Arguments
    ///
    /// * `scmp_error` - The SCMP error to report.
    /// * `path` - The path that the SCMP error was received on (not reversed).
    // The explicit lifetime is required by `mockall`'s `automock` code generation.
    #[allow(clippy::needless_lifetimes, clippy::elidable_lifetime_names)]
    fn report_scmp_error<'a>(&self, scmp_error: ScmpErrorMessage, path: ScionDpPathViewRef<'a>);
}

// Note: `mockall` will generate `MockScmpErrorReceiver` for tests in this module.
