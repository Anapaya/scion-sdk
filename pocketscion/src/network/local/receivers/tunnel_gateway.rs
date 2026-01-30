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
//! Tunnel gateway receiver.

use scion_sdk_token_validator::validator::Token;
use serde::Deserialize;
use snap_dataplane::{
    dispatcher::Dispatcher,
    tunnel_gateway_deprecated::dispatcher::TunnelGatewayDispatcherDeprecated,
};

use crate::network::local::receivers::Receiver;

/// Wrapper around the TunnelGatewayDispatcher to implement the Receiver trait.
pub struct TunnelGatewayReceiver<T>
where
    T: for<'de> Deserialize<'de> + Token,
{
    dispatcher: TunnelGatewayDispatcherDeprecated<T>,
}
impl<T> TunnelGatewayReceiver<T>
where
    T: for<'de> Deserialize<'de> + Token,
{
    /// Creates a new TunnelGatewayReceiver with the given dispatcher.
    pub fn new(dispatcher: TunnelGatewayDispatcherDeprecated<T>) -> Self {
        Self { dispatcher }
    }
}

impl<T> Receiver for TunnelGatewayReceiver<T>
where
    T: for<'de> Deserialize<'de> + Token,
{
    fn receive_packet(&self, packet: scion_proto::packet::ScionPacketRaw) {
        self.dispatcher.try_dispatch(packet);
    }
}
