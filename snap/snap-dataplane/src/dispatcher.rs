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
//! SCION packet dispatcher trait.

use sciparse::packet::view::ScionPacketView;

/// The dispatcher trait is used to dispatch SCION packets to the appropriate handlers within the
/// SNAP (and pocketscion) data plane.
pub trait Dispatcher: Sync + Send {
    /// Try to dispatch the given SCION packet.
    fn try_dispatch(&self, packet: &ScionPacketView);
}
