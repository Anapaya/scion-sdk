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

//! Pocket SCION components.
//!
//! Each component maps to a specific feature of PocketSCION, and is responsible for managing the
//! state related to that feature.
//!
//! All features directly depend on the [PocketScionState](crate::state::PocketScionState) as their
//! source of truth.
//!
//! The PocketScionState can be seen as a database that holds the state of the simulation, and the
//! components are responsible for managing specific parts of that state and implementing the logic
//! related to that state.

pub mod authorization_server;
pub mod control_service;
pub mod daemon;
pub mod endhost_api;
pub mod endhost_api_discovery;
pub mod endhost_segment_lister;
pub mod external_as;
pub mod network_forwarder;
pub mod network_simulation;
pub mod router;
pub mod sim_network_stack;
pub mod simulation_dispatcher;
pub mod snap;
