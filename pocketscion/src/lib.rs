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

//! Pocket SCION is a SCION network simulator.
//!
//! To create a PocketSCION simulation, create a
//! [PocketScionRuntimeBuilder](runtime::builder::PocketScionRuntimeBuilder) and configure the
//! desired state.
//!
//! Pocketscion is split into:
//! - [io_config::IoConfig]: Host specific Network Address configuration.
//! - [state::PocketScionState]: The global state of the PocketSCION simulation
//! - [comp]: The components that implement the logic of components of the simulation, e.g. APIs
//! - [runtime::PocketScionRuntime]: The running PocketSCION simulation, which provides an API to
//!   interact with the simulation.
//! - [util]: Utility functions and types used across the PocketSCION codebase.
//! - [network]: SCION network simulation code, including topology and path management.
//!
//! As a user you can use:
//! - [io_config::IoConfig] to configure the network addresses are used by the simulation to
//!   interact with your host.
//! - [state::PocketScionState] to configure the simulation, e.g. add ASes, links, and components to
//!   the simulation.
//! - [runtime::PocketScionRuntime] to start the simulation and interact with it while it's running.
//!
//! Example usage can be found in the tests and in the [util::topologies] module, which contains
//! example topologies that can be used in tests.

pub mod comp;
pub mod io_config;
pub mod network;
pub mod runtime;
pub mod state;
pub mod util;
