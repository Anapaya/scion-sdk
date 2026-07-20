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

//! Pocket SCION network simulation
//!
//! The network simulation is split in three parts:
//!
//! 1. `scion` contains the SCION network simulation, including the topology and the SCION routers.
//! 2. `local` contains the local network simulation, which simulates Scion Routers and IP routing
//!    within the ASes.
//! 3. `simulator` which combines the SCION and local network simulations and provides an interface
//!    to send packets through the simulated network.
//!
//! The network simulators are designed to be useable independently of the rest of PocketSCION.
//! They do not depend directly on the PocketSCION state and its locking mechanism.

pub mod local;
pub mod scion;
pub mod simulator;
