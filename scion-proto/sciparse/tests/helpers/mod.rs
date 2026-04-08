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

//! Shared test helpers for SCION protocol property tests.
//!
//! - [`header`]: [`valid::ValidHeaderOptions`] and [`exec_every_view_function`] for
//!   [`ScionHeaderView`].
//! - [`scmp`]: [`ValidScmpMessageOptions`] and [`exec_every_view_function`] for
//!   [`ScmpPayloadView`].
//! - [`udp`]: [`exec_every_view_function`] for [`UdpDatagramView`].

pub mod header;
pub mod scmp;
pub mod udp;
