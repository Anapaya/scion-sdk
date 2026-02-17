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

//! SCMP (SCION Control Message Protocol) payload views, layouts, and models.

/// Encoding support for SCMP models.
pub mod encode;
/// Layout definitions for SCMP messages (bit ranges and sizes).
pub mod layout;
pub mod model;
/// Types and enums used by SCMP messages (e.g. codes and message types).
pub mod types;
/// Zero-copy views over SCMP messages and headers.
pub mod view;

/// SCION protocol number for SCMP.
///
/// See the [IETF SCION-dataplane RFC draft][rfc] for possible values.
///
///[rfc]: https://www.ietf.org/archive/id/draft-dekater-scion-dataplane-00.html#protnum
pub const SCMP_PROTOCOL_NUMBER: u8 = 202;
