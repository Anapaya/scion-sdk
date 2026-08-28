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

//! Connect RPC API of the WAP control plane.
//!
//! Serves the `anapaya.wap.v1.WapControl` service defined in
//! `protobuf/anapaya/wap/v1/control_service.proto`, split into three parts:
//!
//! * [`model`] - One model per message of the service, plus the
//!   [`ControlServiceAPIHandler`](model::ControlServiceAPIHandler) that serves them.
//! * [`convert`] - Translation between the protobuf messages and their models.
//! * [`api`] - The endpoints, and [`api::nest_crpc_api`] to serve them on a router.

pub mod api;
pub mod convert;
pub mod model;
