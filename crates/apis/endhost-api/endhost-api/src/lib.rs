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
//! # SCION Endhost API
//!
//! Connect RPC API endpoint handlers and utilities to embed the endhost API into an existing
//! [`axum::Router`].
//!
//! ## Basic Usage
//!
//! ```no_run
//! use std::{net::SocketAddr, sync::Arc};
//!
//! use endhost_api::routes::nest_endhost_api;
//! use endhost_api_models::{SegmentsDiscovery, UnderlayDiscovery};
//! use tokio::net::TcpListener;
//!
//! struct MyUnderlayService;
//! impl UnderlayDiscovery for MyUnderlayService {
//!     fn list_underlays(
//!         &self,
//!         request_as: sciparse::identifier::isd_asn::IsdAsn,
//!     ) -> endhost_api_models::underlays::Underlays {
//!         todo!();
//!     }
//! }
//!
//! struct MySegmentsService;
//! #[async_trait::async_trait]
//! impl SegmentsDiscovery for MySegmentsService {
//!     async fn list_segments(
//!         &self,
//!         request_as: sciparse::identifier::isd_asn::IsdAsn,
//!         dst: sciparse::identifier::isd_asn::IsdAsn,
//!         page_size: i32,
//!         page_token: String,
//!     ) -> Result<sciparse::segment::SegmentsPage, endhost_api_models::SegmentsError> {
//!         todo!();
//!     }
//! }
//!
//! # async {
//! let base_router = axum::Router::<()>::new();
//! let router = nest_endhost_api(
//!     base_router,
//!     Arc::new(MyUnderlayService),
//!     Arc::new(MySegmentsService),
//! );
//!
//! let listener = TcpListener::bind(SocketAddr::from(([127, 0, 0, 1], 0)))
//!     .await
//!     .unwrap();
//! axum::serve(listener, router.into_make_service())
//!     .await
//!     .unwrap();
//! # };
//! ```

pub mod routes;
