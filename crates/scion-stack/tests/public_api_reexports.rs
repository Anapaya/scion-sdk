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

//! Compile-time guard pinning the set of crates re-exported from `scion-stack`'s root.
//!
//! Every crate whose types appear in `scion-stack`'s public API is re-exported from the crate root
//! (see the "Re-exported dependencies" block in `src/lib.rs`) so that clients need not add a direct
//! dependency to name or construct those types. This test names each re-export through the
//! `scion_stack::...` path, so removing or renaming one breaks the build here — a reminder that
//! doing so is a breaking change for downstream clients.
//!
//! It does NOT prove the *absence* of new accidental leaks — Rust has no reflection to enumerate
//! the foreign types in the public API, so that stays a code-review responsibility (see the
//! "Dependency exposure" section of `API_CONVENTIONS.md`). This test only guarantees the
//! intentional re-exports stay put.

// Third-party crates deliberately part of the public API.
// SDK workspace crates deliberately part of the public API.
use scion_stack::{
    anapaya_ead_models, endhost_api_client, hickory_resolver, reqwest, reqwest_connect_rpc,
    scion_quic, sciparse, url, x25519_dalek,
};

#[test]
fn reexports_are_reachable() {
    // Name one representative type from each re-exported crate. If a re-export is dropped, this
    // file fails to compile.
    type _Url = url::Url;
    type _ResolverBuilder =
        hickory_resolver::ResolverBuilder<hickory_resolver::name_server::TokioConnectionProvider>;
    type _Client = reqwest::Client;
    type _StaticSecret = x25519_dalek::StaticSecret;

    type _ScionSocketIpAddr = sciparse::address::ip_socket_addr::ScionSocketIpAddr;
    type _TokenSource = dyn reqwest_connect_rpc::token_source::TokenSource;
    type _EndhostApiClient = dyn endhost_api_client::client::EndhostApiClient;
    type _EndhostApiGroup = anapaya_ead_models::EndhostApiGroup;
    type _BoxedSocketError = scion_quic::socket::BoxedSocketError;
}
