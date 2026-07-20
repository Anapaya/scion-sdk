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

//! Shared utility functions

pub(crate) mod cert_tmp_dir;

/// Returns a SNAP authentication token accepted by a PocketSCION simulation.
///
/// PocketSCION does not verify SNAP tokens, so any well-formed token is accepted. This helper
/// returns one so that examples and quick experiments can build a `ScionStack` against the
/// simulation without pulling in `snap-tokens` themselves. Do **not** use it against a real SCION
/// network.
pub fn dev_auth_token() -> String {
    snap_tokens::v0::dummy_snap_token()
}
pub mod crpc;
pub mod path_providers;
pub mod serde_ext;
pub mod topologies;

/// Transform a [`std::net::SocketAddr`] into a [`url::Url`].
pub fn addr_to_http_url(addr: std::net::SocketAddr) -> url::Url {
    match addr {
        std::net::SocketAddr::V4(addr) => {
            url::Url::parse(&format!("http://{addr}"))
                .expect("It is safe to format a SocketAddr as a URL")
        }
        std::net::SocketAddr::V6(addr) => {
            url::Url::parse(&format!("http://[{}]:{}", addr.ip(), addr.port()))
                .expect("It is safe to format a SocketAddr as a URL")
        }
    }
}

/// Transform a [`std::net::SocketAddr`] into a [`url::Url`].
pub fn addr_to_https_url(addr: std::net::SocketAddr) -> url::Url {
    match addr {
        std::net::SocketAddr::V4(addr) => {
            url::Url::parse(&format!("https://{addr}"))
                .expect("It is safe to format a SocketAddr as a URL")
        }
        std::net::SocketAddr::V6(addr) => {
            url::Url::parse(&format!("https://[{}]:{}", addr.ip(), addr.port()))
                .expect("It is safe to format a SocketAddr as a URL")
        }
    }
}
