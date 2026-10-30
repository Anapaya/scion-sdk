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

/// Returns a SNAP token that the SNAPs of a PocketSCION simulation accept.
///
/// An insecure constant key signs the token. That key pairs with the default SNAP token public key
/// of PocketSCION. The token stays valid for one day. Do **not** use it against a real SCION
/// network.
///
/// The examples get their tokens from the [PocketSCION AA](crate::comp::aa) through
/// [`PocketScionAaTokenSource`](crate::comp::aa::PocketScionAaTokenSource) instead, in the same way
/// as an application on a real SCION network gets them from a production AA. Use this helper where
/// a fixed token is enough, for example in a test.
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
