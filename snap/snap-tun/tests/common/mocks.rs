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

use std::{
    collections::HashMap,
    sync::{Arc, Mutex},
    time::Instant,
};

use ana_gotatun::x25519::PublicKey;
use mockall::mock;
use scion_sdk_reqwest_connect_rpc::client::CrpcClientError;
use snap_tun::{client::SnapTunNgControlPlaneClient, server::SnapTunAuthorization};

// Use mockall to generate mock for SnapTunNgControlPlaneClient
mock! {
    pub ControlPlaneClient {}

    #[async_trait::async_trait]
    impl SnapTunNgControlPlaneClient for ControlPlaneClient {
        async fn register_identity(
            &self,
            identity: PublicKey,
            psk_share: Option<[u8; 32]>,
        ) -> Result<Option<[u8; 32]>, CrpcClientError>;
    }
}

/// Mock authorization that allows fine-grained control over authorization state
pub struct MockAuthorization {
    inner: Arc<Mutex<MockAuthorizationInner>>,
}

struct MockAuthorizationInner {
    authorized_identities: HashMap<[u8; 32], Instant>,
}

impl MockAuthorization {
    /// Create a new MockAuthorization with no authorized identities
    pub fn new() -> Self {
        Self {
            inner: Arc::new(Mutex::new(MockAuthorizationInner {
                authorized_identities: HashMap::new(),
            })),
        }
    }

    /// Authorize an identity until the given expiry time
    pub fn authorize_identity(&self, identity: [u8; 32], expires_at: Instant) {
        let mut inner = self.inner.lock().unwrap();
        inner.authorized_identities.insert(identity, expires_at);
    }

    /// Authorize an identity for a given duration from now
    pub fn authorize_for_duration(&self, identity: [u8; 32], duration: std::time::Duration) {
        let expires_at = Instant::now() + duration;
        self.authorize_identity(identity, expires_at);
    }

    /// Revoke authorization for an identity
    pub fn revoke_identity(&self, identity: &[u8; 32]) {
        let mut inner = self.inner.lock().unwrap();
        inner.authorized_identities.remove(identity);
    }
}

impl SnapTunAuthorization for MockAuthorization {
    fn is_authorized(&self, now: Instant, identity: &[u8; 32]) -> bool {
        let inner = self.inner.lock().unwrap();

        if let Some(&expires_at) = inner.authorized_identities.get(identity) {
            now < expires_at
        } else {
            false
        }
    }
}
