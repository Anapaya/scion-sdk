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
//! DHSD state

use std::iter::IntoIterator;

use ring::hmac;

/// DhsdState
#[derive(zeroize::ZeroizeOnDrop, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct DhsdSecret([u8; 32]);

/// A label for a node in a secret tree.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct NodeLabel([u8; 32]);

impl DhsdSecret {
    /// Create a new DhsdSecret from the root secret.
    pub fn from_root_secret(root_secret: [u8; 32]) -> Self {
        Self::from(root_secret)
    }

    /// Derive a new secret state based on a single node label.
    pub fn derive(&self, label: NodeLabel) -> Self {
        let mut key = hmac::Key::new(hmac::HMAC_SHA256, &self.0);
        let mut tag = hmac::sign(&key, &label.0);

        let mut inner = [0u8; 32];
        inner.copy_from_slice(tag.as_ref());
        unsafe {
            // ring::hmac::Tag does _not_ implement Zeroize, so we do it
            // manually here.
            zeroize::zeroize_flat_type(&mut key);
            zeroize::zeroize_flat_type(&mut tag);
        }
        Self(inner)
    }

    /// Derive new secret state based on path.
    pub fn derive_from_iter<P: IntoIterator<Item = NodeLabel>>(&self, path: P) -> Self {
        path.into_iter()
            .fold(self.clone(), |a, label| a.derive(label))
    }
}

impl From<[u8; 32]> for DhsdSecret {
    fn from(value: [u8; 32]) -> Self {
        Self(value)
    }
}

impl From<[u8; 32]> for NodeLabel {
    fn from(value: [u8; 32]) -> Self {
        Self(value)
    }
}

impl std::fmt::Debug for DhsdSecret {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_tuple("DhsdState").field(&"...").finish()
    }
}

impl From<&str> for NodeLabel {
    fn from(value: &str) -> Self {
        let d = ring::digest::digest(&ring::digest::SHA256, value.as_bytes());
        let mut inner = [0u8; 32];
        inner.copy_from_slice(d.as_ref());
        Self(inner)
    }
}

impl From<String> for NodeLabel {
    fn from(value: String) -> Self {
        Self::from(value.as_str())
    }
}

impl From<&String> for NodeLabel {
    fn from(value: &String) -> Self {
        Self::from(value.as_str())
    }
}
