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
//! Utility functions to configure the rustls crypto provider.
use rustls::crypto::CryptoProvider;

/// Installs the `ring` crypto provider for rustls.
pub fn select_ring_crypto_provider() {
    use std::sync::Once;

    // Ensure this is only run once per process.
    static START: Once = Once::new();
    START.call_once(|| {
        CryptoProvider::install_default(rustls::crypto::ring::default_provider()).unwrap();
    });
}
