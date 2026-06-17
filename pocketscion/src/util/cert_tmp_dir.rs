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

//! Utility for managing temporary files for certificates and keys.

use std::{
    collections::HashMap,
    hash::{DefaultHasher, Hash, Hasher},
    path::{self, PathBuf},
    sync::{Arc, Mutex},
};

use anyhow::Context;

use crate::network::scion::trust_store::{StoreCertificateDer, StoreKeyDer};

#[derive(Debug, Clone)]
pub struct CertificateTempDir {
    existing: Arc<Mutex<HashMap<u64, PathBuf>>>,
    temp_dir: Arc<tempfile::TempDir>,
}
impl CertificateTempDir {
    pub fn new() -> anyhow::Result<Self> {
        Ok(Self {
            existing: Arc::new(Mutex::new(HashMap::new())),
            temp_dir: Arc::new(
                tempfile::tempdir()
                    .context("Failed to create temporary directory for certificates")?,
            ),
        })
    }

    // Creates or gets a temporary file for the given certificate chain, returning the path to the
    // file. The file is created in a temporary directory that is deleted when the
    // CertificateTempDir is dropped. If a file for the given certificate chain already exists, the
    // existing path is returned.
    pub fn get_or_create_cert_file(
        &self,
        cert_chain: &[StoreCertificateDer],
    ) -> anyhow::Result<PathBuf> {
        let mut hasher = DefaultHasher::new();
        cert_chain.hash(&mut hasher);
        let hash = hasher.finish();

        let mut existing_guard = self.existing.lock().unwrap();
        if let Some(path) = existing_guard.get(&hash) {
            Ok(path.clone())
        } else {
            let path = self.temp_dir.path().join(format!("chain-{}.crt", hash));

            let cert_chain = cert_chain
                .iter()
                .map(|cert| cert.to_pem())
                .collect::<Vec<_>>()
                .join("\n");

            std::fs::write(&path, cert_chain)?;
            existing_guard.insert(hash, path.clone());

            Ok(path)
        }
    }

    pub fn get_or_create_key_file(&self, key: &StoreKeyDer) -> anyhow::Result<PathBuf> {
        let mut hasher = DefaultHasher::new();
        key.hash(&mut hasher);
        let hash = hasher.finish();

        let mut existing_guard = self.existing.lock().unwrap();
        if let Some(path) = existing_guard.get(&hash) {
            Ok(path.clone())
        } else {
            let path = self.temp_dir.path().join(format!("key-{}.key", hash));

            std::fs::write(&path, key.to_pem())?;
            existing_guard.insert(hash, path.clone());

            Ok(path)
        }
    }

    pub fn temp_dir_path(&self) -> &path::Path {
        self.temp_dir.path()
    }
}
