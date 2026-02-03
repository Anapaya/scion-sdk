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
//! I/O utility functions.

use std::path::{Path, PathBuf};

use serde::{Serialize, de::DeserializeOwned};
use tokio::{
    fs::{File, OpenOptions},
    io::{AsyncReadExt, AsyncWriteExt},
};

/// Reads a file and deserializes its content into the specified type.
pub async fn read_file<P, T>(path: P) -> std::io::Result<T>
where
    P: AsRef<Path>,
    T: DeserializeOwned,
{
    let mut buf = Vec::new();
    File::open(path.as_ref())
        .await?
        .read_to_end(&mut buf)
        .await?;
    serde_json::from_slice(&buf).map_err(std::io::Error::other)
}

/// Serializes the given type to JSON and writes it to the specified file path.
pub async fn write_file(path: impl AsRef<Path>, content: &impl Serialize) -> std::io::Result<()> {
    let buf = serde_json::to_vec(content).map_err(std::io::Error::other)?;
    OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .open(path.as_ref())
        .await?
        .write_all(&buf)
        .await?;
    Ok(())
}

/// Returns a temporary path in the system's temp directory, prefixed with the current thread name.
pub fn get_tmp_path<S: AsRef<str>>(name: S) -> PathBuf {
    let path = std::env::temp_dir();
    let current_thread = std::thread::current().id();
    path.join(format!("{:?}_{}", current_thread, name.as_ref()))
}
