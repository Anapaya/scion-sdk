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

//! Extensions for serde serialization and deserialization.

/// Extension trait for serde serialization and deserialization.
pub trait SerdeExt: Sized + serde::Serialize + serde::de::DeserializeOwned {
    /// Serialize `self` to a JSON file at `path`.
    fn write_to_file(&self, path: impl AsRef<std::path::Path>) -> std::io::Result<()> {
        let file = std::fs::File::create(path)?;
        serde_json::to_writer_pretty(file, self)?;
        Ok(())
    }

    /// Deserialize an object of type `Self` from a JSON file at `path`.
    fn load_from_file(path: impl AsRef<std::path::Path>) -> std::io::Result<Self> {
        let file = std::fs::File::open(path)?;
        let obj = serde_json::from_reader(file)?;
        Ok(obj)
    }
}

impl<T> SerdeExt for T where T: serde::Serialize + serde::de::DeserializeOwned {}
