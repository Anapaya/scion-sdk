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

//! Path Manager specific types.

use scion_proto::path;

/// Path wrapper to allow additional metadata to be attached to a path for Ranking and Policies
#[derive(Debug, Clone)]
pub struct PathManagerPath {
    /// The actual SCION path
    pub path: path::Path,
    /// If the path was manually registered (true) or fetched (false)
    pub from_registration: bool,
}

impl PathManagerPath {
    /// Wrap a scion path with metadata
    pub fn new(path: path::Path, from_registration: bool) -> Self {
        Self {
            path,
            from_registration,
        }
    }

    /// Returns true if this path came from registration rather than fetching
    pub fn is_from_registration(&self) -> bool {
        self.from_registration
    }

    /// Get the underlying scion path
    pub fn scion_path(&self) -> &path::Path {
        &self.path
    }
}

impl From<&path::Path> for PathManagerPath {
    fn from(path: &path::Path) -> Self {
        Self {
            path: path.clone(),
            from_registration: false,
        }
    }
}
