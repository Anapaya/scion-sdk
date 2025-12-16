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

//! Path policies allow for the selection of paths based on certain criteria.
//!
//! For example, filtering out paths that go through certain ASes or paths.

use scion_proto::path::Path;

/// Path policies allow for the selection of paths based on certain criteria.
pub trait PathPolicy: 'static + Send + Sync {
    /// Returns true if the path should be considered for selection.
    fn predicate(&self, path: &Path) -> bool;
}

// Allow using scion_proto path policies directly
impl<T: scion_proto::path::policy::PathPolicy> PathPolicy for T {
    fn predicate(&self, path: &Path) -> bool {
        <Self as scion_proto::path::policy::PathPolicy>::path_allowed(self, path).unwrap_or(false) // If the policy cannot be evaluated, the path is not allowed
    }
}
