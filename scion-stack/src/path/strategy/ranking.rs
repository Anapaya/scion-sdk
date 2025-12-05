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

//! Path ranking allows expressing preferences between paths.
//!
//! For example, preferring shorter paths, paths that were manually registered, or paths
//! that go through certain ASes.

use std::cmp::Ordering;

use crate::path::types::PathManagerPath;

/// Scion path ranking allows expressing preferences between paths.
pub trait PathRanking: 'static + Send + Sync {
    /// Ranks the order of two paths based on preference.
    ///
    /// # Return
    /// Returns the **preference ordering** between two paths.
    ///
    /// - `Ordering::Less` if `this` is preferred over `other`
    /// - `Ordering::Greater` if `other` is preferred over `this`
    /// - `Ordering::Equal` if both paths are equally preferred
    fn rank_order(&self, this: &PathManagerPath, other: &PathManagerPath) -> Ordering;
}

// Allow any closure that matches the signature to be a PathRanking.
impl<F> PathRanking for F
where
    F: 'static + Send + Sync + Fn(&PathManagerPath, &PathManagerPath) -> Ordering,
{
    fn rank_order(&self, this: &PathManagerPath, other: &PathManagerPath) -> Ordering {
        (self)(this, other)
    }
}

/// Selects the shortest path based on the number of hops.
pub struct Shortest;

impl PathRanking for Shortest {
    fn rank_order(&self, this: &PathManagerPath, other: &PathManagerPath) -> Ordering {
        // Prefer paths that were manually registered.
        match (this.is_from_registration(), other.is_from_registration()) {
            (true, false) => Ordering::Less,
            (false, true) => Ordering::Greater,
            _ => {
                // Prefer shorter paths.
                this.path
                    .interface_count()
                    .cmp(&other.path.interface_count())
            }
        }
    }
}
