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

use std::{collections::BTreeMap, fmt::Debug};

// Helper function to map over the values of a Map like iter
pub fn map_btree<F, K, V1, V2>(
    input: impl IntoIterator<Item = (K, V1)>,
    mut f: F,
) -> BTreeMap<K, V2>
where
    K: Ord,
    F: FnMut(V1) -> V2,
{
    input.into_iter().map(|(k, v)| (k, f(v))).collect()
}

// Helper function to map over the values of a Map like iter with a non-consuming mapping function.
pub fn map_btree_ref<'a, F, K, V1, V2>(
    input: impl IntoIterator<Item = (&'a K, &'a V1)>,
    mut f: F,
) -> BTreeMap<K, V2>
where
    K: Ord + Clone + 'static,
    V1: 'static,
    F: FnMut(&V1) -> V2,
{
    input.into_iter().map(|(k, v)| (k.clone(), f(v))).collect()
}

#[derive(Debug, thiserror::Error)]
#[error("Error mapping BTreeMap value for key {key:?}: {error:?}")]
pub struct BtreeMapError<K: Debug, E: Debug> {
    key: K,
    error: E,
}

/// Helper function to map over the values of a Map like iter with a fallible mapping function.
///
/// Returns an error if the mapping function returns an error for any value, including the key that
/// caused the error.
pub fn map_btree_fallible<F, K, V1, V2, E>(
    input: impl IntoIterator<Item = (K, V1)>,
    mut f: F,
) -> Result<BTreeMap<K, V2>, BtreeMapError<K, E>>
where
    K: Ord + Debug,
    E: Debug,
    F: FnMut(V1) -> Result<V2, E>,
{
    let mut output = BTreeMap::new();
    for (k, v) in input.into_iter() {
        match f(v) {
            Ok(v) => {
                output.insert(k, v);
            }
            Err(e) => {
                return Err(BtreeMapError { key: k, error: e });
            }
        }
    }

    Ok(output)
}
