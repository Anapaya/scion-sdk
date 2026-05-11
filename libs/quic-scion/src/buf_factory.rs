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

//! Pooled buffers factory.
//!
//! Heavily inspired by the tokio-quiche buffer factory:
//! <https://github.com/Anapaya/squiche/blob/master/tokio-quiche/src/buf_factory.rs>

use buffer_pool::{ConsumeBuffer, Pool, Pooled};

const POOL_SHARDS: usize = 8;
const POOL_SIZE: usize = 16 * 1024;

const MAX_POOL_BUF_SIZE: usize = 64 * 1024;

type BufPool = Pool<POOL_SHARDS, ConsumeBuffer>;

/// A generic buffer pool used to pass data around without copying.
static BUF_POOL: BufPool = BufPool::new(POOL_SIZE, MAX_POOL_BUF_SIZE, "generic_pool");

/// A pooled byte buffer to pass stream data around without copying.
pub type PooledBuf = Pooled<ConsumeBuffer>;

/// Handle to the crate's static buffer pools.
#[derive(Default, Clone, Debug)]
pub struct BufFactory;

impl BufFactory {
    /// Fetches a `MAX_BUF_SIZE` sized [`PooledBuf`] from the generic pool.
    pub fn get_max_buf() -> PooledBuf {
        BUF_POOL.get_with(|d| d.expand(MAX_POOL_BUF_SIZE))
    }
}
