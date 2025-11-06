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

use std::{
    collections::HashMap,
    sync::{Arc, Mutex},
    time::{Duration, Instant},
};

use rand::Rng as _;
use rand_chacha::ChaCha8Rng;
use scion_proto::address::EndhostAddr;
use scion_sdk_utils::rangeset::{Range, RangeSet, RemoveError};

#[derive(Debug, thiserror::Error)]
pub enum PortAllocatorError {
    #[error("address not found")]
    AddressNotFound,
    #[error("port already in use")]
    PortAlreadyInUse,
    #[error("no available ports")]
    NoAvailablePorts,
}

impl From<RemoveError<u16>> for PortAllocatorError {
    fn from(error: RemoveError<u16>) -> Self {
        match error {
            RemoveError::ValueNotInSet(_) => PortAllocatorError::PortAlreadyInUse,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Kind {
    Udp,
    Raw,
    ScmpHandler,
}

/// A port allocation guard.
///
/// This is a guard that ensures that the port is freed when the guard is dropped.
pub struct PortGuard {
    kind: Kind,
    address: EndhostAddr,
    port: u16,
    allocator: PortAllocator,
}

impl Drop for PortGuard {
    fn drop(&mut self) {
        self.allocator
            .inner
            .lock()
            .unwrap()
            .free(self.kind, self.address, self.port, Instant::now())
            .unwrap();
    }
}

impl PortGuard {
    pub fn port(&self) -> u16 {
        self.port
    }
}

/// A port allocator for an arbitrary number of addresses.
/// For each address one port of each kind can be allocated at the same time.
pub struct PortAllocator {
    inner: Arc<Mutex<PortAllocatorInner>>,
}

impl PortAllocator {
    pub fn new(addresses: Vec<EndhostAddr>, rng: ChaCha8Rng, reserved_time: Duration) -> Self {
        Self {
            inner: Arc::new(Mutex::new(PortAllocatorInner::new(
                addresses,
                rng,
                reserved_time,
            ))),
        }
    }

    /// Allocate one port for the given kind and address.
    /// If the port is 0, a random port is allocated.
    /// If the port is already in use (on the same address and kind), an error is returned.
    pub fn allocate(
        &self,
        kind: Kind,
        address: EndhostAddr,
        port: u16,
        now: Instant,
    ) -> Result<PortGuard, PortAllocatorError> {
        let port = self
            .inner
            .lock()
            .unwrap()
            .allocate(kind, address, port, now)?;
        Ok(PortGuard {
            kind,
            address,
            port,
            allocator: self.clone(),
        })
    }
}

impl Clone for PortAllocator {
    fn clone(&self) -> Self {
        Self {
            inner: self.inner.clone(),
        }
    }
}

struct PortAllocatorInner {
    allocators: HashMap<(Kind, EndhostAddr), SingleAddrPortAllocator>,
    rng: ChaCha8Rng,
}

impl PortAllocatorInner {
    fn new(addresses: Vec<EndhostAddr>, rng: ChaCha8Rng, reserved_time: Duration) -> Self {
        Self {
            allocators: addresses
                .iter()
                .flat_map(|a| {
                    vec![
                        ((Kind::Udp, *a), SingleAddrPortAllocator::new(reserved_time)),
                        ((Kind::Raw, *a), SingleAddrPortAllocator::new(reserved_time)),
                        (
                            (Kind::ScmpHandler, *a),
                            SingleAddrPortAllocator::new(reserved_time),
                        ),
                    ]
                })
                .collect(),
            rng,
        }
    }

    /// Allocate one port for the given kind and address.
    /// If the port is 0, a random port is allocated.
    /// If the port is already in use (on the same address and kind), an error is returned.
    /// now is the time of the allocation, it is used to determine whether the port is still
    /// reserved.
    fn allocate(
        &mut self,
        kind: Kind,
        address: EndhostAddr,
        port: u16,
        now: Instant,
    ) -> Result<u16, PortAllocatorError> {
        self.allocators
            .get_mut(&(kind, address))
            .ok_or(PortAllocatorError::AddressNotFound)?
            .allocate(port, now, &mut self.rng)
    }

    /// Free one port for the given kind and address.
    /// If the port is not in use, it is ignored.
    fn free(
        &mut self,
        kind: Kind,
        address: EndhostAddr,
        port: u16,
        now: Instant,
    ) -> Result<(), PortAllocatorError> {
        self.allocators
            .get_mut(&(kind, address))
            .ok_or(PortAllocatorError::AddressNotFound)?
            .free(port, now);
        Ok(())
    }
}

/// Allocates ports from the u16 range.
struct SingleAddrPortAllocator {
    free: RangeSet<u16>,
    reserve_for: Duration,
    // The ports are freed after the reservation time passes.
    reserved: HashMap<u16, Instant>,
}

impl SingleAddrPortAllocator {
    fn new(reserved_time: Duration) -> Self {
        Self {
            free: RangeSet::new(vec![Range::new(1, u16::MAX)]).expect("Invalid range"),
            reserved: HashMap::new(),
            reserve_for: reserved_time,
        }
    }

    fn allocate(
        &mut self,
        port: u16,
        now: Instant,
        rng: &mut ChaCha8Rng,
    ) -> Result<u16, PortAllocatorError> {
        self.clean_reserved(now);
        if self.free.is_empty() {
            return Err(PortAllocatorError::NoAvailablePorts);
        }
        let port = match port {
            0 => {
                let n = rng.random_range(0..=self.free.len());
                self.free.nth(n).unwrap()
            }
            p => p,
        };
        self.free.remove(port)?;
        Ok(port)
    }

    fn free(&mut self, port: u16, now: Instant) {
        // if the port is already in the free list, do nothing.
        if self.free.contains(port) {
            return;
        }
        self.reserved.insert(port, now + self.reserve_for);
    }

    fn clean_reserved(&mut self, now: Instant) {
        self.reserved.retain(|port, reserved_until| {
            let is_expired = *reserved_until < now;
            if is_expired && let Err(e) = self.free.insert(*port) {
                panic!("Port already in use, this should never happen: {e}");
            }
            !is_expired
        });
    }
}
