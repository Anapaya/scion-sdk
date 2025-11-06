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

#![allow(missing_docs)]

//! Comparison between different checksum implementations.

use criterion::{BenchmarkId, Criterion, criterion_group, criterion_main};
use rand::{SeedableRng, TryRngCore};
use rand_xorshift::XorShiftRng;
use scion_proto::packet::ChecksumDigest;

fn reference_checksum(data: &[u8]) -> u16 {
    let mut cumsum = 0u32;
    let mut i = 0usize;

    let (data, leftover) = if data.len().is_multiple_of(2) {
        (data, 0u8)
    } else {
        (&data[..data.len() - 1], data[data.len() - 1])
    };

    while i + 1 < data.len() {
        cumsum += ((data[i] as u32) << 8) + (data[i + 1] as u32);
        i += 2;
    }
    cumsum += (leftover as u32) << 8;

    while cumsum > 0xffff {
        cumsum = (cumsum >> 16) + (cumsum & 0xffff);
    }

    !(cumsum as u16)
}

fn bench_checksum(c: &mut Criterion) {
    let mut group = c.benchmark_group("Checksum");
    let mut data = Vec::new();
    let mut rng = XorShiftRng::seed_from_u64(47);

    for length in [512, 1024, 2048, 4096, 8192, 16384, 32768, 65536] {
        let mut input_vec = vec![0u8; length];
        rng.try_fill_bytes(&mut input_vec).unwrap();
        data.push((length, input_vec));
    }

    for (length, vec) in data.iter() {
        group.bench_with_input(
            BenchmarkId::new("Reference", length),
            vec.as_slice(),
            |b, data| b.iter(|| assert_ne!(0, reference_checksum(data))),
        );
        group.bench_with_input(
            BenchmarkId::new("Unsafe", length),
            vec.as_slice(),
            |b, data| b.iter(|| assert_ne!(0, ChecksumDigest::new().add_slice(data).checksum())),
        );
    }

    group.finish()
}

criterion_group!(benches, bench_checksum);
criterion_main!(benches);
