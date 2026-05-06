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

//! Benchmarks comparing sciparse view-based vs model-based packet parsing and serialization.

use core::panic;
use std::hint::black_box;

use bytes::{Bytes, BytesMut};
use criterion::{BatchSize, Criterion, criterion_group, criterion_main};
use scion_proto::{
    packet::ScionPacketRaw as ScionProtoPacketRaw,
    path::StandardPath,
    wire_encoding::{WireDecode, WireEncodeVec},
};
use sciparse::{
    core::{encode::WireEncode, view::View},
    dataplane_path::{
        model::ptest::ArbitraryPathParams, standard::model::ptest::ArbitraryPathContext,
        view::ScionDpPathViewRef,
    },
    header::model::ptest::ArbitraryScionPacketHeaderParams,
    packet::{
        classify::{ClassifiedPacket, ptest::ArbitraryClassifiedPacketParams},
        model::ScionRawPacket,
        view::ScionRawPacketView,
    },
    util::ToValue,
};

/// Number of packets to generate and benchmark on.
const NUM_PACKETS: usize = 10_000;

/// Cap the number of hop fields to a "reasonable" number
const MAX_HOPS_PER_SEGMENT: usize = 12;

/// Generate `NUM_PACKETS` valid encoded SCION packets using proptest's `ClassifiedPacket` arbitrary
/// impl. Returns the wire-encoded bytes for each packet.
/// Paths are capped to at most `MAX_HOPS_PER_SEGMENT` hop fields per segment.
fn generate_packet_bytes() -> Vec<Bytes> {
    let params = ArbitraryClassifiedPacketParams {
        header_params: ArbitraryScionPacketHeaderParams {
            path: ArbitraryPathParams {
                standard: 1,
                one_hop: 0,
                empty: 0,
                unsupported: 0,
                standard_params: ArbitraryPathContext {
                    hops_per_segment: 1..=MAX_HOPS_PER_SEGMENT,
                },
                one_hop_params: Default::default(),
            },
            ..Default::default()
        },
        ..Default::default()
    };

    (0..NUM_PACKETS)
        .filter_map(|seed| {
            let pkt = ClassifiedPacket::arbitrary_value_with(params.clone(), seed as u128);
            if pkt.wire_valid().is_err() {
                panic!("Generated invalid packet with seed {seed}");
            }
            pkt.encode_to_vec().ok().map(Bytes::from)
        })
        .collect()
}

/// Benchmarks for parsing,
fn bench_parsing(c: &mut Criterion) {
    let packets = generate_packet_bytes();
    let num = packets.len();

    // Sciparse
    {
        // Unsafe view parse (zero-copy, no bounds checks).
        c.bench_function(&format!("sciparse/view_parse_unsafe_{num}_packets"), |b| {
            b.iter(|| {
                for pkt in &packets {
                    let view = black_box(unsafe { ScionRawPacketView::from_slice_unchecked(pkt) });
                    black_box(view);
                }
            });
        });

        // Safe view parse (zero-copy, with bounds checks).
        c.bench_function(&format!("sciparse/view_parse_{num}_packets"), |b| {
            b.iter(|| {
                for pkt in &packets {
                    let (view, _rest) =
                        black_box(ScionRawPacketView::from_slice(pkt)).expect("view parse failed");
                    black_box(view);
                }
            });
        });

        // Sciparse model parse (copies all fields into owned Rust types, including path info/hop
        // fields).
        c.bench_function(
            &format!("sciparse/model_parse_{num}_packets_with_path"),
            |b| {
                b.iter(|| {
                    for pkt in &packets {
                        let (model, _rest) =
                            black_box(ScionRawPacket::from_slice(pkt).expect("view parse failed"));
                        black_box(model);
                    }
                });
            },
        );
    }

    // Scion-proto
    {
        // Parse Lazy Path (only decodes common header and address fields, leaves path as raw
        // bytes).
        c.bench_function(&format!("scion_proto/model_parse_{num}_packets"), |b| {
            b.iter(|| {
                for pkt in &packets {
                    // Note: bytes clone does not clone the underlying data.
                    let model = black_box(
                        ScionProtoPacketRaw::decode(&mut pkt.clone()).expect("decode failed"),
                    );
                    black_box(model);
                }
            });
        });

        // Parse full model
        c.bench_function(
            &format!("scion_proto/model_parse_with_path_{num}_packets"),
            |b| {
                b.iter(|| {
                    for pkt in &packets {
                        // Note: bytes clone does not clone the underlying data.
                        let model =
                            ScionProtoPacketRaw::decode(&mut pkt.clone()).expect("decode failed");
                        match model.headers.path {
                            scion_proto::path::DataPlanePath::Standard(encoded_standard_path) => {
                                let p = StandardPath::try_from(encoded_standard_path)
                                    .expect("path parse failed");
                                black_box(p);
                            }
                            other => {
                                black_box(other);
                            }
                        }
                        black_box(&model.headers.common);
                        black_box(&model.headers.address);
                        black_box(&model.payload);
                    }
                });
            },
        );
    }
}

/// Benchmarks for encoding / serialisation of sciparse view and model, and scion-proto model.
fn bench_encode(c: &mut Criterion) {
    let packets = generate_packet_bytes();
    let num = packets.len();

    // Sciparse
    {
        // Pre-parse into sciparse models
        let sciparse_models: Vec<ScionRawPacket> = packets
            .iter()
            .map(|pkt| {
                let (view, _) = ScionRawPacketView::from_slice(pkt).unwrap();
                ScionRawPacket::from_view(view).unwrap()
            })
            .collect();

        // As bytes for sciparse view (zero-copy, just returns the original byte slice).
        // This should be free, as it's just a pointer cast
        c.bench_function(&format!("sciparse/view_as_bytes_{num}_packets"), |b| {
            b.iter(|| {
                for pkt in &packets {
                    let view = unsafe { ScionRawPacketView::from_slice_unchecked(pkt) };
                    let bytes = black_box(view.as_bytes());
                    black_box(bytes);
                }
            });
        });

        // Model encode, needs to encode all fields back into a buffer
        c.bench_function(
            &format!("sciparse/model_encode_{num}_packets_with_path"),
            |b| {
                b.iter_batched(
                    || [0; 4000],
                    |mut buf| {
                        for model in &sciparse_models {
                            black_box(model.encode(&mut buf).expect("encode failed"));
                        }
                    },
                    BatchSize::LargeInput,
                );
            },
        );
    }

    // Scion-proto
    {
        // Pre-parse into scion-proto models with fully decoded paths.
        // We store the decoded StandardPath alongside the raw packet so we can also benchmark
        // encoding the path.
        let scion_proto_models: Vec<(ScionProtoPacketRaw, Option<StandardPath>)> = packets
            .iter()
            .map(|pkt| {
                let model = ScionProtoPacketRaw::decode(&mut pkt.clone()).unwrap();
                let decoded_path = match &model.headers.path {
                    scion_proto::path::DataPlanePath::Standard(esp) => {
                        Some(StandardPath::try_from(esp.clone()).unwrap())
                    }
                    _ => None,
                };
                (model, decoded_path)
            })
            .collect();

        // --- scion-proto model encode (without path) ---
        c.bench_function(&format!("scion_proto/model_encode_{num}_packets"), |b| {
            b.iter_batched(
                || BytesMut::with_capacity(4000),
                |mut buffer| {
                    for (model, _decoded_path) in &scion_proto_models {
                        let encoded = model.encode_with(&mut buffer).expect("encode failed");
                        // Note: Since scion-proto does not encode into a single contiguous buffer,
                        // we need to concatenate the header and payload parts to get the full
                        // packet bytes.
                        let concatenated = black_box(encoded.concat());
                        black_box(concatenated);
                        buffer.clear();
                    }
                },
                BatchSize::LargeInput,
            );
        });

        // --- scion-proto model encode (with full path encode) ---
        c.bench_function(
            &format!("scion_proto/model_encode_{num}_packets_with_path"),
            |b| {
                b.iter_batched(
                    || BytesMut::with_capacity(4000),
                    |mut buffer| {
                        for (model, decoded_path) in &scion_proto_models {
                            // Pay the path encoding cost.
                            if let Some(path) = decoded_path {
                                let encoded =
                                    path.encode_with(&mut buffer).expect("path encode failed");
                                black_box(encoded);
                            }
                            buffer.clear();

                            let encoded = model.encode_with(&mut buffer).expect("encode failed");
                            // Note: Since scion-proto does not encode into a single contiguous
                            // buffer, we need to concatenate the header
                            // and payload parts to get the full
                            // packet bytes.
                            let concatenated = black_box(encoded.concat());
                            black_box(concatenated);
                            buffer.clear();
                        }
                    },
                    BatchSize::LargeInput,
                );
            },
        );
    }
}

/// Benchmarks comparing field access cost of view vs model.
fn bench_access(c: &mut Criterion) {
    let packets = generate_packet_bytes();
    let num = packets.len();
    // SciParse
    {
        // Pre-parse into sciparse models
        let sciparse_models: Vec<ScionRawPacket> = packets
            .iter()
            .map(|pkt| {
                let (view, _) = ScionRawPacketView::from_slice(pkt).unwrap();
                ScionRawPacket::from_view(view).unwrap()
            })
            .collect();

        // View access cost
        c.bench_function(&format!("sciparse/view_sum_hops_{num}_packets"), |b| {
            b.iter(|| {
                let mut total: u64 = 0;
                for pkt in &packets {
                    // We use unchecked view parse here to isolate just the cost of field access.
                    let view = unsafe { ScionRawPacketView::from_slice_unchecked(pkt) };
                    if let ScionDpPathViewRef::Standard(std_path) = view.header().path() {
                        for hf in std_path.hop_fields() {
                            total += hf.cons_ingress() as u64 + hf.cons_egress() as u64;
                        }
                    }
                }
                black_box(total)
            });
        });

        // Model access cost
        c.bench_function(&format!("sciparse/model_sum_hops_{num}_packets"), |b| {
            b.iter(|| {
                let mut total: u64 = 0;
                for model in &sciparse_models {
                    if let Some(std_path) = model.header.path.standard() {
                        for hf in std_path.iter_hop_fields() {
                            total += hf.cons_ingress as u64 + hf.cons_egress as u64;
                        }
                    }
                }
                black_box(total)
            });
        });
    }

    {
        // Pre-parse into scion-proto models
        let scion_proto_models: Vec<ScionProtoPacketRaw> = packets
            .iter()
            .map(|pkt| {
                let mut buf = bytes::Bytes::copy_from_slice(pkt);
                ScionProtoPacketRaw::decode(&mut buf).unwrap()
            })
            .collect();

        // Scion proto lazy path access cost
        c.bench_function(
            &format!("scion_proto/lazy_path_sum_hops_{num}_packets"),
            |b| {
                b.iter(|| {
                    let mut total: u64 = 0;
                    for model in &scion_proto_models {
                        if let scion_proto::path::DataPlanePath::Standard(ref esp) =
                            model.headers.path
                        {
                            for hf in esp.hop_fields() {
                                total += hf
                                    .cons_ingress_interface()
                                    .map(|i| i.get() as u64)
                                    .unwrap_or(0)
                                    + hf.cons_egress_interface()
                                        .map(|i| i.get() as u64)
                                        .unwrap_or(0);
                            }
                        }
                    }
                    black_box(total)
                });
            },
        );
    }
}

criterion_group!(benches, bench_parsing, bench_encode, bench_access);
criterion_main!(benches);
