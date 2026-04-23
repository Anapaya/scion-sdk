# SciParse

Zero-copy SCION packet parsing and serialization and control plane components.

## Overview

SciParse provides efficient, zero-copy parsing and construction of
[SCION](https://www.scion.org/) network packets.

It offers two complementary representations:

- **Views** - zero-copy projections over byte buffers that provide direct field access without
  allocation or data copying, with only the validation required to uphold memory safety.
- **Models** - structured Rust types for constructing new packets or performing complex
  modifications that are impractical using views alone.

Additionally, the crate includes control-plane components like PathSegments and signed messages.

### Parsing a packet (zero-copy view)

Use `ScionRawPacketView` to parse an incoming packet directly from a byte buffer without any allocation.

```rust
use sciparse::core::view::View;
use sciparse::packet::view::ScionRawPacketView;

fn handle_packet(buf: &[u8]) {
    let (packet, _rest) = ScionRawPacketView::from_slice(buf)
        .expect("buffer too small");

    let header = packet.header();
    println!("path type:  {:?}", header.path_type());
    println!("dst ISD-AS: {}", header.dst_ia());
    println!("payload:    {} bytes", header.payload_len());
}
```

### Classifying a packet by payload protocol

Classify a raw packet view into UDP, SCMP, or other to access protocol-specific fields:

```rust
use sciparse::core::view::View;
use sciparse::packet::view::ScionRawPacketView;
use sciparse::packet::classify::ClassifiedPacketView;

fn dispatch(buf: &[u8]) {
    let (packet, _rest) = ScionRawPacketView::from_slice(buf).unwrap();

    match packet.classify() {
        Ok(ClassifiedPacketView::Udp(udp)) => {
            let dst_port = udp.udp().dst_port();
            println!("UDP packet to port {dst_port}");
        }
        Ok(ClassifiedPacketView::Scmp(scmp)) => {
            println!("SCMP packet");
        }
        Ok(ClassifiedPacketView::Other(raw)) => {
            println!("unknown protocol");
        }
        Err(e) => eprintln!("classification error: {e}"),
    }
}
```

### Converting a view to a model

Convert a zero-copy view into an owned model to perform complex modifications.

```rust
use sciparse::core::view::View;
use sciparse::packet::view::ScionRawPacketView;
use sciparse::packet::model::{ScionRawPacket, ScionUdpPacket};
use sciparse::packet::classify::ClassifiedPacketView;

fn view_to_model(buf: &[u8]) {
    let (view, _rest) = ScionRawPacketView::from_slice(buf).unwrap();

    // Convert a raw view directly into an owned model.
    let raw_model = ScionRawPacket::from_view(&view).unwrap();
}
```

### Constructing and encoding a packet using a model

Build a SCION/UDP packet using `ScionUdpPacket::new`, which takes source and destination
socket addresses, a path, and the raw payload. The header fields and UDP datagram are
constructed automatically:

```rust
use sciparse::core::encode::WireEncode;
use sciparse::address::socket_addr::ScionSocketAddr;
use sciparse::header::model::Path;
use sciparse::packet::model::ScionUdpPacket;

fn build_udp_packet(
    src: ScionSocketAddr,
    dst: ScionSocketAddr,
    path: Path,
) {
    let packet = ScionUdpPacket::new(src, dst, path, b"hello SCION".to_vec());

    let mut buf = vec![0u8; packet.required_size()];
    let written = packet.encode(&mut buf).expect("encode failed");

    println!("encoded {written} bytes");
}
```

## Performance

Benchmarks are available in the `sciparse-interop` crate (`cargo bench -p sciparse-interop`).
Results are in clock time and may vary based on hardware and software environment.
These measurements are intended for indicative comparison only, not as definitive performance guarantees.

Ran on Intel(R) Core(TM) i7-14700K @~5.5 GHz P-core (last update 23-Apr-2026)

### Parse (10,000 packets)

Parsing the same set of 10,000 packets using different methods:

| Benchmark                         | Total     | Per Packet | vs Sciparse View |
| --------------------------------- | --------- | ---------- | ---------------- |
| sciparse/view_parse_unsafe        | 5.63 µs   | 0.56 ns    | 0.03x            |
| sciparse/view_parse               | 200.44 µs | 20.04 ns   | 1.00x            |
| scion_proto/model_parse           | 991.52 µs | 99.15 ns   | 4.95x            |
| sciparse/model_parse_with_path    | 2.17 ms   | 217.00 ns  | 10.85x           |
| scion_proto/model_parse_with_path | 6.44 ms   | 644.00 ns  | 32.20x           |

### Encode (10,000 packets)

Encoding the same set of 10,000 packets using different methods:

| Benchmark                          | Total   | Per Packet | vs Sciparse Model |
| ---------------------------------- | ------- | ---------- | ----------------- |
| sciparse/view_as_bytes             | 4.27 µs | 0.43 ns    | 0.01x             |
| sciparse/model_encode_with_path    | 1.56 ms | 156.00 ns  | 1.00x             |
| scion_proto/model_encode           | 1.60 ms | 160.00 ns  | 1.03x             |
| scion_proto/model_encode_with_path | 4.47 ms | 446.00 ns  | 2.86x             |

### Access – Sum Hops (10,000 packets)

Summing the number of hops in the same set of 10,000 packets using different methods:

| Benchmark                      | Total     | Per Packet | vs Sciparse View |
| ------------------------------ | --------- | ---------- | ---------------- |
| sciparse/model_sum_hops        | 280.72 µs | 28.07 ns   | 0.84x            |
| sciparse/view_sum_hops         | 335.59 µs | 33.56 ns   | 1.00x            |
| scion_proto/lazy_path_sum_hops | 435.51 µs | 43.55 ns   | 1.30x            |

## Design

### Views

Views are `#[repr(transparent)]` wrappers around `[u8]` slices. A view is created by validating
that the buffer is large enough to safely access all fields (`View::has_required_size`), then
transmuting the slice into the view type. Because views are just reinterpreted pointers,
mutability and ownership are handled by Rust's built-in types (`&View`, `&mut View`,
`Box<View>`).

Views guarantee **memory safety** but do **not** guarantee semantic correctness - for example,
a view will not check that the `next_header` field actually matches the payload contents. It is
the caller's responsibility to validate fields as needed.

### Models

Models are standard Rust structs that own their data. They implement the `WireEncode` trait,
which provides:

1. `required_size()` - the exact number of bytes needed for the wire encoding.
2. `wire_valid()` - minimal validation to prevent encoding structurally invalid packets.
3. `encode()` / `encode_to_vec()` - serialization into a byte buffer.

### Layouts

Layouts define the size and position of every field within a header or data structure at the bit
level. They serve as the single source of truth that both views and models use for reading and
writing data. Layouts also provide debug annotations for visualizing binary structures.

## License

Licensed under the Apache License, Version 2.0.
