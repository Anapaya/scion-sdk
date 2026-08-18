# SCION endhost software development kit (SDK)

[![CI](https://github.com/Anapaya/scion-sdk/actions/workflows/rust-checks.yml/badge.svg)](https://github.com/Anapaya/scion-sdk/actions/workflows/rust-checks.yml)
[![crates.io](https://img.shields.io/crates/v/scion-stack.svg)](https://crates.io/crates/scion-stack)
[![docs.rs](https://docs.rs/scion-stack/badge.svg)](https://docs.rs/scion-stack)
[![License](https://img.shields.io/badge/License-Apache_2.0-blue.svg)](LICENSE)

Supercharge your applications with SCION's path-aware networking capabilities!

The SCION endhost SDK provides the tools and libraries necessary to build applications that can
leverage the full potential of the [SCION Internet architecture](https://www.scion.org/). It enables
developers to create path-aware, secure, and reliable applications that can intelligently select
their network paths, providing enhanced control over their network traffic.

This SDK is developed and maintained by [Anapaya](https://www.anapaya.net/), a leading SCION
technology company. We thank our colleagues at [Mysten Labs](https://mystenlabs.com/) for publishing
[scion-rs](https://github.com/mystenlabs/scion-rs) upon which parts of this SDK are based.

## What SCION gives you as an application developer

SCION is an inter-domain networking architecture — think of it as an alternative
to today's BGP-routed Internet — with one property that matters most to
application developers: **the application, not the network, chooses the path its
packets take.**

On the SCION network you can:

- **See every path to a destination** and their properties (which ISDs and ASes
  they cross, MTU, latency hints) instead of being handed one opaque route.
- **Pick a path per packet** — steer traffic away from a provider, prefer a
  low-latency route, or spread load across several paths — from application code.
- **Fail over instantly** when a path breaks, because you already hold the
  alternatives.
- **Trust the source**, because SCION paths are cryptographically authenticated.

## Usage

The main entry point for using the SCION endhost SDK is the [scion-stack](crates/scion-stack/)
crate. It provides the `ScionStack` type - a stateful object that is the conceptual equivalent of
the UDP/TCP/IP networking stack found in typical operating systems.

To use the SCION endhost SDK in your Rust project, add the `scion-stack` crate as a dependency in
your `Cargo.toml`:

```bash
cargo add scion-stack
```

### Basic example: Creating a path-aware socket

The following example demonstrates how to create a `ScionStack` and bind a path-aware UDP socket.
This type of socket automatically manages path selection, simplifying the process of sending and
receiving data over the SCION network.

```rust
use scion_stack::stack::{ScionStack, ScionStackBuilder};
use sciparse::address::ip_socket_addr::ScionSocketIpAddr;
use url::Url;

async fn socket_example() -> Result<(), Box<dyn std::error::Error>> {
    // Point the stack at your local SCION endhost API.
    let endhost_api: Url = "http://127.0.0.1:1234".parse()?;
    let builder = ScionStackBuilder::new().with_endhost_api(endhost_api);

    let scion_stack = builder.build().await?;
    let socket = scion_stack.bind(None).await?;

    let destination: ScionSocketIpAddr = "1-ff00:0:111,[192.168.1.1]:8080".parse()?;

    socket.send_to(b"hello", destination).await?;
    let mut buffer = [0u8; 1024];
    let (len, src) = socket.recv_from(&mut buffer).await?;
    println!("Received: {:?} from {:?}", &buffer[..len], src);

    Ok(())
}
```

## Documentation

The full developer guide is published at **<https://learn.anapaya.net/docs/academy/scion-sdk>**.
That site tracks the latest *released* version of the SDK.

To preview the documentation for the current `HEAD` of this repository instead, use the standalone
preview app in [docs/preview/](docs/preview/):

```bash
cd docs/preview
pnpm install
pnpm start          # http://localhost:3000 (live reload)
```

## Code structure

The SCION endhost SDK lives under [crates/](crates/), organized into building-block libraries
([crates/libs/](crates/libs/)) and API/RPC binding families ([crates/apis/](crates/apis/)), with
the main components at the top level. The most relevant crates are:

- [scion-stack](crates/scion-stack/): The main entry point for creating SCION sockets. It provides
  the `ScionStack` and related components for building SCION applications.
- [pocketscion](crates/pocketscion/): A SCION simulator for local development and testing.
- [snap](crates/snap/): A client implementation for the SNAP (SCION Network Access Point) transport
  underlay.
- [sciparse](crates/libs/sciparse/): Contains the definitions for SCION data plane and control plane
  entities, such as packet formats and control plane messages.

Language bindings live outside `crates/`:

- [bindings/android/](bindings/android/): Packages the SCION HTTP/3 client into an Android library
  (AAR), cross-compiling [scion-http3-ffi](crates/libs/scion-http3-ffi/) for `arm64-v8a` and
  `x86_64`.

## Contributing

We welcome contributions from the community! If you'd like to help improve the SCION endhost SDK,
here's how you can get started:

- **Bug reports and feature requests**: If you encounter a bug or have an idea for a new feature,
  please open an issue using the appropriate issue template (bug report or feature request, once
  they are available).
- **Pull requests**: We encourage you to contribute code! To submit a pull request, please follow
  this workflow:
    1. Fork the repository.
    1. Create a new branch for your changes.
    1. Make your changes and commit them with a clear and descriptive message.
    1. Submit a pull request to the `main` branch of the original repository.
    1. Address any feedback or requested changes from the maintainers.
    1. Once approved, your changes will be first synced to our internal repository, merged, and then
       published to the public repository. We will make sure to properly attribute your contribution
       in the commit history.

For larger features or significant changes, we recommend opening an issue first to discuss your
plans with the maintainers. This helps ensure that your work aligns with the project's goals and
avoids duplication of effort.

## License

This project is licensed under the Apache 2.0 License. See the [LICENSE](LICENSE) file for more
details.

## Contact

For any questions or inquiries, please contact us at
[scion-sdk@anapaya.net](mailto:scion-sdk@anapaya.net).
