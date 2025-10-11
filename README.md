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

## Usage

The main entry point for using the SCION endhost SDK is the [scion-stack](scion-stack/) crate. It
provides the `ScionStack` type - a stateful object that is the conceptual equivalent of the
UDP/TCP/IP networking stack found in typical operating systems.

### Basic example: Creating a path-aware socket

The following example demonstrates how to create a `ScionStack` and bind a path-aware UDP socket.
This type of socket automatically manages path selection, simplifying the process of sending and
receiving data over the SCION network.

```rust
use scion_proto::address::SocketAddr;
use scion_stack::scionstack::{ScionStack, ScionStackBuilder};
use url::Url;

async fn socket_example() -> Result<(), Box<dyn std::error::Error>> {
    let endhost_api: url::Url = "http://127.0.0.1:1234".parse()?;
    let builder = ScionStackBuilder::new(endhost_api);

    let scion_stack = builder.build().await?;
    let socket = scion_stack.bind(None).await?;

    let destination: SocketAddr = "1-ff00:0:111,[192.168.1.1]:8080".parse()?;

    socket.send_to(b"hello", destination).await?;
    let mut buffer = [0u8; 1024];
    let (len, src) = socket.recv_from(&mut buffer).await?;
    println!("Received: {:?} from {:?}", &buffer[..len], src);

    Ok(())
}
```

### Transport underlays

The `ScionStack` automatically discovers the available transports by querying the local SCION
endhost API.

The SCION endhost SDK supports two different transport underlays:

1. **UDP Underlay**: The UDP underlay is the default transport mechanism for SCION packets. SCION
   applications send and receive SCION packets directly to and from the SCION routers using UDP
   sockets. While simple and efficient, the UDP underlay does not support changing network types
   (e.g. switching from WiFi to cellular), deal with NAT traversal, or provide authorization
   mechanisms.
1. **SNAP Underlay**: The SCION Network Access Point (SNAP) transport underlay uses QUIC datagrams
   over a SNAP tunnel to send and receive SCION packets. With the SNAP underlay, applications do not
   interact directly with the SCION routers. Instead, a SNAP provides a frontend that authorizes
   users that are allowed to use the SCION infrastructure of a given SCION AS. Due to its use of
   QUIC, the SNAP underlay supports NAT traversal and can seamlessly switch between different
   network types.

### Local development and testing with PocketSCION

For local development and testing, [pocketscion](pocketscion/) provides a lightweight SCION network
simulator. It allows you to create and manage local SCION topologies, making it an invaluable tool
for testing your applications without needing a full-fledged SCION network.

`pocketscion` supports both the UDP and SNAP underlays, allowing you to test your applications in a
variety of network scenarios.

You can find examples on how to use `pocketscion` for local testing in
[examples/](pocketscion/examples/) and [integration-tests/](integration-tests/). For more details
about `pocketscion`, please refer to the [documentation](pocketscion/README.md).

## Code structure

The SCION endhost SDK is organized into several crates, each with a specific purpose:

* [scion-stack](scion-stack/): The main entry point for creating SCION sockets. It provides the
  `ScionStack` and related components for building SCION applications. and related components for
  building SCION applications.
* [scion-proto](scion-proto/): Contains the definitions for SCION data plane and control plane
  entities, such as packet formats and control plane messages. The base for this crate is
  [scion-rs](https://github.com/mystenlabs/scion-rs), published by Mysten Labs.
* [pocketscion](pocketscion/): A SCION simulator for local development and testing.
* [snap](snap/): A client implementation for the SNAP (SCION Network Access Point) transport
  underlay.
* [endhost-api](endhost-api/): A client for the SCION endhost API, which is used for discovering
  transport underlays and fetching path and certificate information.
* [libs](libs/): Shared libraries and utilities that are used throughout the codebase.
* [integration-tests](integration-tests/): A suite of integration tests that use `pocketscion` to
  test the functionality of the `scion-stack`.

## Contributing

We welcome contributions from the community! If you'd like to help improve the SCION endhost SDK,
here's how you can get started:

* **Bug reports and feature requests**: If you encounter a bug or have an idea for a new feature,
  please open an issue using the appropriate issue template (bug report or feature request, once
  they are available).
* **Pull requests**: We encourage you to contribute code! To submit a pull request, please follow
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
[engineering@anapaya.net](mailto:engineering@anapaya.net).
