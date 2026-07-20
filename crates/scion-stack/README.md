# SCION endhost software development kit (SDK)

Supercharge your applications with SCION's path-aware networking capabilities!

The SCION endhost SDK provides the tools and libraries necessary to build applications that can
leverage the full potential of the [SCION Internet architecture](https://www.scion.org/). It enables
developers to create path-aware, secure, and reliable applications that can intelligently select
their network paths, providing enhanced control over their network traffic.

## Usage

This crate provides the `ScionStack` type - a stateful object that is the conceptual equivalent of
the UDP/TCP/IP networking stack found in typical operating systems.

The following example demonstrates how to create a `ScionStack` and bind a path-aware UDP socket.
This type of socket automatically manages path selection, simplifying the process of sending and
receiving data over the SCION network.

```rust
use scion_stack::resolver::{ScionDnsResolver, txt::ScionTxtDnsResolver};
use scion_stack::{ScionStack, ScionStackBuilder};
use sciparse::address::ip_socket_addr::ScionSocketIpAddr;

async fn socket_example() -> Result<(), Box<dyn std::error::Error>> {
    let endhost_api: url::Url = "http://127.0.0.1:1234".parse()?;
    let scion_stack = ScionStackBuilder::new()
        .with_endhost_api(endhost_api)
        .with_auth_token("SNAP token".to_string())
        .build()
        .await?;
    let socket = scion_stack.bind(None).await?;

    let resolver = ScionTxtDnsResolver::new()?;
    let addresses = resolver.resolve("example.com").await?;
    let address = *addresses.first().expect("no addresses resolved");

    let destination = ScionSocketIpAddr::new(address.isd_asn(), address.ip(), 8080);

    socket.send_to(b"hello", destination).await?;
    let mut buffer = [0u8; 1024];
    let (len, src) = socket.recv_from(&mut buffer).await?;
    println!("Received: {:?} from {:?}", &buffer[..len], src);

    Ok(())
}
```

See [`API_CONVENTIONS.md`](API_CONVENTIONS.md) for the crate's public-API conventions (naming,
errors, builders, `#[non_exhaustive]`, and linting).
