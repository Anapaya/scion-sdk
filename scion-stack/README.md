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

Refer to the crate documentation for more details and advanced usage.
