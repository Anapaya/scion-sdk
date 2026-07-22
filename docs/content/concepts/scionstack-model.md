---
title: The ScionStack model
description: The central abstraction of the SDK. What a ScionStack is, how you build one, and how addressing, paths, and underlays all hang off it.
sidebar_position: 1
---

import ScionstackAnatomy from './fig/scionstack-anatomy.drawio.svg';

Everything you do with the SDK starts from a
[`ScionStack`](https://docs.rs/scion-stack/latest/scion_stack/struct.ScionStack.html). It is the
SCION equivalent of your operating system's networking stack: the object you open sockets on. If you
have used the standard library's UDP sockets, the shape will feel familiar. The difference is that a
`ScionStack` also knows how to discover the local SCION infrastructure, look up paths, carry your
packets over a transport underlay, and authenticate you to the network, so your application does not
have to.

This page explains what a stack is, how to create one, and where the other concepts
([addressing](./addressing.md), [paths and policies](./paths-and-policies.md), and
[transport underlays](./transport-underlays.md)) attach to it.

## The mental model

You build one `ScionStack` per process and keep it for the lifetime of your application, opening as
many sockets on it as you need. The stack owns the machinery that is shared across all of those
sockets:

<ScionstackAnatomy
  className="svg-diagram"
  role="img"
  aria-label="How a ScionStack ties the pieces together"
/>

- **Sockets** are what your application code touches. You bind and connect them, then `send`/`recv`,
  just like ordinary UDP.
- **Addressing:** the stack works in SCION addresses (`ISD-AS,[host]:port`), which name both the
  network and the endpoint. See [Addressing](./addressing.md).
- **Path management:** the stack fetches and maintains the set of SCION paths to the destinations
  you talk to, and picks one for each packet unless you choose yourself. See
  [Paths and path policies](./paths-and-policies.md).
- **Transport underlay:** how the packets physically reach the SCION network, either directly over
  UDP/IP or through an authenticated tunnel to a SNAP. See
  [Transport underlays](./transport-underlays.md).

Your application interacts with the top of this picture (sockets). The stack handles the rest.

## Building a stack

You configure a stack with
[`ScionStackBuilder`](https://docs.rs/scion-stack/latest/scion_stack/struct.ScionStackBuilder.html)
and finish with
[`build`](https://docs.rs/scion-stack/latest/scion_stack/struct.ScionStackBuilder.html#method.build).
At minimum the stack needs to know where the local *endhost API* is, the service that answers
underlay and path-lookup queries, and, when it will use a SNAP, how to authenticate. The examples
wrap this in a one-line helper:

```rust reference="@sdk/crates/scion-stack/examples/common/mod.rs#build-stack" title="examples/common/mod.rs"
```

The builder is where the cross-cutting choices live: which underlay to prefer
([`with_preferred_underlay`](https://docs.rs/scion-stack/latest/scion_stack/struct.ScionStackBuilder.html#method.with_preferred_underlay)),
how to reach the endhost API
([`with_endhost_api`](https://docs.rs/scion-stack/latest/scion_stack/struct.ScionStackBuilder.html#method.with_endhost_api)),
and how to obtain a SNAP token
([`with_auth_token`](https://docs.rs/scion-stack/latest/scion_stack/struct.ScionStackBuilder.html#method.with_auth_token)).
Those knobs are covered on the [transport underlays](./transport-underlays.md) page.
For the full set, see the
[`ScionStackBuilder` reference](https://docs.rs/scion-stack/latest/scion_stack/struct.ScionStackBuilder.html).

### Lifecycle

`build` is `async`, and a built stack runs background tasks: discovering the underlay, keeping the
path set fresh, and refreshing authentication tokens. Two consequences follow:

- The SDK runs on the [Tokio](https://tokio.rs/) async runtime. Construct and use the stack from
  within an async context.
- Keep the stack alive for as long as you need SCION connectivity. Dropping it tears down those
  background tasks and its sockets stop working, so store it somewhere durable rather than letting
  it fall out of scope.

## The socket surfaces

All sockets are opened on the stack. The one you will use most is the path-aware UDP socket. The
others exist for narrower needs.

| Method | Socket | Use it for |
| --- | --- | --- |
| [`bind`](https://docs.rs/scion-stack/latest/scion_stack/struct.ScionStack.html#method.bind) | [`UdpScionSocket`](https://docs.rs/scion-stack/latest/scion_stack/struct.UdpScionSocket.html) | path-aware UDP, the default; the stack picks paths for you |
| [`connect`](https://docs.rs/scion-stack/latest/scion_stack/struct.ScionStack.html#method.connect) | [`UdpScionSocket`](https://docs.rs/scion-stack/latest/scion_stack/struct.UdpScionSocket.html) | a `bind` fixed to one remote address |
| [`bind_path_unaware`](https://docs.rs/scion-stack/latest/scion_stack/struct.ScionStack.html#method.bind_path_unaware) | [`PathUnawareUdpScionSocket`](https://docs.rs/scion-stack/latest/scion_stack/struct.PathUnawareUdpScionSocket.html) | UDP where *you* supply the path on every send |
| [`bind_raw`](https://docs.rs/scion-stack/latest/scion_stack/struct.ScionStack.html#method.bind_raw) | [`RawScionSocket`](https://docs.rs/scion-stack/latest/scion_stack/struct.RawScionSocket.html) | sending and receiving raw SCION packets |
| [`bind_scmp`](https://docs.rs/scion-stack/latest/scion_stack/struct.ScionStack.html#method.bind_scmp) | [`ScmpScionSocket`](https://docs.rs/scion-stack/latest/scion_stack/struct.ScmpScionSocket.html) | SCMP, SCION's control and diagnostic messages (think ICMP) |

Binding and using a socket looks exactly like the standard library. Here are the server and client
from the `udp_echo` example:

```rust reference="@sdk/crates/scion-stack/examples/udp_echo.rs#server" title="examples/udp_echo.rs"
```

```rust reference="@sdk/crates/scion-stack/examples/udp_echo.rs#client" title="examples/udp_echo.rs"
```

[`recv_from`](https://docs.rs/scion-stack/latest/scion_stack/struct.UdpScionSocket.html#method.recv_from)
yields the peer's SCION address and the socket remembers a return path to it automatically, so
[`send_to`](https://docs.rs/scion-stack/latest/scion_stack/struct.UdpScionSocket.html#method.send_to)
can reply without your code ever touching path selection. Path awareness is there when you want it
(see [Paths and path policies](./paths-and-policies.md)) and out of the way when you do not.

## Where to go next

- **[Addressing](./addressing.md):** how SCION addresses name a network and an endpoint.
- **[Paths and path policies](./paths-and-policies.md):** inspect the paths to a destination and
  choose how your traffic is routed.
- **[Transport underlays](./transport-underlays.md):** UDP versus SNAP, and how tokens
  authorize you to the network.
- **[Getting started](../getting-started.md):** build a stack and run a real program end to end on
  PocketSCION.
- **[`scion-stack` API reference](https://docs.rs/scion-stack):** the complete stack and socket API.
