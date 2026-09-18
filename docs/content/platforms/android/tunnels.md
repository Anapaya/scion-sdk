---
title: Tunnels
sidebar_position: 2
description: Carry a protocol that is not HTTP/3 through a CONNECT tunnel over SCION, as a byte stream, a java.net.Socket, or an OkHttp connection.
---

The [HTTP/3 client guide](http3-client.md) sends an HTTP/3 request over SCION. This page is for
the traffic that is not an HTTP/3 request: a protocol client of your own, a library that takes a
`java.net.Socket`, or an OkHttp stack you already have. All of them travel through a `CONNECT`
tunnel on the same client.

The page builds on the guide. It uses the client the guide builds, the same test network, and the
same sample app.

## What a tunnel is

`openTunnel` asks the client for a byte stream to a `host:port`. The client resolves `host` to a
SCION address, as it does for the host of a request URL, and opens an HTTP/3 connection to the
server at that address. That server is the gateway. It accepts a `CONNECT` request for the
`host:port`, opens a TCP connection to that port, and passes bytes between the two connections. The
tunnel is your end of that byte stream. It travels on the HTTP/3 connection your requests use, and
it has no framing of its own.

The gateway decides which hosts and ports it forwards a tunnel to. The client verifies the gateway's
certificate against `host`, as it does for a request URL.

### How a SCION host is named

A host on SCION publishes its SCION address in DNS as a TXT record, in the TXT-based SCION address
resolution (TSAR) format. The client's own resolver reads that record. The platform's resolver,
which `InetAddress` and OkHttp's default `Dns` use, reads A and AAAA records only. A host that
exists on SCION alone has none, so a platform lookup fails for it. Nothing on this page needs a
platform lookup: every API below takes the host name and hands it to the client, which resolves it.
A `dnsOverride` replaces the TSAR lookup for one host, for a tunnel as for a request.

The test network's server is its own gateway with two behaviours. A tunnel to `localhost` is an
echo: every byte written into it comes back. A tunnel to `http.invalid` reaches an HTTP/1.1 server
inside the tunnel.

## The byte stream

`openTunnel` returns a `ScionHttp3Tunnel`. The sample writes a message into the echo and reads
back what comes out:

```kotlin reference="@sdk/bindings/android/hello-scion/src/main/kotlin/com/anapaya/scion/http3/hello/Tunnels.kt#byte-stream" title="Tunnels.kt"
```

Four things about the stream matter:

- **The two directions are independent.** One coroutine can read while another writes.
- **`shutdownWrite` ends your direction only.** The peer sees the end of the stream, and your
  reads stay open until the peer ends its direction. A read then returns an empty array.
- **One read returns at most one frame.** A payload the transport split arrives over several
  reads, so read in a loop until you have what you expect.
- **Cancellation closes the tunnel.** A read or a write that is cancelled mid-flight may have
  lost the bytes it just read or written part of its data. The stream is not usable after it.

Close the tunnel when you are done with it. Closing resets the stream. A call still in flight ends
with `TunnelClosed`.

## A `java.net.Socket`

`ScionTunnelSocket` is a `java.net.Socket` whose bytes travel through a tunnel. It is for a protocol
library that takes a socket and knows nothing about SCION:

```kotlin reference="@sdk/bindings/android/hello-scion/src/main/kotlin/com/anapaya/scion/http3/hello/Tunnels.kt#socket" title="Tunnels.kt"
```

`connect` opens the tunnel to the endpoint's host name and port. Use
`InetSocketAddress.createUnresolved`, so that no platform lookup happens. That lookup fails for a
host that exists on SCION alone, as [How a SCION host is named](#how-a-scion-host-is-named)
explains. A resolved address works too: the socket takes the host name from it and ignores the IP
address.

The socket keeps the `Socket` contract that a library expects:

- Its streams block the calling thread. Do not use one on the main thread.
- `soTimeout` bounds a read and a passed deadline arrives as `SocketTimeoutException`. The
  socket stays usable after it.
- `shutdownOutput` is `shutdownWrite` on the tunnel.
- `close` from another thread ends a blocked read with `SocketException`.
- The socket options, such as `tcpNoDelay` and `keepAlive`, can be set and read, but have no
  effect. There is no TCP connection to apply them to.

A tunnel failure arrives as an `IOException`.

## OkHttp

`ScionTunnelSocketFactory` is a `javax.net.SocketFactory` that creates tunnel sockets over one
client. OkHttp takes it and needs one more setting:

```kotlin reference="@sdk/bindings/android/hello-scion/src/main/kotlin/com/anapaya/scion/http3/hello/Tunnels.kt#okhttp" title="Tunnels.kt"
```

OkHttp resolves the host of the URL through its `Dns` before it asks the factory for a socket and
then connects the socket to the address it got. The default `Dns` is the platform's resolver, which
fails for a host that exists on SCION alone, as [How a SCION host is named](#how-a-scion-host-is-named)
explains. The `Dns` above returns a placeholder address that keeps the host name. The socket takes
the name from it and the tunnel carries the name to the gateway, which is where the SCION lookup
happens.

The `Dns` refuses every host that is not meant for SCION. The two settings belong together: this
factory never connects to the placeholder, but a platform socket would connect to `0.0.0.0` on the
device itself. Set both on one OkHttp client. A client derived with `newBuilder()` inherits both.

Every connection in OkHttp's pool is one tunnel. OkHttp opens one when it needs one and reuses it
for the next request to the same host, as it does with a TCP connection. Requests over the tunnel
are HTTP/1.1. The library sends an `https` URL over TLS through the tunnel with OkHttp's own TLS
stack and trust settings.

The sample uses an `http` URL to the test network's plain HTTP/1.1 host. The library's e2e tests
fetch an `https` URL through the same socket with OkHttp's TLS stack over the tunnel. The sample's
OkHttp client, its socket factory, and the client under them are built once and kept.

## Errors

The tunnel arms of `ScionHttp3Exception` add to the arms the guide lists:

- `TunnelRefused` is a `CONNECT` the gateway answered with a status other than 2xx. It carries
  the status. `isRetryable` is true for a 5xx status and false for a 4xx status.
- `TunnelReset` is a tunnel the peer reset while it was open.
- `TunnelDisconnected` is a tunnel that ended because the connection under it went away, for
  example when the network changed. Open a new one.
- `TunnelClosed` is a call on a tunnel your app already closed, or a write after `shutdownWrite`.

On a `ScionTunnelSocket`, and so in OkHttp, all of them arrive as an `IOException`. Its cause is
the `ScionHttp3Exception`.

## Try it

Start the test network as the guide describes, run the sample app, and press one of the three
tunnel buttons. **Echo through a tunnel** and **Echo through a socket** show the message the app
sent, back from the echo. **Fetch with OkHttp** shows:

```text
200

world
```

That is `GET /hello`, as HTTP/1.1 inside a `CONNECT` tunnel, over SCION.

## Where to go next

- **The library README** —
  [`bindings/android/scion-http3-android/README.md`](https://github.com/Anapaya/scion-sdk/tree/main/bindings/android/scion-http3-android)
  is the reference for the tunnel and socket API.
- **The sample** —
  [`Tunnels.kt`](https://github.com/Anapaya/scion-sdk/tree/main/bindings/android/hello-scion/src/main/kotlin/com/anapaya/scion/http3/hello/Tunnels.kt)
  is the class this page is built from.
