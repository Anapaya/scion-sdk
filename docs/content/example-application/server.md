---
title: The server
sidebar_position: 2
description: How the chat server serves an Axum router over HTTP/3 on SCION, with a certificate that clients pin and a graceful shutdown.
---

The chat server is an [Axum](https://docs.rs/axum) application. The
[`scion-h3-axum`](https://docs.rs/scion-h3-axum) crate serves its router over HTTP/3 on a SCION
socket. The SCION code of the server is in one file,
[`chat-server/src/scion.rs`](https://github.com/Anapaya/scion-sdk-chat/blob/main/crates/chat-server/src/scion.rs).

## From a minimal server to the chat server

The chat server is an HTTP/3 server. The SDK example
[`axum_h3.rs`](https://github.com/Anapaya/scion-sdk/tree/main/crates/scion-stack/examples/axum_h3.rs)
is a minimal HTTP/3 server. It builds a stack, binds a socket, and serves a router on the socket:

```rust reference="@sdk/crates/scion-stack/examples/axum_h3.rs#axum-server" title="examples/axum_h3.rs"
```

The chat server does the same three steps:

1. It builds a stack. [The credential](#the-credential) shows how.
2. It binds a socket on the stack. [The listen address](#the-listen-address) shows how.
3. It serves the Axum router on the socket. The next section shows how.

A real server adds three things to the example: a credential that does not expire, a certificate that
clients can pin, and a graceful shutdown.

## The credential

The server uses the SNAP underlay, so it proves to the SNAP that it may use the network. The
server takes one of two flags:

- `--auth-token-file` gives one SNAP token. The server stops working when the token expires.
  `chat-dev` uses this flag.
- `--auth-api-key-file` gives an API key. The Anapaya AA exchanges the key for tokens, and the SDK
  renews the token while the server runs.

```rust reference="@chat/crates/chat-server/src/scion.rs#build-stack" title="chat-server/src/scion.rs"
```

[The ScionStack model](../concepts/scionstack-model.md#building-a-stack) explains the stack builder.

## Serve the router

[`ScionH3AxumServer::serve_with_graceful_shutdown`](https://docs.rs/scion-h3-axum/latest/scion_h3_axum/struct.ScionH3AxumServer.html#method.serve_with_graceful_shutdown)
takes the socket, the router, a QUIC configuration and a
[`CancellationToken`](https://docs.rs/tokio-util/latest/tokio_util/sync/struct.CancellationToken.html):

```rust reference="@chat/crates/chat-server/src/scion.rs#serve" title="chat-server/src/scion.rs"
```

The function returns when the server stops or fails. The `main` function of the chat server
cancels the token on the first signal that asks the process to stop, and the server then stops
gracefully.

The router is the same Axum `Router` that the chat server serves over TCP with `--transport tcp`.
The routes, the store and the login of the chat are ordinary Axum code.

## The certificate

HTTP/3 runs on QUIC, and QUIC uses TLS, so the server needs a certificate. The chat server makes a
self-signed certificate on its first start and keeps it in its data directory. The server logs the
fingerprint of the certificate. The operator gives that fingerprint to the clients that pin the
certificate:

```rust reference="@chat/crates/chat-server/src/scion.rs#certificate" title="chat-server/src/scion.rs"
```

The server then loads the certificate and its key into the QUIC configuration, with
`load_cert_chain_from_pem_file` and `load_priv_key_from_pem_file`. Both functions read a PEM file.

A client of the chat [pins this certificate](./client.md#trust-the-server). A public server uses a
publicly trusted certificate, and its clients trust it through the system roots.
[From a local SCION network to a real network](./real-network.md#trust-and-credentials)
explains the move from one to the other.

## The listen address

The `--listen` flag of the server gives the IP address and the port of the socket. The endhost API
gives the AS: the server binds in the AS that `stack.local_ases()` returns.

```rust reference="@chat/crates/chat-server/src/scion.rs#bind" title="chat-server/src/scion.rs"
```

[Addressing](../concepts/addressing.md#working-with-addresses-in-the-sdk) explains SCION addresses.

A fixed port gives clients a fixed URL. For example, `chat-dev` starts the server with
`--listen 127.0.0.1:8443`, and its clients use the URL `https://localhost:8443`.

## Where to go next

- **[The client](./client.md):** the other end of the connection.
- **[From a local SCION network to a real network](./real-network.md):** the credential, the
  certificate and the endhost API of a real deployment.
- **[`scion-h3-axum` API reference](https://docs.rs/scion-h3-axum):** the complete server API.
