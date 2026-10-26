---
title: The client
sidebar_position: 3
description: The HTTP/3 client in Rust as the terminal client of the chat uses it.
---

This page shows the HTTP/3 client in Rust, the [`scion-http3`](https://docs.rs/scion-http3) crate,
as the terminal client of the chat uses it. The SCION code of the Rust client is in one file,
[`transport/scion.rs`](https://github.com/Anapaya/scion-sdk-chat/blob/main/crates/chat-client-core/src/transport/scion.rs).
[The mobile clients](./mobile.md) shows the Android and iOS clients of the chat.

## Build the client and send a request

A [`Config`](https://docs.rs/scion-http3/latest/scion_http3/struct.Config.html) names the endhost
API and the credential.
[`Client::new`](https://docs.rs/scion-http3/latest/scion_http3/struct.Client.html#method.new)
builds the client from it. The client sends a
[`Request`](https://docs.rs/scion-http3/latest/scion_http3/struct.Request.html) and returns the
response. The SDK example
[`http3_get_post.rs`](https://github.com/Anapaya/scion-sdk/tree/main/crates/libs/scion-http3/examples/http3_get_post.rs)
shows these steps in one short program.

The chat builds one `Client` in `ScionTransport::new`, each time the user connects to a server. The
credential is an API key or a SNAP token. An API key goes into an `AnapayaAaTokenSource`.

A SNAP token expires. A fixed token is enough for a test, but a running app needs new tokens.
`AnapayaAaTokenSource` sends the API key to the Anapaya AA (Authentication and Authorization
service) and gets a new token before the current token expires.
[Access and authentication](../concepts/access-and-authentication.md#the-anapaya-aa-token-source)
explains token sources.

To send a request, the transport converts an `http::Request` into a `scion_http3::Request` and
sends it with `Client::request`. It collects the body of the response up to a limit.

## Trust the server

The client verifies the certificate of the server. The chat offers three choices, and the transport
turns each choice into a `QuicConfig`:

```rust reference="@chat/crates/chat-client-core/src/transport/scion.rs#trust" title="transport/scion.rs"
```

- `SystemRoots` keeps the default: the root certificates of the system.
- `Pinned` trusts one certificate file, for example the self-signed certificate of the
  [chat server](./server.md#the-certificate).
- `Insecure` accepts any certificate. Use it for tests only, because anyone on the path can then
  answer as the server.

## Reach a server without a TSAR record

The client resolves the host of a URL to a SCION address. It reads a DNS TXT record in the TSAR
format (TXT-based SCION address resolution). A server in a local SCION network has no such record.
The chat gives the address of such a server as `target`, and the resolver answers for the host of
the server from the configuration:

```rust reference="@chat/crates/chat-client-core/src/transport/scion.rs#resolver" title="transport/scion.rs"
```

`with_override` maps one host to fixed SCION addresses. The resolver looks up every other host in
DNS. The address has no port: the port and the name that the certificate must match come from the
URL.

## Map the errors

Every failure of the client is a
[`scion_http3::Error`](https://docs.rs/scion-http3/latest/scion_http3/enum.Error.html). The chat
sorts the variants into its own error kinds:

```rust reference="@chat/crates/chat-client-core/src/transport/scion.rs#errors" title="transport/scion.rs"
```

The TCP transport of the chat reports the same error kinds. Thus the rest of the client handles one
set of errors for all transports.

## Where to go next

- **[The server](./server.md):** the other end of the connection.
- **[The mobile clients](./mobile.md):** the same transport on Android and iOS.
- **[From a local SCION network to a real network](./real-network.md):** the credential, the
  address and the trust of a real deployment.
- **[`scion-http3` API reference](https://docs.rs/scion-http3):** the complete client API.
