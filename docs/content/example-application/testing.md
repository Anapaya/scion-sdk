---
title: Testing against PocketSCION
sidebar_position: 6
description: How the chat tests its SCION code, with the server in one AS and the client in another, on a PocketSCION network that the test starts.
---

[PocketSCION](https://docs.rs/pocketscion) is a SCION network in one process. The SDK examples run
on it, as [Getting started](../getting-started.md#run-your-first-scion-program) shows. An
application can use it in its tests too. To add it to your crate, see
[Add the SDK to your own project](../getting-started.md#add-the-sdk-to-your-own-project).

The chat has one test that runs its server and its Rust client on a PocketSCION network, in two
different ASes:
[`tests/scion.rs`](https://github.com/Anapaya/scion-sdk-chat/blob/main/crates/chat-client-core/tests/scion.rs).

## The fixture

The fixture starts the network, puts the server in one AS, and returns a client that is attached to
the other AS:

```rust reference="@chat/crates/chat-client-core/tests/scion.rs#fixture" title="tests/scion.rs"
```

- `minimal_topology` starts two ASes, `1-ff00:0:132` and `2-ff00:0:212`, with one link. Getting started
  shows [the same network](../getting-started.md#what-just-happened).
- `endhost_api` returns the endhost API of an AS. The server uses the endhost API of `IA212`, and
  the client uses the endhost API of `IA132`.
- `dev_auth_token` returns a token that PocketSCION accepts. The server reads the token from a file,
  and the client gets it as a `Credential::Token`.
- The test makes the certificate before the server starts. Thus the client pins the certificate
  that the server presents.
- The network has no TSAR records, so the client gets the address of the server as `target`.
- `await_ready` sends health requests until the server answers. The server binds its socket before
  it reads from the socket, so the first requests can get lost.

The `serve` helper in the same file binds the server on port 0, and then reads the port that the
socket got. It gives the host and the port to the fixture, for the client.

## The test

The test uses the client in the same way as the app does:

```rust reference="@chat/crates/chat-client-core/tests/scion.rs#round-trip" title="tests/scion.rs"
```

The test reads the server information, registers a user, logs in, creates a room and sends a
message. Then it reads the room and compares the message. Each request goes from the AS of the
client to the AS of the server, so the test covers the SCION code of the server and of the client.

When the test ends, it drops the fixture. The fixture then cancels its `CancellationToken`, and the
server stops.

## A larger network

`chat-dev` builds a network of three ASes from the same building blocks as `minimal_topology`: a
topology, and an endhost API and a SNAP for each AS.
[From a local SCION network to a real network](./real-network.md#the-local-scion-network) shows
the code.

## Where to go next

- **[PocketSCION](https://github.com/Anapaya/scion-sdk/tree/main/crates/pocketscion):** the other
  topologies and underlays that you can simulate.
- **[The chat application](./overview.md):** the other pages of this section.
