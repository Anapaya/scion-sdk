---
title: The chat application
sidebar_position: 1
description: An example application on the SDK. Where the SDK is in its server and its three clients, and the one design that the clients share.
---

import ChatOverview from './fig/chat-overview.drawio.svg';

The [chat application](https://github.com/Anapaya/scion-sdk-chat/tree/main) is an example
application on the SCION SDK. It has one server and three clients: a terminal client in Rust, an Android
app and an iOS app. Every request between a client and the server is HTTP/3 over SCION.

The pages in this section explain the SDK topics that the chat shows. To build and run the chat,
read the [README of the chat](https://github.com/Anapaya/scion-sdk-chat/blob/main/README.md).

## One server, three clients

<ChatOverview
  className="svg-diagram"
  role="img"
  aria-label="The server, the three clients and the local SCION network of the chat"
/>

The parts in the figure:

- **chat-server** serves the API over HTTP/3 on SCION, built on `scion-stack` and `scion-h3-axum`.
- **chat-dev** starts a SCION network on your machine, built on `pocketscion`, with the chat
  server in it.
- **Terminal client** is the chat client for the terminal, built on `scion-http3`.
- **Android app** is the chat client for Android, built on `scion-http3-android`.
- **iOS app** is the chat client for iOS, built on `scion-http3-swift`.

## Where the SDK is

The SDK is in one file for each role. Each row links to the file and to the page that explains it.

| Role | File | Explained on |
| --- | --- | --- |
| The server | [`chat-server/src/scion.rs`](https://github.com/Anapaya/scion-sdk-chat/blob/main/crates/chat-server/src/scion.rs) | [The server](./server.md) |
| A client, in Rust | [`transport/scion.rs`](https://github.com/Anapaya/scion-sdk-chat/blob/main/crates/chat-client-core/src/transport/scion.rs) | [The client](./client.md) |
| A client, on Android | [`ScionTransport.kt`](https://github.com/Anapaya/scion-sdk-chat/blob/main/android/chat-client/src/main/kotlin/com/anapaya/chat/client/ScionTransport.kt) | [The Android client](./mobile.md#the-android-client) |
| A client, on iOS | [`ScionTransport.swift`](https://github.com/Anapaya/scion-sdk-chat/blob/main/ios/ChatClient/Sources/ChatClient/ScionTransport.swift) | [The iOS client](./mobile.md#the-ios-client) |
| A SCION network on your machine | [`topology.rs`](https://github.com/Anapaya/scion-sdk-chat/blob/main/crates/chat-dev/src/topology.rs) | [From a local SCION network to a real network](./real-network.md) |
| All of the above, in one test | [`tests/scion.rs`](https://github.com/Anapaya/scion-sdk-chat/blob/main/crates/chat-client-core/tests/scion.rs) | [Testing against PocketSCION](./testing.md) |

## One design for three clients

The three clients have the same structure. In each app, one module depends on the SDK, and one file
imports the SDK: the transport. The transport has three parts:

- It builds the client.
- It sends a request.
- It maps the errors of the SDK to the errors of the app.

The rest of each app calls the transport through a `Transport` interface of its own. The SDK renews
the token for the transport. [The client](./client.md) shows the three parts in Rust, and
[The mobile clients](./mobile.md) shows them in Kotlin and Swift.

## Where to go next

- **[The server](./server.md):** serve an Axum router over HTTP/3 on SCION.
- **[The client](./client.md):** the HTTP/3 client in Rust.
- **[The mobile clients](./mobile.md):** the Android and iOS clients.
- **[From a local SCION network to a real network](./real-network.md):** what changes when the
  chat moves from PocketSCION to a real SCION network.
- **[Testing against PocketSCION](./testing.md):** a test with the server in one AS and the client in
  another.
