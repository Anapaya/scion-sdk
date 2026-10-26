---
title: From a local SCION network to a real network
sidebar_position: 5
description: What chat-dev gives a client on your machine, what a real deployment gives in its place, and how trust and credentials change.
---

import ChatDevFlow from './fig/chat-dev-flow.drawio.svg';
import ChatDevTopology from './fig/chat-dev-topology.drawio.svg';

To run the chat on your machine, start `chat-dev`. `chat-dev` starts a SCION network on
[PocketSCION](https://docs.rs/pocketscion), a SCION network simulator, and starts the chat server in
that network. It also serves the `/info` endpoint, which gives a client every value that the client
needs to connect to the server: the endhost API, a credential, the URL and the SCION address of the
server, and the certificate of the server.

In a real deployment, no single place gives these values. The client gets each value from a
different source. This page compares the local SCION network with a real deployment, value by
value, and links to the page that explains each value.

## The local SCION network

`chat-dev` starts three ASes on [PocketSCION](https://docs.rs/pocketscion) and puts the chat server
in the middle AS. Each AS gets an endhost API and a SNAP endpoint:

```rust reference="@chat/crates/chat-dev/src/topology.rs#start" title="chat-dev/src/topology.rs"
```

The topology has one link from each client AS to the AS of the server:

```rust reference="@chat/crates/chat-dev/src/topology.rs#definition" title="chat-dev/src/topology.rs"
```

<ChatDevTopology
  className="svg-diagram"
  role="img"
  aria-label="Three ASes in two ISDs, with one core link from each client AS to the AS of the server"
/>

The network publishes one address for each AS. `1-ff00:0:132` publishes the address that `chat-dev`
binds, and every client that reaches that address attaches there. An Android emulator reaches your
machine at `10.0.2.2`, and inside the emulator `127.0.0.1` is the emulator itself. Thus the
emulator gets its own AS, `2-ff00:0:222`, which publishes `10.0.2.2`.

The underlay is SNAP, so a client behind a NAT can join.
[Transport underlays](../concepts/transport-underlays.md#the-snap-underlay) explains the SNAP
underlay.

## What chat-dev gives a client

`chat-dev` runs the local SCION network and the chat server in one process. It also serves the
settings that a client needs at `GET /info`, on its control port, 8099. `/info` is plain HTTP, and
it belongs to `chat-dev`, not to the chat server. A real deployment has no `/info`. A client uses
it in three steps:

<ChatDevFlow
  className="svg-diagram"
  role="img"
  aria-label="How a client uses /info, the local SCION network and the chat server"
/>

This is a sample of the response of `/info`:

```json
{
  "control_url": "http://127.0.0.1:8099",
  "endhost_api_url": "http://127.0.0.1:65263/",
  "client_isd_as": "1-ff00:0:132",
  "auth_token": "eyJ0eXAiOiJKV1Qi...",
  "base_url": "https://localhost:8443",
  "target": "2-ff00:0:212,127.0.0.1",
  "ca_path": "/tmp/.tmpTFIcwA/cert.pem",
  "chat_server_args": ["--transport", "scion", "--listen", "127.0.0.1:8443", "..."]
}
```

A client reads five values from it:

- `endhost_api_url` is where the client discovers its SCION connectivity.
- `auth_token` is a SNAP token. Each read of `/info` makes a new token.
- `base_url` is the URL of the chat server.
- `target` is the SCION address of the server, without a port.
- `ca_path` is the self-signed certificate of the server.

## What a real deployment gives

A real deployment gives a client the same values from other sources:

| A client needs | `chat-dev` gives | A real deployment gives | Explained on |
| --- | --- | --- | --- |
| An endhost API | `endhost_api_url`, over plain HTTP on your machine | the endhost API of the network operator, over HTTPS | [The ScionStack model](../concepts/scionstack-model.md#building-a-stack) |
| A credential | `auth_token`, one SNAP token | an API key, which the Anapaya AA exchanges for tokens | [Transport underlays](../concepts/transport-underlays.md#using-the-snap-underlay-tokens) |
| The URL of the server | `base_url`, `https://localhost:8443` | the public URL of the server, with a host name that the certificate of the server names | [The server](./server.md#the-listen-address) |
| The address of the server | `target` | a TSAR record in DNS for the host of the server | [The client](./client.md#reach-a-server-without-a-tsar-record) |
| Trust in the server | `ca_path`, a certificate to pin | a publicly trusted certificate, which the system roots trust | [The client](./client.md#trust-the-server) |

The chat client takes each of these values from its configuration. Thus the move to a real network
changes the configuration of the client, and the code stays the same.

## Trust and credentials

In the local SCION network, the chat server makes a self-signed certificate and logs its
fingerprint, as [The server](./server.md#the-certificate) shows. Each client pins that certificate.
`chat-dev` gives each client a SNAP token, and each client needs its own token. A token expires,
so a client with only a token stops working at that time.

In a real network, the server presents a publicly trusted certificate, and the clients trust it
through the system roots. Each client holds an API key. The SDK exchanges the key
with the Anapaya AA for a token, and renews the token while the client runs.

The server also uses the SNAP underlay, so it also needs a credential. In the local SCION network,
`chat-dev` writes a SNAP token to a file and gives the file to the server with `--auth-token-file`.
A SNAP token is short-lived, and an AA must issue a new token at regular intervals. Thus a token
file makes testing simple, but it is not a credential for a real network. In a real network, the
server gets an API key with `--auth-api-key-file`.

The AA URL uses `https`. The AA client accepts `http` only for a loopback host. The chat clients
and the chat server use the Anapaya AA at `https://auth.scion.anapaya.net` by default.

## A phone on the same network

By default, `chat-dev` binds to `127.0.0.1`, so only clients on your machine reach it. To connect a
phone on your local network, start `chat-dev` with `--bind-ip` and an address of your machine that
the phone reaches. Every part of the network then uses that address, and every client uses it too.
With such an address, an Android emulator reaches the default AS like every other client.

The README of the chat gives the commands, in
[From another machine](https://github.com/Anapaya/scion-sdk-chat/blob/main/README.md#from-another-machine).

## Where to go next

- **[Testing against PocketSCION](./testing.md):** the same building blocks, in a test.
- **[The topology](https://github.com/Anapaya/scion-sdk-chat/blob/main/README.md#the-topology)**
  in the README of the chat: the ASes and the addresses that they publish.
