---
title: WebGateway
sidebar_position: 2
description: Send the requests of a Ktor client through a PathGuard WebGateway.
---

A WebGateway gives an HTTP API a SCION address. The API stays on TCP. The gateway in front of it
accepts the connections over SCION. With a gateway, an app can use SCION for an API that does not
support SCION itself. The gateway is part of
[Anapaya PathGuard](https://learn.anapaya.net/docs/products-and-use-cases/products/anapaya-pathguard).

The engine has two transports:

| Transport  | Setting      | On the wire                                                                                 |
| ---------- | ------------ | ------------------------------------------------------------------------------------------- |
| HTTP/3     | default      | HTTP/3 over QUIC over SCION, to the origin                                                  |
| WebGateway | `webGateway` | HTTP/1.1 over TLS, in an HTTP/3 `CONNECT` tunnel over SCION, to a PathGuard WebGateway      |

The [Ktor client](ktor-client.md) guide covers the first transport. This page covers the second.

## Send the requests through a gateway

The sample `app-testing` has an API client that knows nothing about SCION, and the client that the
app ships with:

```kotlin reference="@sdk/bindings/kmp-ktor-engine/samples/app-testing/src/commonMain/kotlin/net/anapaya/ktor/scion/sample/testing/GreetingApi.kt#api" title="GreetingApi.kt"
```

```kotlin reference="@sdk/bindings/kmp-ktor-engine/samples/app-testing/src/commonMain/kotlin/net/anapaya/ktor/scion/sample/testing/GreetingApi.kt#production-client" title="GreetingApi.kt"
```

`webGateway = ScionWebGateway()` sends each request of this client through a gateway. For requests
over HTTP/3 to an origin, use a second client without `webGateway`.

## How the engine finds the gateway

The gateway is transparent. The engine has no setting for the address of the gateway. The engine
resolves the host of the request URL, and it expects the gateway at that SCION address. For a host
behind a gateway, the TSAR record of the host holds the SCION address of the gateway.

The engine connects to port 443 of the gateway. To use a different port, set
`ScionWebGateway(port = ...)`.

### A host without a TSAR record

If the host has no TSAR record, call `dnsOverride` with the SCION address of the gateway. In this
example, the gateway has the SCION address `1-ff00:0:110,192.0.2.10`, and the app sends its requests
to `api.example.com`:

```kotlin
val client = HttpClient(ScionHttp) {
    engine {
        tokenSource = ScionTokenSource.AnapayaAa(apiKey = key)
        webGateway = ScionWebGateway()
        dnsOverride("api.example.com", "1-ff00:0:110,192.0.2.10")
    }
}

val response = client.get("https://api.example.com/accounts")
```

- The first argument is the host of the request URL. It is not a name of the gateway.
- The address has the form `<ISD>-<AS>,<IP>`. Do not add brackets or a port.
- Call `dnsOverride` once for each host that the app sends through the gateway. All calls use the
  same gateway address.

The sample `hello-scion` does the same with its `--gateway-address` option:

```kotlin reference="@sdk/bindings/kmp-ktor-engine/samples/hello-scion/src/commonMain/kotlin/net/anapaya/ktor/scion/sample/Main.kt#gateway" title="Main.kt"
```

## The tunnel

The engine opens the tunnel with `CONNECT <request host>:<request port>`. The gateway selects the
backend by that authority, and connects the tunnel to the backend over TCP.

The connection to the origin runs end to end in the tunnel:

- With an `https` URL, TLS runs from the engine to the origin, so the gateway sees no plain text.
  `caCertificatesPem` and the platform verifier apply to this TLS session.
- With an `http` URL, no TLS runs in the tunnel, and the gateway sees the HTTP requests. Use `http`
  for tests only.

The engine does not check the certificate of the gateway. The TLS session in the tunnel
authenticates the origin.

## Test the gateway

`ktor-client-scion-testing` has a gateway in the test process. [Testing your
app](testing.md#test-an-api-behind-a-gateway) tests the sample above against an API on TCP.
