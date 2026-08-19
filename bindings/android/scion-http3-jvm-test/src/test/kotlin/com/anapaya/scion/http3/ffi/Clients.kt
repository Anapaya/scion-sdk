// Copyright 2026 Anapaya Systems

package com.anapaya.scion.http3.ffi

import com.anapaya.scion.http3.uniffi.ClientConfig
import com.anapaya.scion.http3.uniffi.HttpRequest
import com.anapaya.scion.http3.uniffi.ScionHttp3Client
import com.anapaya.scion.http3.uniffi.TrustAnchors
import com.anapaya.scion.http3.uniffi.defaultClientConfig

/**
 * A client pointed at [server], with the topology's token and its self-signed anchor.
 *
 * The timeouts are shortened from the defaults so that a test which is going to fail does so while
 * someone is still watching.
 */
fun clientFor(
    server: TestServer,
    configure: (ClientConfig) -> ClientConfig = { it },
): ScionHttp3Client {
    val config =
        defaultClientConfig(server.endpoints.endhostApiUrl).copy(
            authToken = server.endpoints.authToken,
            trust = TrustAnchors.Pem(server.endpoints.caPem.toByteArray()),
            connectTimeoutMs = 15_000u,
            requestTimeoutMs = 30_000u,
        )
    return ScionHttp3Client(configure(config))
}

/**
 * A request to [path] on [server], addressed by SCION address rather than by name.
 *
 * The topology has no TSAR records, and a resolver override is not part of the exported surface, so
 * every request that is meant to succeed goes through the target escape hatch. Name resolution
 * itself is covered by `scion-http3`'s own end-to-end tests.
 */
fun requestTo(
    server: TestServer,
    path: String,
    configure: (HttpRequest) -> HttpRequest = { it },
): HttpRequest =
    configure(HttpRequest(url = server.url(path), targets = listOf(server.endpoints.target)))

/** The response body as text. */
fun ByteArray.asText(): String = toString(Charsets.UTF_8)
