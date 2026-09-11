// Copyright 2026 Anapaya Systems

package com.anapaya.scion.http3.ffi

import com.anapaya.scion.http3.uniffi.ClientConfig
import com.anapaya.scion.http3.uniffi.DnsOverride
import com.anapaya.scion.http3.uniffi.HttpRequest
import com.anapaya.scion.http3.uniffi.ScionHttp3Client
import com.anapaya.scion.http3.uniffi.TrustAnchors
import com.anapaya.scion.http3.uniffi.defaultClientConfig
import java.net.URI

/**
 * A client pointed at [server], with the topology's token and its self-signed anchor.
 *
 * The topology has no TSAR records, so the server's host is resolved through a DNS override
 * instead. Name resolution itself is covered by `scion-http3`'s own end-to-end tests.
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
            dnsOverrides = listOf(server.dnsOverride()),
            connectTimeoutMs = 15_000u,
            requestTimeoutMs = 30_000u,
        )
    return ScionHttp3Client(configure(config))
}

/**
 * A DNS override that resolves [TestServer]'s host to [addresses], by default its own address.
 */
fun TestServer.dnsOverride(vararg addresses: String = arrayOf(endpoints.target)): DnsOverride =
    DnsOverride(host = URI(endpoints.baseUrl).host, addresses = addresses.toList())

/** A request to [path] on [server]. */
fun requestTo(
    server: TestServer,
    path: String,
    configure: (HttpRequest) -> HttpRequest = { it },
): HttpRequest = configure(HttpRequest(url = server.url(path)))

/** The response body as text. */
fun ByteArray.asText(): String = toString(Charsets.UTF_8)
