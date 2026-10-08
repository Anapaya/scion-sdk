// Copyright 2026 Anapaya Systems

package net.anapaya.ktor.scion

import io.ktor.client.HttpClient
import io.ktor.client.HttpClientConfig
import net.anapaya.ktor.scion.testing.ScionTestNetwork

/**
 * The test network that all tests of the process share. It runs in the
 * process, through `ktor-client-scion-testing`, until the process ends.
 */
internal class TestNetwork private constructor(
    // Keeps the network alive. See ScionTestNetwork.
    private val network: ScionTestNetwork,
) {
    val endhostApiUrl: String = network.endhostApiUrl
    val authToken: String = network.authToken

    /** `https://localhost:<port>`. */
    val baseUrl: String = network.testApiUrl

    /** The SCION address of the server, without a port. */
    val target: String = network.serverAddress
    val caPem: String = network.testApiCaPem

    /** A CA that signs nothing in the topology. */
    val wrongCaPem: String = network.untrustedCaPem

    companion object {
        val current: TestNetwork by lazy { TestNetwork(ScionTestNetwork.start()) }
    }
}

/** A client that reaches the test server: its endhost API, token, CA, and address. */
internal fun scionClient(
    engine: ScionEngineConfig.() -> Unit = {},
    client: HttpClientConfig<ScionEngineConfig>.() -> Unit = {},
): HttpClient {
    val network = TestNetwork.current
    return HttpClient(ScionHttp) {
        engine {
            endhostApiUrl = network.endhostApiUrl
            tokenSource = ScionTokenSource.Static(network.authToken)
            caCertificatesPem = network.caPem
            dnsOverride("localhost", network.target)
            engine()
        }
        client()
    }
}
