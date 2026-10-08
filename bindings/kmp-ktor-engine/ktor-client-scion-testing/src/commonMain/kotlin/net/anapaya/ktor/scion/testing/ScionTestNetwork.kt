// Copyright 2026 Anapaya Systems

package net.anapaya.ktor.scion.testing

import net.anapaya.ktor.scion.ScionEngineConfig
import net.anapaya.ktor.scion.ScionTokenSource
import net.anapaya.ktor.scion.ScionUnderlay
import uniffi.ktor_scion_testing.TestNetwork
import uniffi.ktor_scion_testing.TestNetworkException
import uniffi.ktor_scion_testing.TestNetworkOptions
import uniffi.ktor_scion_testing.TestUnderlay

/**
 * A PocketSCION topology in the test process, for tests that send requests
 * with the Ktor SCION engine.
 *
 * The client attaches to AS 1-ff00:0:132. A server of the user attaches to
 * AS 2-ff00:0:212 through [serverEndhostApiUrl] and [authToken], and gets
 * the SCION address [serverAddress]. For the WebGateway mode, the built-in
 * server plays the gateway at [gatewayPort]. It connects each tunnel to a
 * gateway backend over TCP. The built-in server also serves a test API at
 * [testApiUrl].
 *
 * Each network has its own ports, token, and CA. [close] stops it. The
 * garbage collector also stops a network that nothing refers to, so keep a
 * reference while tests use it.
 */
public class ScionTestNetwork private constructor(
    private val network: TestNetwork,
    internal val gatewayHosts: List<String>,
) : AutoCloseable {
    private val description = network.description()

    /** The endhost API of AS 1-ff00:0:132, for the client. */
    public val endhostApiUrl: String = description.endhostApiUrl

    /** The endhost API of AS 2-ff00:0:212, for a server of the user. */
    public val serverEndhostApiUrl: String = description.serverEndhostApiUrl

    /** The token for both endhost APIs and the SNAP control plane. */
    public val authToken: String = description.authToken

    /** The SCION address of a server in AS 2-ff00:0:212 on this host, without a port. */
    public val serverAddress: String = description.serverAddress

    /** The port for `ScionWebGateway`. */
    public val gatewayPort: Int = description.gatewayPort.toInt()

    /** `https://localhost:<port>`, the test API of the built-in server. */
    public val testApiUrl: String = description.testApiUrl

    /** The CA of the test API. */
    public val testApiCaPem: String = description.testApiCaPem

    /**
     * A CA that signs no certificate of the network. A client that trusts
     * only this CA rejects every server of the network.
     */
    public val untrustedCaPem: String = description.untrustedCaPem

    /** Stops the topology. A second call does nothing. */
    override fun close() {
        network.stop()
        network.close()
    }

    /** What a network starts with. */
    public class Options internal constructor() {
        /**
         * How the client and the server enter the network. [ScionUnderlay.Udp]
         * gives each AS a router that they reach over UDP.
         * [ScionUnderlay.Snap] gives each AS a SNAP instead. The endhost APIs
         * offer only this underlay, so the engine uses it, even if its
         * `preferredUnderlay` names the other one.
         */
        public var underlay: ScionUnderlay = ScionUnderlay.Udp

        internal val gatewayBackends: MutableMap<String, String> = linkedMapOf()

        /**
         * Connects each `CONNECT` tunnel to [authority] to the TCP backend
         * [target], as `ip:port`. [authority] is `host` or `host:port`. A key
         * with a port matches only that port, and it wins over a key without
         * a port.
         */
        public fun gatewayBackend(authority: String, target: String) {
            gatewayBackends[authority] = target
        }
    }

    public companion object {
        /** Starts a network and returns once it serves. */
        public fun start(options: Options.() -> Unit = {}): ScionTestNetwork {
            // Start the topology.
            val settings = Options().apply(options)
            val network = try {
                TestNetwork.start(
                    TestNetworkOptions(
                        underlay = when (settings.underlay) {
                            ScionUnderlay.Udp -> TestUnderlay.UDP
                            ScionUnderlay.Snap -> TestUnderlay.SNAP
                        },
                        gatewayBackends = settings.gatewayBackends.toMap(),
                    ),
                )
            } catch (failure: TestNetworkException) {
                throw IllegalStateException("cannot start the SCION test network: ${failure.message}", failure)
            }

            // Remember the gateway hosts for useTestNetwork.
            val gatewayHosts = settings.gatewayBackends.keys.map { it.substringBefore(':') }.distinct()
            return ScionTestNetwork(network, gatewayHosts)
        }
    }
}

/**
 * Points this engine at [network]. It sets `endhostApiUrl`, `tokenSource`, and
 * a DNS override to [ScionTestNetwork.serverAddress] for `localhost`, for the
 * host of each gateway backend, and for each of [hosts].
 *
 * It does not set `caCertificatesPem`, because a server of the user has its
 * own CA. For the test API, set it to [ScionTestNetwork.testApiCaPem].
 */
public fun ScionEngineConfig.useTestNetwork(network: ScionTestNetwork, vararg hosts: String) {
    // Attach to the network.
    endhostApiUrl = network.endhostApiUrl
    tokenSource = ScionTokenSource.Static(network.authToken)

    // Point the hosts at the test server.
    for (host in listOf("localhost") + network.gatewayHosts + hosts) {
        dnsOverride(host, network.serverAddress)
    }
}
