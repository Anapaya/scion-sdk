// Copyright 2026 Anapaya Systems

package net.anapaya.ktor.scion

import io.ktor.client.engine.HttpClientEngine
import io.ktor.client.engine.HttpClientEngineConfig
import io.ktor.client.engine.HttpClientEngineFactory

/**
 * Ktor engine that sends HTTP over SCION.
 *
 * The transport can be configured to be either:
 * - HTTP/3 over SCION directly to the origin
 * - HTTP/1.1 over SCION through a [ScionWebGateway]
 *
 * ```
 * val client = HttpClient(ScionHttp) {
 *     engine { tokenSource = ScionTokenSource.AnapayaAa(apiKey = key) }
 * }
 * ```
 *
 * See [ScionEngineConfig] for the engine settings.
 */
public object ScionHttp : HttpClientEngineFactory<ScionEngineConfig> {
    override fun create(block: ScionEngineConfig.() -> Unit): HttpClientEngine =
        ScionEngine(ScionEngineConfig().apply(block))
}

/** Where the engine gets the token for the endhost API and the SNAP control plane. */
public sealed class ScionTokenSource {
    /**
     * Gets the token from the Anapaya AA with [apiKey] and renews it before it
     * expires. A `null` value keeps the default of the Rust library.
     */
    public class AnapayaAa(
        public val apiKey: String,
        /** The URL of the AA. */
        public val url: String? = null,
        /** The device ID that the engine sends to the AA. */
        public val deviceId: String? = null,
    ) : ScionTokenSource()

    /**
     * A fixed token. It stays for the life of the client, so a new token
     * needs a new client. Use it for tests only.
     */
    public class Static(public val token: String) : ScionTokenSource()
}

/** The underlay to prefer if the endhost API offers both. */
public enum class ScionUnderlay { Snap, Udp }

/**
 * A PathGuard WebGateway that the engine sends each request through.
 *
 * The gateway is transparent. The engine resolves the request host through
 * TSAR or [ScionEngineConfig.dnsOverride], and expects the gateway at that
 * address, at [port].
 *
 * It opens an HTTP/3 `CONNECT` tunnel over SCION to the gateway, with the
 * request host and port as the authority.
 *
 * The gateway selects the backend by that authority and connects the tunnel
 * to it over TCP.
 *
 * TLS to the origin and HTTP/1.1 run inside the tunnel, so the gateway
 * sees no plain text.
 *
 * The engine does not check the certificate of the gateway itself. The TLS
 * session inside the tunnel authenticates the origin.
 */
public class ScionWebGateway(
    /** The port of the gateway. */
    public val port: Int = 443,
)

/**
 * Settings of the engine.
 *
 * A `null` value keeps the default of the Rust library. The defaults live in
 * `rust/src/engine/config.rs`. The engine reads this config once, when the
 * client starts.
 *
 * The Rust library rejects a time or a count that is 0 or less. Only
 * [connectionAttemptDelayMillis] accepts 0.
 *
 * [HttpClientEngineConfig.proxy] has no effect.
 */
public class ScionEngineConfig : HttpClientEngineConfig() {

    /**
     * A fixed endhost API. If `null`, the client discovers the endhost APIs:
     * through the URL that the AA sends, else through the global discovery
     * service.
     */
    public var endhostApiUrl: String? = null

    /** If `null`, the engine sends no token. */
    public var tokenSource: ScionTokenSource? = null

    /** The underlay to prefer. `null` keeps the default, UDP. */
    public var preferredUnderlay: ScionUnderlay? = null

    /**
     * Trust anchors for origin certificates, as a PEM bundle.
     *
     * If `null`, the Rust library uses the platform verifier, which trusts the
     * CAs of the device. On Android, these are the system CAs and the user
     * CAs. The Network Security Config of the app has no effect on them.
     */
    public var caCertificatesPem: String? = null

    /**
     * Trust anchors for the AA, the discovery service, the endhost API, and
     * the SNAP control plane, as a PEM bundle. The same `null` rule as
     * [caCertificatesPem] applies.
     */
    public var controlPlaneCaCertificatesPem: String? = null

    /**
     * Sends each request through this WebGateway. `null` sends each request
     * over HTTP/3 to the origin.
     *
     * With a gateway, [caCertificatesPem] and [acceptInvalidCertificates]
     * apply to the TLS session inside the tunnel.
     */
    public var webGateway: ScionWebGateway? = null

    /** Turns off origin certificate checks. Use it for tests only. */
    public var acceptInvalidCertificates: Boolean = false

    /** Time budget for name resolution and all connection attempts to an origin. */
    public var connectTimeoutMillis: Long? = null

    /** Time budget for a whole request. The `HttpTimeout` plugin overrides it per request. */
    public var requestTimeoutMillis: Long? = null

    /** Time an idle pooled connection stays open. */
    public var idleConnectionTimeoutMillis: Long? = null

    /** Distinct origins that the pool keeps a connection to. */
    public var maxOrigins: Int? = null

    /** Delay between connection attempts to the candidate addresses of one origin. */
    public var connectionAttemptDelayMillis: Long? = null

    /**
     * Largest response body that the Rust library accepts. The Rust library
     * buffers the body in memory, so this bounds the memory of one request.
     * `null` keeps 16 MiB.
     */
    public var maxResponseBodyBytes: Long? = null

    internal val dnsOverrides: MutableMap<String, List<String>> = linkedMapOf()

    /**
     * Resolves [host] to fixed SCION [addresses] instead of through DNS. Use
     * it for a host without TSAR records. Each address has the form
     * `<isd>-<as>,<ip>`, without a port.
     */
    public fun dnsOverride(host: String, vararg addresses: String) {
        dnsOverrides[host] = addresses.toList()
    }
}
