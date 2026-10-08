// Copyright 2026 Anapaya Systems

@file:OptIn(InternalAPI::class)

package net.anapaya.ktor.scion

import io.ktor.client.engine.HttpClientEngineBase
import io.ktor.client.engine.HttpClientEngineCapability
import io.ktor.client.engine.callContext
import io.ktor.client.engine.mergeHeaders
import io.ktor.client.network.sockets.ConnectTimeoutException
import io.ktor.client.plugins.HttpRequestTimeoutException
import io.ktor.client.plugins.HttpTimeoutCapability
import io.ktor.client.request.HttpRequestData
import io.ktor.client.request.HttpResponseData
import io.ktor.http.HeadersBuilder
import io.ktor.http.HttpHeaders
import io.ktor.http.HttpProtocolVersion
import io.ktor.http.HttpStatusCode
import io.ktor.util.date.GMTDate
import io.ktor.utils.io.ByteReadChannel
import io.ktor.utils.io.InternalAPI
import kotlinx.coroutines.CoroutineDispatcher
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.Job
import uniffi.ktor_scion_core.CoreConfig
import uniffi.ktor_scion_core.CoreDnsOverride
import uniffi.ktor_scion_core.CoreException
import uniffi.ktor_scion_core.CoreHeader
import uniffi.ktor_scion_core.CoreHttpVersion
import uniffi.ktor_scion_core.CoreRequest
import uniffi.ktor_scion_core.CoreResponse
import uniffi.ktor_scion_core.CoreTokenSource
import uniffi.ktor_scion_core.CoreUnderlay
import uniffi.ktor_scion_core.CoreWebGateway
import uniffi.ktor_scion_core.ScionCore
import kotlin.coroutines.CoroutineContext

/**
 * Headers that the Rust library does not take from Ktor.
 *
 * HTTP/3 forbids the connection-specific ones. The Rust library writes the
 * length of the body itself, and hyper writes the host in the gateway mode.
 */
private val CORE_OWNED_HEADERS = setOf(
    HttpHeaders.ContentLength,
    HttpHeaders.TransferEncoding,
    HttpHeaders.Connection,
    HttpHeaders.Upgrade,
    "Keep-Alive",
    "Proxy-Connection",
    HttpHeaders.Host,
).mapTo(HashSet()) { it.lowercase() }

internal class ScionEngine(
    override val config: ScionEngineConfig,
) : HttpClientEngineBase("scion") {

    override val dispatcher: CoroutineDispatcher = Dispatchers.Default

    override val supportedCapabilities: Set<HttpClientEngineCapability<*>> =
        setOf(HttpTimeoutCapability)

    private val core = run {
        initPlatformTrust()
        ScionCore(config.toCore())
    }

    init {
        // Ktor completes this job in close(), after the requests in flight end.
        // An earlier close would cancel them.
        coroutineContext[Job]?.invokeOnCompletion { core.close() }
    }

    override suspend fun execute(data: HttpRequestData): HttpResponseData {
        // Read the request.
        val callContext = callContext()
        val requestTime = GMTDate()
        val body = data.body.readAllBytes(callContext)
        val timeoutMillis = data.getCapabilityOrNull(HttpTimeoutCapability)
            ?.requestTimeoutMillis
            ?.takeIf { it > 0 }
            ?: 0L

        // Drop the headers that the Rust library owns.
        val headers = ArrayList<CoreHeader>()
        mergeHeaders(data.headers, data.body) { key, value ->
            if (key.lowercase() !in CORE_OWNED_HEADERS) headers += CoreHeader(key, value)
        }

        // UniFFI does not promise to drop the Rust future on cancellation, so
        // the id is the channel back to Rust. Each id needs one release.
        val requestId = core.nextRequestId()
        val response = try {
            core.execute(
                requestId,
                CoreRequest(
                    method = data.method.value,
                    url = data.url.toString(),
                    headers = headers,
                    body = body,
                    timeoutMs = timeoutMillis.toULong(),
                ),
            )
        } catch (cause: CoreException) {
            throw toException(data, cause, timeoutMillis)
        } finally {
            core.release(requestId)
        }

        return response.toKtor(requestTime, callContext)
    }
}

private fun ScionEngineConfig.toCore(): CoreConfig {
    val token = when (val source = tokenSource) {
        is ScionTokenSource.AnapayaAa -> CoreTokenSource.AnapayaAa(
            apiKey = source.apiKey,
            url = source.url,
            deviceId = source.deviceId,
        )
        is ScionTokenSource.Static -> CoreTokenSource.Static(token = source.token)
        null -> null
    }

    val underlay = when (preferredUnderlay) {
        ScionUnderlay.Snap -> CoreUnderlay.SNAP
        ScionUnderlay.Udp -> CoreUnderlay.UDP
        null -> null
    }

    // Check the gateway port.
    val gateway = webGateway?.let {
        require(it.port in 1..65535) { "the gateway port ${it.port} is out of range" }
        CoreWebGateway(port = it.port.toUShort())
    }

    return CoreConfig(
        endhostApiUrl = endhostApiUrl,
        tokenSource = token,
        preferredUnderlay = underlay,
        caCertificatesPem = caCertificatesPem?.encodeToByteArray(),
        controlPlaneCaCertificatesPem = controlPlaneCaCertificatesPem?.encodeToByteArray(),
        acceptInvalidCerts = acceptInvalidCertificates,
        dnsOverrides = dnsOverrides.map { (host, addresses) -> CoreDnsOverride(host, addresses) },
        connectTimeoutMs = connectTimeoutMillis,
        requestTimeoutMs = requestTimeoutMillis,
        idleTimeoutMs = idleConnectionTimeoutMillis,
        maxOrigins = maxOrigins,
        connectionAttemptDelayMs = connectionAttemptDelayMillis,
        maxResponseBodyBytes = maxResponseBodyBytes,
        webGateway = gateway,
    )
}

private fun CoreResponse.toKtor(
    requestTime: GMTDate,
    callContext: CoroutineContext,
): HttpResponseData {
    // Copy the headers.
    val builder = HeadersBuilder()
    for (header in headers) builder.append(header.name, header.value)

    val protocol = when (version) {
        CoreHttpVersion.HTTP11 -> HttpProtocolVersion.HTTP_1_1
        CoreHttpVersion.HTTP3 -> HttpProtocolVersion.HTTP_3_0
    }
    return HttpResponseData(
        statusCode = HttpStatusCode.fromValue(status.toInt()),
        requestTime = requestTime,
        headers = builder.build(),
        version = protocol,
        body = ByteReadChannel(body),
        callContext = callContext,
    )
}

private fun toException(
    data: HttpRequestData,
    cause: CoreException,
    timeoutMillis: Long,
): Throwable = when {
    // The Rust library timed out on the budget that the HttpTimeout plugin set.
    cause is CoreException.Timeout && timeoutMillis > 0 ->
        HttpRequestTimeoutException(data.url.toString(), timeoutMillis, cause)

    cause is CoreException.ConnectTimeout ->
        ConnectTimeoutException("${data.method.value} ${data.url}: ${cause.message}", cause)

    else -> ScionEngineException("${data.method.value} ${data.url}: ${cause.message}", cause)
}
