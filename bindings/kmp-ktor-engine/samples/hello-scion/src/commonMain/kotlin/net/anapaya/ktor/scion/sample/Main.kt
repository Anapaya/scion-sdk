// Copyright 2026 Anapaya Systems

package net.anapaya.ktor.scion.sample

import io.ktor.http.Url
import kotlinx.coroutines.runBlocking
import net.anapaya.ktor.scion.ScionTokenSource
import net.anapaya.ktor.scion.ScionWebGateway

private const val USAGE = """usage: hello-scion [options] <api-key> <url> [endhost-api-url]

options:
  --gateway                  send the requests through a WebGateway. The
                             engine finds the gateway through TSAR.
  --gateway-address <addr>   send the requests through the WebGateway at the
                             SCION address <addr>, for example
                             1-ff00:0:110,192.0.2.10.
  --gateway-port <port>      the port of the WebGateway. The default is 443."""

/**
 * Sends requests over SCION, with an API key of the AA. The arguments are the
 * API key, the request URL, and optionally a fixed endhost API URL. Without
 * it, the client discovers the endhost APIs. The options send the requests
 * through a WebGateway.
 *
 * The same code runs on the JVM, over JNA, and on Kotlin/Native, over
 * cinterop.
 */
fun main(args: Array<String>): Unit = runBlocking {
    val arguments = parseArguments(args)
    if (arguments == null) {
        println(USAGE)
        return@runBlocking
    }

    runSample(arguments.url) {
        tokenSource = ScionTokenSource.AnapayaAa(apiKey = arguments.apiKey)
        endhostApiUrl = arguments.endhostApiUrl
        if (arguments.gateway) {
            webGateway = ScionWebGateway(port = arguments.gatewayPort)
        }
        arguments.gatewayAddress?.let { dnsOverride(Url(arguments.url).host, it) }
    }
}

private class Arguments(
    val apiKey: String,
    val url: String,
    val endhostApiUrl: String?,
    val gateway: Boolean,
    val gatewayAddress: String?,
    val gatewayPort: Int,
)

/** Returns `null` if [args] do not match [USAGE]. */
private fun parseArguments(args: Array<String>): Arguments? {
    var gateway = false
    var gatewayAddress: String? = null
    var gatewayPort = 443
    val positional = mutableListOf<String>()

    val remaining = args.iterator()
    while (remaining.hasNext()) {
        when (val arg = remaining.next()) {
            "--gateway" -> gateway = true
            "--gateway-address" -> {
                gateway = true
                gatewayAddress = if (remaining.hasNext()) remaining.next() else return null
            }
            "--gateway-port" -> {
                gateway = true
                gatewayPort = (if (remaining.hasNext()) remaining.next() else return null)
                    .toIntOrNull() ?: return null
            }
            else -> if (arg.startsWith("--")) return null else positional += arg
        }
    }

    if (positional.size !in 2..3) return null
    return Arguments(
        apiKey = positional[0],
        url = positional[1],
        endhostApiUrl = positional.getOrNull(2),
        gateway = gateway,
        gatewayAddress = gatewayAddress,
        gatewayPort = gatewayPort,
    )
}
