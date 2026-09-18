// Copyright 2026 Anapaya Systems

package com.anapaya.scion.http3.hello

import com.anapaya.scion.http3.ScionHttp3Client
import com.anapaya.scion.http3.ScionTunnelSocket
import com.anapaya.scion.http3.ScionTunnelSocketFactory
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import okhttp3.Dns
import okhttp3.OkHttpClient
import okhttp3.Request
import java.io.ByteArrayOutputStream
import java.net.InetAddress
import java.net.InetSocketAddress
import java.net.URI
import java.net.UnknownHostException

/**
 * Three ways to carry bytes that are not HTTP/3 through a `CONNECT` tunnel over SCION.
 *
 * The test network's server echoes what a tunnel to its own host carries and serves HTTP/1.1
 * inside a tunnel to [HTTP_HOST].
 */
class Tunnels(
    private val client: ScionHttp3Client,
    network: LocalNetwork,
) {
    private val echoHost = URI(network.baseUrl).host
    private val port = URI(network.baseUrl).port

    // ANCHOR: byte-stream

    /** Sends [message] through a tunnel to the echo and reads back what comes out. */
    suspend fun echo(message: String): String =
        client.openTunnel(echoHost, port).use { tunnel ->
            tunnel.write(message.encodeToByteArray())
            // The peer sees the end of the stream. The echo ends its side in turn.
            tunnel.shutdownWrite()

            val received = ByteArrayOutputStream()
            while (true) {
                val chunk = tunnel.read(4096)
                if (chunk.isEmpty()) break
                received.write(chunk)
            }
            received.toString(Charsets.UTF_8.name())
        }
    // ANCHOR_END: byte-stream

    // ANCHOR: socket

    suspend fun echoThroughSocket(message: String): String =
        withContext(Dispatchers.IO) {
            ScionTunnelSocket(client).use { socket ->
                socket.connect(InetSocketAddress.createUnresolved(echoHost, port))
                socket.getOutputStream().write(message.encodeToByteArray())
                socket.shutdownOutput()
                socket.getInputStream().readBytes().decodeToString()
            }
        }
    // ANCHOR_END: socket

    // ANCHOR: okhttp
    private val okHttp =
        OkHttpClient
            .Builder()
            .socketFactory(ScionTunnelSocketFactory(client))
            // OkHttp resolves the host before it asks for a socket. A host that exists on SCION
            // alone has no A record.
            .dns(
                object : Dns {
                    override fun lookup(hostname: String): List<InetAddress> {
                        if (hostname != HTTP_HOST) throw UnknownHostException(hostname)
                        return listOf(InetAddress.getByAddress(hostname, byteArrayOf(0, 0, 0, 0)))
                    }
                },
            ).build()

    /** `GET /hello` with OkHttp, as HTTP/1.1 inside a tunnel. */
    suspend fun fetchWithOkHttp(): HelloScion.Reply =
        withContext(Dispatchers.IO) {
            val request = Request.Builder().url("http://$HTTP_HOST:$port/hello").build()
            okHttp.newCall(request).execute().use { response ->
                HelloScion.Reply(response.code, response.body?.string().orEmpty())
            }
        }
    // ANCHOR_END: okhttp

    companion object {
        /** The host the test network's server answers a tunnel to with HTTP/1.1. */
        const val HTTP_HOST = "http.invalid"
    }
}
