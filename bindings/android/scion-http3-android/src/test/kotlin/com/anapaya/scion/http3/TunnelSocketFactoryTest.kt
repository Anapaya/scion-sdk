// Copyright 2026 Anapaya Systems

package com.anapaya.scion.http3

import okhttp3.Dns
import okhttp3.OkHttpClient
import okhttp3.Request
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertFalse
import org.junit.jupiter.api.Assertions.assertInstanceOf
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.assertThrows
import java.net.InetAddress
import java.net.InetSocketAddress
import java.net.UnknownHostException
import com.anapaya.scion.http3.uniffi.ScionHttp3Exception as FfiException

class TunnelSocketFactoryTest {
    private val factory = FakeBackendFactory()
    private val sockets = ScionTunnelSocketFactory(client(factory = factory))
    private val address = InetAddress.getByAddress("chat.example.org", bytesOf(10, 0, 0, 1))

    @Test
    fun `the no-argument form is an unconnected tunnel socket`() {
        val socket = sockets.createSocket()

        assertInstanceOf(ScionTunnelSocket::class.java, socket)
        assertFalse(socket.isConnected)
        assertTrue(factory.backend.targets.isEmpty())
    }

    @Test
    fun `the other forms come back connected, and the local address is ignored`() {
        sockets.createSocket("chat.example.org", 5222)
        sockets.createSocket(
            "chat.example.org",
            5223,
            InetAddress.getByAddress(bytesOf(127, 0, 0, 1)),
            4,
        )
        sockets.createSocket(address, 443)
        sockets.createSocket(address, 444, null, 0)

        assertEquals(
            listOf(
                "chat.example.org:5222",
                "chat.example.org:5223",
                "chat.example.org:443",
                "chat.example.org:444",
            ),
            factory.backend.targets,
        )
    }

    @Test
    fun `with a via port every form dials the via port`() {
        val sockets = ScionTunnelSocketFactory(client(factory = factory), viaPort = 443)

        sockets.createSocket().connect(InetSocketAddress.createUnresolved("chat.example.org", 5222))
        sockets.createSocket("chat.example.org", 5222)
        sockets.createSocket(address, 8765)

        assertEquals(
            listOf("chat.example.org:5222", "chat.example.org:5222", "chat.example.org:8765"),
            factory.backend.targets,
        )
        assertEquals(List(3) { "chat.example.org:443" }, factory.backend.vias)
    }

    @Test
    fun `a via port out of range is refused`() {
        assertThrows<IllegalArgumentException> {
            ScionTunnelSocketFactory(client(factory = factory), viaPort = 0)
        }
    }

    @Test
    fun `OkHttp sends a request through the socket and reads the answer`() {
        val tunnel = factory.backend.tunnel
        tunnel.reads.addLast(
            "HTTP/1.1 200 OK\r\nContent-Length: 5\r\nConnection: close\r\n\r\nworld".toByteArray(),
        )
        val okHttp =
            OkHttpClient
                .Builder()
                .socketFactory(sockets)
                .dns(
                    object : Dns {
                        override fun lookup(hostname: String): List<InetAddress> {
                            if (hostname != "chat.example.org") throw UnknownHostException(hostname)
                            return listOf(InetAddress.getByAddress(hostname, bytesOf(0, 0, 0, 0)))
                        }
                    },
                ).build()
        val request = Request.Builder().url("http://chat.example.org:8080/hello").build()

        val body =
            okHttp.newCall(request).execute().use { response ->
                assertEquals(200, response.code)
                response.body!!.string()
            }

        assertEquals("world", body)
        assertEquals(listOf("chat.example.org:8080"), factory.backend.targets)
        val sent = tunnel.written.fold(ByteArray(0)) { all, part -> all + part }.decodeToString()
        assertTrue(sent.startsWith("GET /hello HTTP/1.1\r\n"), sent)
        assertTrue(sent.contains("Host: chat.example.org:8080\r\n"), sent)
        okHttp.dispatcher.executorService.shutdown()
    }

    @Test
    fun `a connect that fails leaves no socket behind`() {
        factory.backend.failure = FfiException.TunnelRefused(502u, true, "d")

        assertThrows<ScionHttp3Exception.TunnelRefused> {
            sockets.createSocket(
                "chat.example.org",
                5222,
            )
        }
    }
}
