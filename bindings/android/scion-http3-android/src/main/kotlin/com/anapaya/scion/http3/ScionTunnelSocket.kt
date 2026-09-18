// Copyright 2026 Anapaya Systems
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//   http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package com.anapaya.scion.http3

import kotlinx.coroutines.TimeoutCancellationException
import kotlinx.coroutines.runBlocking
import kotlinx.coroutines.withTimeout
import java.io.InputStream
import java.io.InterruptedIOException
import java.io.OutputStream
import java.net.InetAddress
import java.net.InetSocketAddress
import java.net.Socket
import java.net.SocketAddress
import java.net.SocketException
import java.net.SocketImpl
import java.net.SocketOptions
import java.net.SocketTimeoutException
import java.util.concurrent.ConcurrentHashMap
import java.util.concurrent.atomic.AtomicBoolean
import java.util.concurrent.atomic.AtomicReference

/**
 * A `java.net.Socket` whose bytes travel through a `CONNECT` tunnel over SCION.
 *
 * Do not use one on the main thread. Every call blocks for a network round trip.
 *
 * The platform's `SSLSocket` layers over this socket, so TLS through the tunnel works.
 */
public class ScionTunnelSocket private constructor(
    impl: TunnelSocketImpl,
) : Socket(impl) {
    /** An unconnected socket over [client]. [connect] opens the tunnel. */
    public constructor(client: ScionHttp3Client) : this(TunnelSocketImpl(client))

    init {
        impl.attach(this)
    }
}

/** The [SocketImpl] under [ScionTunnelSocket]. */
internal class TunnelSocketImpl(
    private val client: ScionHttp3Client,
) : SocketImpl() {
    private lateinit var socket: Socket

    private val tunnel = AtomicReference<ScionHttp3Tunnel?>(null)

    private val closed = AtomicBoolean(false)

    @Volatile
    private var inputShut = false

    @Volatile
    private var endOfStream = false

    @Volatile
    private var soTimeoutMillis = 0

    private val options = ConcurrentHashMap<Int, Any>()

    private val input: InputStream by lazy { TunnelInput() }
    private val output: OutputStream by lazy { TunnelOutput() }

    fun attach(socket: Socket) {
        this.socket = socket
    }

    override fun create(stream: Boolean) {
        if (!stream) throw SocketException("a ScionTunnelSocket carries a stream, not datagrams")
    }

    override fun connect(
        host: String,
        port: Int,
    ) {
        connect(InetSocketAddress.createUnresolved(host, port), 0)
    }

    override fun connect(
        address: InetAddress,
        port: Int,
    ) {
        connect(InetSocketAddress(address, port), 0)
    }

    override fun connect(
        address: SocketAddress,
        timeout: Int,
    ) {
        val endpoint =
            address as? InetSocketAddress
                ?: throw IllegalArgumentException("unsupported address type: ${address.javaClass}")
        if (closed.get()) throw SocketException("Socket closed")
        if (tunnel.get() != null) throw SocketException("already connected")
        val authority = ScionHttp3Authority.of(endpoint)
        val opened =
            try {
                runBlocking {
                    if (timeout > 0) {
                        withTimeout(timeout.toLong()) { client.openTunnel(authority) }
                    } else {
                        client.openTunnel(authority)
                    }
                }
            } catch (e: TimeoutCancellationException) {
                throw SocketTimeoutException("connect timed out").apply { initCause(e) }
            } catch (e: InterruptedException) {
                Thread.currentThread().interrupt()
                throw InterruptedIOException("connect interrupted").apply { initCause(e) }
            }
        if (!tunnel.compareAndSet(null, opened)) {
            opened.close()
            throw SocketException("already connected")
        }
        this.address = endpoint.address
        this.port = endpoint.port
        // Checked after the store. A close between the check and the store would find no tunnel to
        // close and leave this one open.
        if (closed.get()) {
            opened.close()
            throw SocketException("Socket closed")
        }
    }

    override fun bind(
        host: InetAddress?,
        port: Int,
    ) {
        localport = 0
    }

    override fun listen(backlog: Int): Unit =
        throw SocketException("a ScionTunnelSocket cannot listen")

    override fun accept(s: SocketImpl?): Unit =
        throw SocketException("a ScionTunnelSocket cannot accept")

    override fun getInputStream(): InputStream = input

    override fun getOutputStream(): OutputStream = output

    override fun available(): Int = 0

    override fun close() {
        if (!closed.compareAndSet(false, true)) return
        tunnel.get()?.close()
    }

    override fun shutdownInput() {
        inputShut = true
    }

    override fun shutdownOutput() {
        blocking { it.shutdownWrite() }
    }

    override fun sendUrgentData(data: Int): Unit =
        throw SocketException("urgent data is not supported")

    override fun setOption(
        optID: Int,
        value: Any?,
    ) {
        when (optID) {
            SocketOptions.SO_TIMEOUT ->
                soTimeoutMillis =
                    value as? Int ?: throw SocketException("bad parameter for SO_TIMEOUT")
            SocketOptions.TCP_NODELAY,
            SocketOptions.SO_KEEPALIVE,
            SocketOptions.SO_OOBINLINE,
            SocketOptions.SO_REUSEADDR,
            ->
                options[optID] =
                    value as? Boolean ?: throw SocketException("bad parameter for $optID")
            SocketOptions.IP_TOS,
            SocketOptions.SO_SNDBUF,
            SocketOptions.SO_RCVBUF,
            ->
                options[optID] = value as? Int ?: throw SocketException("bad parameter for $optID")
            SocketOptions.SO_LINGER -> Unit
            else -> throw SocketException("unsupported socket option: $optID")
        }
    }

    override fun getOption(optID: Int): Any =
        when (optID) {
            SocketOptions.SO_TIMEOUT -> soTimeoutMillis
            SocketOptions.TCP_NODELAY,
            SocketOptions.SO_KEEPALIVE,
            SocketOptions.SO_OOBINLINE,
            SocketOptions.SO_REUSEADDR,
            -> options[optID] ?: false
            SocketOptions.IP_TOS -> options[optID] ?: 0
            SocketOptions.SO_SNDBUF, SocketOptions.SO_RCVBUF ->
                options[optID]
                    ?: DEFAULT_BUFFER_BYTES
            SocketOptions.SO_LINGER -> -1
            SocketOptions.SO_BINDADDR -> InetAddress.getByAddress(ByteArray(4))
            else -> throw SocketException("unsupported socket option: $optID")
        }

    /** Runs [block] on the tunnel, blocking the calling thread. */
    private fun <T> blocking(block: suspend (ScionHttp3Tunnel) -> T): T {
        val tunnel = this.tunnel.get() ?: throw SocketException("Socket is not connected")
        if (closed.get()) throw SocketException("Socket closed")
        try {
            return runBlocking { block(tunnel) }
        } catch (e: ScionHttp3Exception.TunnelClosed) {
            if (!closed.get()) throw e
            throw SocketException("Socket closed").apply { initCause(e) }
        } catch (e: ScionHttp3Exception.Closed) {
            // The client was shut down, which a Socket caller also reads as a closed socket.
            throw SocketException("Socket closed").apply { initCause(e) }
        } catch (e: InterruptedException) {
            socket.close()
            Thread.currentThread().interrupt()
            throw InterruptedIOException("interrupted while blocked on the tunnel").apply {
                initCause(e)
            }
        }
    }

    private inner class TunnelInput : InputStream() {
        override fun read(): Int {
            val one = ByteArray(1)
            return if (read(one, 0, 1) < 0) -1 else one[0].toInt() and 0xff
        }

        override fun read(
            b: ByteArray,
            off: Int,
            len: Int,
        ): Int {
            checkBounds(b, off, len)
            if (len == 0) return 0
            if (inputShut || endOfStream) return -1
            val chunk =
                blocking { it.readWithin(len, soTimeoutMillis.toLong()) }
                    ?: throw SocketTimeoutException("Read timed out")
            if (chunk.isEmpty()) {
                endOfStream = true
                return -1
            }
            System.arraycopy(chunk, 0, b, off, chunk.size)
            return chunk.size
        }

        override fun available(): Int = 0

        override fun close() {
            socket.close()
        }
    }

    private inner class TunnelOutput : OutputStream() {
        override fun write(b: Int) {
            write(byteArrayOf(b.toByte()), 0, 1)
        }

        override fun write(
            b: ByteArray,
            off: Int,
            len: Int,
        ) {
            checkBounds(b, off, len)
            if (len == 0) return
            val data = b.copyOfRange(off, off + len)
            blocking { it.write(data) }
        }

        override fun close() {
            socket.close()
        }
    }

    private fun checkBounds(
        b: ByteArray,
        off: Int,
        len: Int,
    ) {
        if (off < 0 || len < 0 || len > b.size - off) {
            throw IndexOutOfBoundsException("offset $off, length $len, array of ${b.size}")
        }
    }

    private companion object {
        /** What the stack reads at most in one call, reported for the buffer sizes. */
        const val DEFAULT_BUFFER_BYTES = 64 * 1024
    }
}
