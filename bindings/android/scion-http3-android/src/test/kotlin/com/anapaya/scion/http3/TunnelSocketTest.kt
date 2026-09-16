// Copyright 2026 Anapaya Systems

package com.anapaya.scion.http3

import kotlinx.coroutines.CompletableDeferred
import org.junit.jupiter.api.Assertions.assertArrayEquals
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertFalse
import org.junit.jupiter.api.Assertions.assertInstanceOf
import org.junit.jupiter.api.Assertions.assertNull
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.assertThrows
import java.io.IOException
import java.io.InterruptedIOException
import java.net.InetAddress
import java.net.InetSocketAddress
import java.net.SocketException
import java.net.SocketTimeoutException
import java.util.concurrent.atomic.AtomicReference
import com.anapaya.scion.http3.uniffi.ScionHttp3Exception as FfiException

/**
 * [ScionTunnelSocket] over a fake tunnel: the `Socket` contract.
 *
 * The socket runs on the desktop JVM's `java.net.Socket`, which is close enough to Android's for
 * the state machine and the option plumbing.
 */
class TunnelSocketTest {
    private val factory = FakeBackendFactory()
    private val fake get() = factory.backend.tunnel
    private val client = client(factory = factory)
    private val endpoint = InetSocketAddress.createUnresolved("chat.example.org", 5222)

    private fun connected(): ScionTunnelSocket =
        ScionTunnelSocket(client).apply { connect(endpoint) }

    @Test
    fun `an unconnected socket has no streams and has touched nothing`() {
        val socket = ScionTunnelSocket(client)

        assertFalse(socket.isConnected)
        assertFalse(socket.isClosed)
        val e = assertThrows<SocketException> { socket.getInputStream() }
        assertEquals("Socket is not connected", e.message)
        assertEquals(0, factory.creations.get())
    }

    @Test
    fun `options set before connecting are kept and open no tunnel`() {
        val socket = ScionTunnelSocket(client)

        socket.soTimeout = 5_000
        socket.tcpNoDelay = true
        socket.keepAlive = true

        assertEquals(5_000, socket.soTimeout)
        assertTrue(socket.tcpNoDelay)
        assertTrue(socket.keepAlive)
        assertFalse(socket.reuseAddress)
        assertEquals(-1, socket.soLinger)
        assertTrue(socket.receiveBufferSize > 0)
        assertEquals(0, factory.creations.get())
    }

    @Test
    fun `connect builds the authority from the endpoint`() {
        val cases =
            listOf(
                InetSocketAddress.createUnresolved("Chat.example.org", 5222) to
                    "chat.example.org:5222",
                InetSocketAddress(
                    InetAddress.getByAddress("chat.example.org", bytesOf(10, 0, 0, 1)),
                    443,
                ) to "chat.example.org:443",
                InetSocketAddress(InetAddress.getByAddress(bytesOf(10, 0, 0, 1)), 443) to
                    "10.0.0.1:443",
                InetSocketAddress(InetAddress.getByAddress(ByteArray(15) + 1), 443) to
                    "[0:0:0:0:0:0:0:1]:443",
                InetSocketAddress.createUnresolved("[::1]", 443) to "[::1]:443",
            )

        cases.forEach { (endpoint, _) -> ScionTunnelSocket(client).connect(endpoint) }

        assertEquals(cases.map { it.second }, factory.backend.authorities)
    }

    @Test
    fun `a connected socket knows its endpoint`() {
        val resolved = InetSocketAddress(InetAddress.getByAddress(bytesOf(10, 0, 0, 1)), 443)
        val socket = ScionTunnelSocket(client).apply { connect(resolved) }

        assertTrue(socket.isConnected)
        assertEquals(443, socket.port)
        assertEquals(resolved.address, socket.inetAddress)
        assertEquals(resolved, socket.remoteSocketAddress)

        val unresolved = connected()
        assertNull(unresolved.inetAddress, "an unresolved endpoint has no address to report")
        assertEquals(5222, unresolved.port)
    }

    @Test
    fun `a refused tunnel fails connect with its own arm and leaves the socket unconnected`() {
        factory.backend.failure = FfiException.TunnelRefused(404u, false, "not allowed")
        val socket = ScionTunnelSocket(client)

        val e = assertThrows<ScionHttp3Exception.TunnelRefused> { socket.connect(endpoint) }

        assertEquals(404, e.status)
        assertFalse(socket.isConnected)
    }

    @Test
    fun `a connect that exceeds its timeout is a socket timeout`() {
        factory.backend.gate = CompletableDeferred()
        val socket = ScionTunnelSocket(client)

        assertThrows<SocketTimeoutException> { socket.connect(endpoint, 50) }

        assertFalse(socket.isConnected)
    }

    @Test
    fun `connecting twice is refused`() {
        val socket = connected()

        assertThrows<SocketException> { socket.connect(endpoint) }
        assertEquals(1, factory.backend.authorities.size)
    }

    @Test
    fun `a closed socket does not connect`() {
        val socket = ScionTunnelSocket(client)
        socket.close()

        assertThrows<SocketException> { socket.connect(endpoint) }
        assertTrue(factory.backend.authorities.isEmpty())
    }

    @Test
    fun `reads and writes go through the tunnel`() {
        fake.reads += bytesOf(1, 2, 3)
        val socket = connected()
        val buffer = ByteArray(16)

        val n = socket.getInputStream().read(buffer)
        socket.getOutputStream().write(bytesOf(4, 5, 6), 1, 2)
        socket.getOutputStream().write(7)

        assertEquals(3, n)
        assertArrayEquals(bytesOf(1, 2, 3), buffer.copyOf(3))
        assertEquals(listOf(16), fake.maxima, "the buffer's length is the most a read asks for")
        assertArrayEquals(bytesOf(5, 6), fake.written[0])
        assertArrayEquals(bytesOf(7), fake.written[1])
    }

    @Test
    fun `a read into the middle of a buffer lands where asked`() {
        fake.reads += bytesOf(9, 9)
        val socket = connected()
        val buffer = ByteArray(6)

        assertEquals(2, socket.getInputStream().read(buffer, 2, 4))

        assertArrayEquals(bytesOf(0, 0, 9, 9, 0, 0), buffer)
        assertEquals(listOf(4), fake.maxima)
    }

    @Test
    fun `a single byte read is that byte, unsigned`() {
        fake.reads += bytesOf(0xff)
        val socket = connected()

        assertEquals(0xff, socket.getInputStream().read())
    }

    @Test
    fun `an empty read or write touches nothing`() {
        val socket = connected()

        assertEquals(0, socket.getInputStream().read(ByteArray(4), 0, 0))
        socket.getOutputStream().write(ByteArray(0))

        assertTrue(fake.maxima.isEmpty())
        assertTrue(fake.written.isEmpty())
    }

    @Test
    fun `bad bounds are refused before anything is read`() {
        val socket = connected()

        assertThrows<IndexOutOfBoundsException> { socket.getInputStream().read(ByteArray(4), 2, 4) }
        assertThrows<IndexOutOfBoundsException> {
            socket.getOutputStream().write(
                ByteArray(4),
                3,
                2,
            )
        }
        assertTrue(fake.maxima.isEmpty())
    }

    @Test
    fun `the end of the stream is minus one, and stays so`() {
        fake.reads += ByteArray(0)
        val socket = connected()
        val input = socket.getInputStream()

        assertEquals(-1, input.read(ByteArray(4)))
        assertEquals(-1, input.read(ByteArray(4)))
        assertEquals(-1, input.read())

        assertEquals(1, fake.maxima.size, "after the end nothing is asked of the stack")
        assertFalse(socket.isClosed)
    }

    @Test
    fun `a read deadline is a socket timeout, and the socket stays usable`() {
        val socket = connected()
        socket.soTimeout = 50
        val input = socket.getInputStream()

        assertThrows<SocketTimeoutException> { input.read(ByteArray(4)) }

        assertFalse(socket.isClosed)
        assertEquals(0, fake.aborts.get())
        fake.reads += bytesOf(1)
        assertEquals(1, input.read(ByteArray(4)))
    }

    @Test
    fun `without a deadline a read waits`() {
        val socket = connected()
        val outcome = readOnAnotherThread(socket)

        awaitPendingRead()
        assertTrue(outcome.thread.isAlive)
        assertEquals(0, fake.cancelsCreated.get(), "no deadline, so no cancellation was set up")

        socket.close()
        outcome.thread.join()
    }

    @Test
    fun `closing from another thread ends a blocked read as socket closed`() {
        val socket = connected()
        val outcome = readOnAnotherThread(socket)
        awaitPendingRead()

        socket.close()
        outcome.thread.join()

        val e = assertInstanceOf(SocketException::class.java, outcome.failure.get())
        assertEquals("Socket closed", e.message)
        assertTrue(socket.isClosed)
        assertEquals(1, fake.aborts.get())
    }

    @Test
    fun `interrupting a blocked read closes the tunnel and keeps the interrupt`() {
        val socket = connected()
        val outcome = readOnAnotherThread(socket)
        awaitPendingRead()

        outcome.thread.interrupt()
        outcome.thread.join()

        assertInstanceOf(InterruptedIOException::class.java, outcome.failure.get())
        assertTrue(
            outcome.interruptedAfterwards.get(),
            "runBlocking cleared the flag; it is re-set",
        )
        assertEquals(1, fake.aborts.get(), "the dropped read may have lost bytes")
        assertTrue(socket.isClosed)
        assertThrows<SocketException> { socket.getInputStream() }
    }

    @Test
    fun `a client that was shut down reads as a closed socket`() {
        fake.reads += FfiException.Closed(false, "the client was shut down")
        val socket = connected()

        val e = assertThrows<SocketException> { socket.getInputStream().read() }

        assertEquals("Socket closed", e.message)
        assertInstanceOf(ScionHttp3Exception.Closed::class.java, e.cause)
    }

    @Test
    fun `stream failures from the stack pass through as they are`() {
        fake.reads += FfiException.TunnelReset(true, "d")
        fake.reads += FfiException.TunnelDisconnected(true, "d")
        val socket = connected()
        val input = socket.getInputStream()

        assertThrows<ScionHttp3Exception.TunnelReset> { input.read() }
        assertThrows<ScionHttp3Exception.TunnelDisconnected> { input.read() }
        assertFalse(socket.isClosed)
    }

    @Test
    fun `shutting the output down ends the write direction`() {
        val socket = connected()
        val output = socket.getOutputStream()

        socket.shutdownOutput()

        assertEquals(1, fake.shutdownWrites.get())
        assertTrue(socket.isOutputShutdown)
        assertFalse(socket.isClosed)
        // The socket itself refuses to hand the stream out again, and a stream already held is
        // refused by the stack, with its own arm rather than "Socket closed".
        assertThrows<SocketException> { socket.getOutputStream() }
        assertThrows<ScionHttp3Exception.TunnelClosed> { output.write(1) }
    }

    @Test
    fun `shutting the input down makes reads return minus one without the stack`() {
        val socket = connected()
        val input = socket.getInputStream()

        socket.shutdownInput()

        assertEquals(-1, input.read(ByteArray(4)))
        assertTrue(socket.isInputShutdown)
        assertTrue(fake.maxima.isEmpty())
    }

    @Test
    fun `closing a stream closes the socket`() {
        val socket = connected()

        socket.getInputStream().close()

        assertTrue(socket.isClosed)
        assertEquals(1, fake.aborts.get())

        val other = connected()
        other.getOutputStream().close()
        assertTrue(other.isClosed)
    }

    @Test
    fun `close resets and releases once, and everything after it says so`() {
        val socket = connected()
        val input = socket.getInputStream()
        val output = socket.getOutputStream()

        socket.close()
        socket.close()

        assertEquals(1, fake.aborts.get())
        assertEquals(1, fake.closes.get())
        assertEquals("Socket closed", assertThrows<SocketException> { input.read() }.message)
        assertEquals("Socket closed", assertThrows<SocketException> { output.write(1) }.message)
        assertThrows<SocketException> { socket.getInputStream() }
    }

    @Test
    fun `closing an unconnected socket is fine`() {
        val socket = ScionTunnelSocket(client)

        socket.close()

        assertTrue(socket.isClosed)
        assertEquals(0, fake.aborts.get())
    }

    @Test
    fun `binding is accepted and does nothing`() {
        val socket = ScionTunnelSocket(client)

        socket.bind(null)

        assertTrue(socket.isBound)
        assertEquals(0, factory.creations.get())
    }

    @Test
    fun `urgent data is refused`() {
        val socket = connected()

        assertThrows<SocketException> { socket.sendUrgentData(1) }
    }

    private class Outcome(
        val thread: Thread,
        val failure: AtomicReference<IOException?>,
        val interruptedAfterwards: AtomicReference<Boolean>,
    )

    private fun readOnAnotherThread(socket: ScionTunnelSocket): Outcome {
        val failure = AtomicReference<IOException?>(null)
        val interrupted = AtomicReference(false)
        val thread =
            Thread {
                try {
                    socket.getInputStream().read(ByteArray(4))
                } catch (e: IOException) {
                    failure.set(e)
                    interrupted.set(Thread.currentThread().isInterrupted)
                }
            }
        thread.start()
        return Outcome(thread, failure, interrupted)
    }

    private fun awaitPendingRead() {
        val deadline = System.nanoTime() + 5_000_000_000L
        while (!fake.isReadPending) {
            check(System.nanoTime() < deadline) { "no read reached the fake" }
            Thread.sleep(1)
        }
    }
}
