// Copyright 2026 Anapaya Systems

package com.anapaya.scion.http3.e2e

import androidx.test.ext.junit.runners.AndroidJUnit4
import com.anapaya.scion.http3.ScionHttp3RequestBody
import kotlinx.coroutines.runBlocking
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Test
import org.junit.runner.RunWith

/**
 * Enough traffic through the SNAP tunnel to exercise the datagram paths under it.
 *
 * The tunnel sends and receives with it, using segmentation offload and receive batching where the
 * kernel offers them and a plain sendmsg loop where it does not.
 */
@RunWith(AndroidJUnit4::class)
class SnapUnderlayTest {
    @Test(timeout = TEST_TIMEOUT_MILLIS)
    fun megabytesSurviveInBothDirections() =
        runBlocking {
            // Not a repeated byte: a payload that is the same everywhere would hide a chunk landing
            // twice, or in the wrong order, which is exactly the sort of mistake batching makes.
            val payload = ByteArray(TRANSFER_BYTES) { (it * 31 + it / 251).toByte() }

            Fixture.client().use { client ->
                val upload =
                    Fixture
                        .request("/echo")
                        .post(ScionHttp3RequestBody.bytes(payload))
                        .build()
                client.newCall(upload).execute().use { response ->
                    assertEquals(200, response.code)
                    assertArrayEquals(payload, response.body.bytes())
                }

                client.getFromFixture("/big?bytes=$TRANSFER_BYTES").use { response ->
                    assertEquals(200, response.code)
                    assertEquals(TRANSFER_BYTES.toLong(), response.body.contentLength)
                }
            }
        }

    private companion object {
        const val TRANSFER_BYTES = 4 * 1024 * 1024
    }
}
