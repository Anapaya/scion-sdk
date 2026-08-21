// Copyright 2026 Anapaya Systems

package com.anapaya.scion.http3.e2e

import androidx.test.ext.junit.runners.AndroidJUnit4
import com.anapaya.scion.http3.ScionHttp3Exception
import kotlinx.coroutines.runBlocking
import org.junit.Assert.assertEquals
import org.junit.Assert.assertThrows
import org.junit.Test
import org.junit.runner.RunWith

/**
 * Two failures that arrive from the transport rather than from a check on this side.
 *
 * The taxonomy itself is covered by a table test in Rust and by the Kotlin unit tests. These two
 * are here because they are produced by the real transport: one is a frame the peer sends, the
 * other a limit applied while a body is being collected.
 */
@RunWith(AndroidJUnit4::class)
class ErrorMappingTest {
    @Test(timeout = TEST_TIMEOUT_MILLIS)
    fun aStreamResetPartwayThroughAResponseIsReportedAsOne() {
        Fixture.client().use { client ->
            // Not an unreachable peer and not a clean response: the status arrives, the body starts,
            // and then the peer resets the stream. A client that lumps this in with either would
            // tell an application to retry when it should not, or the reverse.
            assertThrows(ScionHttp3Exception.StreamReset::class.java) {
                runBlocking { client.getFromFixture("/reset-stream") }
            }
        }
    }

    @Test(timeout = TEST_TIMEOUT_MILLIS)
    fun aBodyOverTheLimitReportsTheLimitItPassed() {
        Fixture.client().use { client ->
            val request =
                Fixture
                    .request("/big?bytes=65536")
                    .maxResponseBody(1024)
                    .build()

            val tooLarge =
                assertThrows(ScionHttp3Exception.BodyTooLarge::class.java) {
                    runBlocking { client.newCall(request).execute() }
                }
            // The limit that was passed, so an application can raise the right one rather than
            // guessing which of the two applied.
            assertEquals(1024L, tooLarge.limit)
        }
    }
}
