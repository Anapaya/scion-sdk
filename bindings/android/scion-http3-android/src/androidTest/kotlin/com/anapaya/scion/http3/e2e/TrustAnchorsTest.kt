// Copyright 2026 Anapaya Systems

package com.anapaya.scion.http3.e2e

import androidx.test.ext.junit.runners.AndroidJUnit4
import com.anapaya.scion.http3.ScionHttp3Exception
import com.anapaya.scion.http3.TrustAnchors
import kotlinx.coroutines.runBlocking
import org.junit.Assert.assertEquals
import org.junit.Assert.assertThrows
import org.junit.Test
import org.junit.runner.RunWith

/**
 * Which authorities a server certificate is actually checked against.
 */
@RunWith(AndroidJUnit4::class)
class TrustAnchorsTest {
    @Test(timeout = TEST_TIMEOUT_MILLIS)
    fun theServersOwnAuthorityIsAccepted() =
        runBlocking {
            Fixture.client().use { client ->
                assertEquals(200, client.getFromFixture("/hello").use { it.code })
            }
        }

    @Test(timeout = TEST_TIMEOUT_MILLIS)
    fun anotherAuthorityForTheSameNameIsRejected() {
        val pinnedToTheWrongOne =
            Fixture
                .clientBuilder()
                .trust(TrustAnchors.pinned(Fixture.info.wrongCaPem.toByteArray()))
                .build()

        runBlocking {
            Fixture.client().use { reachable ->
                assertEquals(200, reachable.getFromFixture("/hello").use { it.code })
            }
        }

        pinnedToTheWrongOne.use { client ->
            assertThrows(ScionHttp3Exception.Connect::class.java) {
                runBlocking { client.getFromFixture("/hello") }
            }
        }
    }
}
