// Copyright 2026 Anapaya Systems

package com.anapaya.scion.http3.e2e

import androidx.test.ext.junit.runners.AndroidJUnit4
import com.anapaya.scion.http3.ScionHttp3RequestBody
import com.google.gson.JsonParser
import kotlinx.coroutines.runBlocking
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test
import org.junit.runner.RunWith

/**
 * E2e tests for the request and response paths of [ScionHttp3Client].
 */
@RunWith(AndroidJUnit4::class)
class RequestsTest {
    @Test(timeout = TEST_TIMEOUT_MILLIS)
    fun getCarriesTheHeadersItWasGiven() =
        runBlocking {
            Fixture.client().use { client ->
                val request =
                    Fixture
                        .request("/echo-headers")
                        .header("x-single", "one")
                        .addHeader("x-repeated", "first")
                        .addHeader("x-repeated", "second")
                        .build()

                val fields =
                    client.newCall(request).execute().use { response ->
                        assertEquals(200, response.code)
                        JsonParser.parseString(response.body.string()).asJsonArray
                    }

                val sent =
                    fields.map { it.asJsonObject }.map {
                        it.get("name").asString to it.get("value").asString
                    }
                assertTrue("$sent", "x-single" to "one" in sent)
                // Repeated field lines, in the order they were added: a client that folds them into
                // a map keyed by name loses one of them, and only the server can say which arrived.
                assertEquals(
                    listOf("first", "second"),
                    sent.filter { it.first == "x-repeated" }.map { it.second },
                )
            }
        }

    @Test(timeout = TEST_TIMEOUT_MILLIS)
    fun getReadsTheTrailingHeaderSection() =
        runBlocking {
            Fixture.client().use { client ->
                client.getFromFixture("/trailers").use { response ->
                    assertEquals(200, response.code)
                    assertEquals("with trailers", response.body.string())
                    assertEquals("42", response.trailers?.get("x-checksum"))
                }
            }
        }

    @Test(timeout = TEST_TIMEOUT_MILLIS)
    fun postRoundTripsItsBodyByteForByte() =
        runBlocking {
            // Bytes that are not text, including a lone continuation byte, so that anything
            // treating the body as a string on the way through is caught.
            val payload = byteArrayOf(0x00, 0x7f, -0x01, -0x80, 0x61)

            Fixture.client().use { client ->
                val request =
                    Fixture
                        .request("/echo")
                        .post(ScionHttp3RequestBody.bytes(payload))
                        .build()

                client.newCall(request).execute().use { response ->
                    assertEquals(200, response.code)
                    assertArrayEquals(payload, response.body.bytes())
                }
            }
        }
}
