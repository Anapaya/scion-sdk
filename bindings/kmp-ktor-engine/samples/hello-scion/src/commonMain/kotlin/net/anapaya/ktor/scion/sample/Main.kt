// Copyright 2026 Anapaya Systems

package net.anapaya.ktor.scion.sample

import kotlinx.coroutines.runBlocking
import net.anapaya.ktor.scion.ScionTokenSource

/**
 * Sends requests over SCION, with an API key of the AA. The arguments are the
 * API key, the request URL, and optionally a fixed endhost API URL. Without
 * it, the client discovers the endhost APIs.
 *
 * The same code runs on the JVM, over JNA, and on Kotlin/Native, over
 * cinterop.
 */
fun main(args: Array<String>): Unit = runBlocking {
    if (args.size !in 2..3) {
        println("usage: hello-scion <api-key> <url> [endhost-api-url]")
        return@runBlocking
    }

    runSample(args[1]) {
        tokenSource = ScionTokenSource.AnapayaAa(apiKey = args[0])
        endhostApiUrl = args.getOrNull(2)
    }
}
