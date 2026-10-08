package net.anapaya.ktor.scion

import io.ktor.http.content.OutgoingContent
import io.ktor.utils.io.toByteArray
import io.ktor.utils.io.writer
import kotlinx.coroutines.CoroutineScope
import kotlin.coroutines.CoroutineContext

private val EMPTY = ByteArray(0)

/**
 * Reads the request body into memory.
 *
 * The Rust library takes a full byte array, so a streamed body is collected
 * first. A large upload therefore costs its own size in memory.
 */
internal suspend fun OutgoingContent.readAllBytes(context: CoroutineContext): ByteArray = when (this) {
    is OutgoingContent.NoContent -> EMPTY
    is OutgoingContent.ByteArrayContent -> bytes()
    is OutgoingContent.ReadChannelContent -> readFrom().toByteArray()
    is OutgoingContent.WriteChannelContent ->
        CoroutineScope(context).writer(context) { writeTo(channel) }.channel.toByteArray()

    is OutgoingContent.ContentWrapper -> delegate().readAllBytes(context)
    is OutgoingContent.ProtocolUpgrade ->
        throw UnsupportedOperationException("the SCION engine does not support a protocol upgrade")
}
