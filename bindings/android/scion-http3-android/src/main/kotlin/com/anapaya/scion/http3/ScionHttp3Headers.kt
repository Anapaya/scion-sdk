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

/**
 * A header section: ordered, case-insensitive by name, and able to hold a name more than once.
 *
 * Order and repetition are both preserved, because HTTP/3 gives them meaning that merging would
 * destroy: several `set-cookie` lines are not one joined line.
 *
 * Build one with [Builder], or reach the ones on a response through [ScionHttp3Response.headers].
 */
public class ScionHttp3Headers private constructor(
    private val entries: List<Entry>,
) : Iterable<ScionHttp3Headers.Entry> {
    /** One header line. */
    public data class Entry(
        public val name: String,
        public val value: String,
    )

    /** How many lines the section has, counting a repeated name once per occurrence. */
    public val size: Int get() = entries.size

    /** The distinct names present, lower-cased, in the order they first appear. */
    public val names: Set<String>
        get() = entries.mapTo(LinkedHashSet()) { it.name.lowercase() }

    /**
     * The first value for [name], or null if the section has none.
     *
     * The *first*, not the last, and never a joining of several. Use [values] when a name may
     * legitimately appear more than once.
     */
    public operator fun get(name: String): String? =
        entries.firstOrNull { it.name.equals(name, ignoreCase = true) }?.value

    /** Every value for [name], in order; empty when the section has none. */
    public fun values(name: String): List<String> =
        entries.filter { it.name.equals(name, ignoreCase = true) }.map { it.value }

    /** Whether [name] is present at all. */
    public operator fun contains(name: String): Boolean =
        entries.any { it.name.equals(name, ignoreCase = true) }

    override fun iterator(): Iterator<Entry> = entries.iterator()

    /** A builder holding everything already in this section, for deriving a modified copy. */
    public fun newBuilder(): Builder = Builder(entries)

    override fun equals(other: Any?): Boolean =
        this === other || (other is ScionHttp3Headers && entries == other.entries)

    override fun hashCode(): Int = entries.hashCode()

    override fun toString(): String = entries.joinToString(", ") { "${it.name}: ${it.value}" }

    /** Accumulates header lines. Not thread-safe; build one per request. */
    public class Builder internal constructor(
        initial: List<Entry>,
    ) {
        private val entries = initial.toMutableList()

        public constructor() : this(emptyList())

        /**
         * Appends a line, keeping any line that already has this name.
         *
         * @throws IllegalArgumentException if [name] is not a valid header name, or [value] holds
         *   a character a header value cannot carry. Rejected here rather than at request time, so
         *   the stack trace points at the call that got it wrong.
         */
        public fun add(
            name: String,
            value: String,
        ): Builder {
            entries += Entry(validateName(name), validateValue(name, value))
            return this
        }

        /** Replaces every line with this name, wherever they were, with a single line. */
        public fun set(
            name: String,
            value: String,
        ): Builder {
            removeAll(name)
            return add(name, value)
        }

        /** Removes every line with this name. */
        public fun removeAll(name: String): Builder {
            entries.removeAll { it.name.equals(name, ignoreCase = true) }
            return this
        }

        /** Appends [name] only if the section does not have it yet. */
        internal fun addIfAbsent(
            name: String,
            value: String,
        ): Builder {
            if (entries.none { it.name.equals(name, ignoreCase = true) }) add(name, value)
            return this
        }

        public fun build(): ScionHttp3Headers = ScionHttp3Headers(entries.toList())
    }

    public companion object {
        /** A section with no lines. */
        @JvmField
        public val EMPTY: ScionHttp3Headers = ScionHttp3Headers(emptyList())

        /** A section holding exactly the given lines, in the given order. */
        @JvmStatic
        public fun of(vararg pairs: Pair<String, String>): ScionHttp3Headers {
            val builder = Builder()
            pairs.forEach { (name, value) -> builder.add(name, value) }
            return builder.build()
        }

        internal fun ofEntries(entries: List<Entry>): ScionHttp3Headers = ScionHttp3Headers(entries)

        // RFC 9110's token, which is what a field name is. Anything outside it would either be
        // rejected by the peer or, worse, change where the header section ends.
        private const val TOKEN_SYMBOLS = "!#$%&'*+-.^_`|~"

        private const val DEL = '\u007F'

        private fun validateName(name: String): String {
            require(name.isNotEmpty()) { "a header name cannot be empty" }
            name.forEachIndexed { index, c ->
                val allowed = (c.isLetterOrDigit() && c.code < 0x80) || c in TOKEN_SYMBOLS
                require(allowed) {
                    "header name \"$name\" holds ${describe(c)} at index $index"
                }
            }
            return name
        }

        private fun validateValue(
            name: String,
            value: String,
        ): String {
            value.forEachIndexed { index, c ->
                // Tab and printable ASCII only. RFC 9110 still tolerates the high bytes, but a value
                // crosses into the stack as a UTF-8 string, so U+00FF would arrive there as the two
                // bytes 0xC3 0xBF rather than as the byte that was written. Refusing it is better
                // than sending something else than the caller asked for.
                val allowed = c == '\t' || c in ' '..'~'
                require(allowed) {
                    "value of header \"$name\" holds ${describe(c)} at index $index. " +
                        "Header values have to be ASCII; encode anything else, e.g., as base64."
                }
            }
            return value
        }

        private fun describe(c: Char): String =
            when (c) {
                '\n' -> "a line feed"
                '\r' -> "a carriage return"
                '\u0000' -> "a NUL"
                DEL -> "a DEL"
                else -> "U+%04X".format(c.code)
            }
    }
}
