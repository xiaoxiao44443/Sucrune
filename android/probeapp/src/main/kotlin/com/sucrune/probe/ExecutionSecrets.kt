package com.sucrune.probe

import java.io.ByteArrayOutputStream

/**
 * Transient Linux launch values. Never serialize this object, its launch snapshot,
 * or its input map. Persist [names] only, alongside the unchanged public env.
 *
 * CharArray/ByteArray copies owned here are cleared. A launch snapshot necessarily
 * creates JVM Strings, and Binder/JNI/guest copies cannot promise zero remanence.
 * The caller must discard its Array<String> references after IPC; this is not a
 * secure-heap facility or a defence against a guest that encodes/writes a secret.
 */
internal class ExecutionSecrets private constructor(
    private val publicEnvironment: Array<String>,
    private val entries: List<Pair<String, CharArray>>
) : AutoCloseable {
    private var closed = false
    val names: List<String> get() = entries.map { it.first }

    /** A new, bounded snapshot for the launch call only; never add it to a request. */
    @Synchronized fun launchEnvironment(): Array<String> {
        check(!closed) { "Execution secrets are closed" }
        return Array(publicEnvironment.size + entries.size) { index ->
            if (index < publicEnvironment.size) publicEnvironment[index]
            else {
                val (name, value) = entries[index - publicEnvironment.size]
                val chars = CharArray(name.length + 1 + value.size)
                try {
                    name.toCharArray().copyInto(chars)
                    chars[name.length] = '='
                    value.copyInto(chars, name.length + 1)
                    String(chars)
                } finally { chars.fill('\u0000') }
            }
        }
    }

    /** Each output pipe needs its own filter, kept alive through EOF. */
    @Synchronized fun outputFilter(): SecretOutputFilter {
        check(!closed) { "Execution secrets are closed" }
        val patterns = ArrayList<ByteArray>()
        fun add(bytes: ByteArray) {
            if (bytes.isEmpty() || patterns.any { it.contentEquals(bytes) }) bytes.fill(0)
            else patterns.add(bytes)
        }
        try {
            entries.forEach { (_, value) ->
                add(strictUtf8(value))
                add(jsonContents(value, solidus = false, separators = false, unicode = 0))
                add(jsonContents(value, solidus = true, separators = false, unicode = 0))
                add(jsonContents(value, solidus = false, separators = true, unicode = 0))
                add(jsonContents(value, solidus = false, separators = false, unicode = 1))
                add(jsonContents(value, solidus = false, separators = false, unicode = 2))
            }
            check(patterns.sumOf { it.size } <= MAX_PATTERN_BYTES) { "Secret filter capacity exceeded" }
            return SecretOutputFilter(patterns)
        } catch (failure: Throwable) {
            patterns.forEach { it.fill(0) }
            throw failure
        }
    }

    /** Do not log an original Throwable or protocol frame after sanitizing a copy. */
    fun sanitizeDiagnostic(text: String): SecretRedaction {
        val truncated = text.length > DIAGNOSTIC_CHAR_LIMIT
        val input = text.take(DIAGNOSTIC_CHAR_LIMIT).toByteArray(Charsets.UTF_8)
        val output = ByteArrayOutputStream()
        try {
            outputFilter().use { filter ->
                var offset = 0
                while (offset < input.size) {
                    val chunk = filter.feed(input, offset, minOf(SecretOutputFilter.CHUNK_LIMIT, input.size - offset))
                    output.write(chunk.bytes)
                    chunk.bytes.fill(0)
                    offset += minOf(SecretOutputFilter.CHUNK_LIMIT, input.size - offset)
                }
                val tail = filter.finish()
                output.write(tail.bytes)
                tail.bytes.fill(0)
                val rendered = output.toByteArray()
                try {
                    return SecretRedaction(String(rendered, Charsets.UTF_8), filter.redactionCount, truncated)
                } finally { rendered.fill(0) }
            }
        } finally { input.fill(0); output.reset() }
    }

    @Synchronized override fun close() {
        if (closed) return
        closed = true
        entries.forEach { it.second.fill('\u0000') }
        publicEnvironment.fill("")
    }

    override fun toString(): String = "ExecutionSecrets(names=$names)"

    companion object {
        private const val MAX_PATTERN_BYTES = 2 * 1024 * 1024
        private const val DIAGNOSTIC_CHAR_LIMIT = 65_536
        private val NAME = Regex("[A-Za-z_][A-Za-z0-9_]*")

        /** Copy and validate synchronously before creating any durable execution. */
        fun capture(argv: List<String>, publicEnv: List<String>, secretEnv: Map<String, CharArray>): ExecutionSecrets {
            require(argv.size <= 64 && publicEnv.size <= 64 && secretEnv.size <= 64 &&
                publicEnv.size + secretEnv.size <= 64) { "At most 64 arguments and 64 environment entries are supported" }
            val arguments = argv.toList()
            val environment = publicEnv.toTypedArray()
            val copied = ArrayList<Pair<String, CharArray>>()
            try {
                secretEnv.forEach { (name, chars) ->
                    require(name.length <= 4_095 && chars.size <= 4_095 - name.length) {
                        "Argument or environment entry exceeds 4096 UTF-8 bytes"
                    }
                    copied.add(name to chars.copyOf())
                }
                require(arguments.size <= 64 && environment.size + copied.size <= 64) {
                    "At most 64 arguments and 64 environment entries are supported"
                }
                var total = 0L
                fun measure(chars: CharArray): Int {
                    require('\u0000' !in chars) { "NUL is not supported" }
                    val bytes = strictUtf8Size(chars)
                    require(bytes <= 4_096) { "Argument or environment entry exceeds 4096 UTF-8 bytes" }
                    total += bytes + 1L
                    return bytes
                }
                arguments.forEach {
                    require(it.length <= 4_096) { "Argument or environment entry exceeds 4096 UTF-8 bytes" }
                    measure(it.toCharArray())
                }
                val names = HashSet<String>()
                environment.forEach { entry ->
                    require(entry.length <= 4_096) { "Argument or environment entry exceeds 4096 UTF-8 bytes" }
                    measure(entry.toCharArray())
                    val separator = entry.indexOf('=')
                    require(separator > 0) { "Environment entries must be NAME=value" }
                    val name = entry.substring(0, separator)
                    require(NAME.matches(name) && names.add(name)) { "Environment names must be valid and unique" }
                }
                copied.forEach { (name, chars) ->
                    require(NAME.matches(name) && names.add(name)) { "Environment names must be valid and unique" }
                    require(!name.startsWith("SUCRUNE_")) { "Runtime policy names must use the public environment" }
                    require('\u0000' !in chars) { "NUL is not supported" }
                    val bytes = name.length.toLong() + 1L + strictUtf8Size(chars)
                    require(bytes <= 4_096) { "Argument or environment entry exceeds 4096 UTF-8 bytes" }
                    total += bytes + 1L
                }
                require(total <= 65_536) { "Arguments and environment exceed 64 KiB" }
                return ExecutionSecrets(environment, copied.sortedBy { it.first })
            } catch (failure: Throwable) {
                copied.forEach { it.second.fill('\u0000') }
                environment.fill("")
                throw failure
            }
        }
    }
}

internal data class SecretRedaction(val text: String, val count: Long, val truncated: Boolean = false)
internal data class SecretRedactionBytes(val bytes: ByteArray, val count: Long)

/**
 * Bounded streaming leftmost-longest substitution. Exact UTF-8 values and common
 * JSON content encodings are matched before output capture or base64 events.
 * A byte is held only while a possible cross-chunk match starts at that position;
 * unrelated protocol responses are released immediately, without needing EOF.
 * Empty values add no pattern. This is NOT a generic
 * decoder: arbitrary mixed Unicode escapes, base64, hashes, fragments and guest
 * files are outside its guarantee. Replacements never recursively match.
 */
internal class SecretOutputFilter internal constructor(patterns: List<ByteArray>) : AutoCloseable {
    private class Matcher(val bytes: ByteArray) {
        val fallback = IntArray(bytes.size)
        var matched = 0
        init {
            var prefix = 0
            for (index in 1 until bytes.size) {
                while (prefix > 0 && bytes[index] != bytes[prefix]) prefix = fallback[prefix - 1]
                if (bytes[index] == bytes[prefix]) prefix++
                fallback[index] = prefix
            }
        }
        fun accept(byte: Byte): Boolean {
            while (matched > 0 && byte != bytes[matched]) matched = fallback[matched - 1]
            if (byte == bytes[matched]) matched++
            if (matched != bytes.size) return false
            matched = fallback[matched - 1]
            return true
        }
        fun clear() { bytes.fill(0); fallback.fill(0); matched = 0 }
    }
    private val matchers = patterns.map { Matcher(it) }
    private val maximum = patterns.maxOfOrNull { it.size } ?: 0
    private val pending = ByteArray(maxOf(1, maximum))
    private val lengths = IntArray(pending.size)
    private var seen = 0L
    private var cursor = 0L
    private var closed = false
    var redactionCount = 0L
        private set

    @Synchronized fun feed(bytes: ByteArray, offset: Int = 0, length: Int = bytes.size - offset): SecretRedactionBytes {
        check(!closed) { "Secret output filter is closed" }
        require(offset >= 0 && length >= 0 && offset <= bytes.size - length && length <= CHUNK_LIMIT) {
            "Invalid or oversized secret filter chunk"
        }
        if (maximum == 0) return SecretRedactionBytes(bytes.copyOfRange(offset, offset + length), 0)
        val output = ByteArrayOutputStream(length)
        val before = redactionCount
        for (index in offset until offset + length) {
            val byte = bytes[index]
            pending[slot(seen)] = byte
            seen++
            matchers.forEach { matcher ->
                if (matcher.accept(byte)) {
                    val start = seen - matcher.bytes.size
                    if (start >= cursor) {
                        val position = slot(start)
                        lengths[position] = maxOf(lengths[position], matcher.bytes.size)
                    }
                }
            }
            while (cursor < seen && !incompleteAtCursor()) emit(output)
        }
        return SecretRedactionBytes(output.toByteArray(), redactionCount - before)
    }

    @Synchronized fun finish(): SecretRedactionBytes {
        check(!closed) { "Secret output filter is closed" }
        val output = ByteArrayOutputStream()
        val before = redactionCount
        try {
            while (cursor < seen) emit(output)
            return SecretRedactionBytes(output.toByteArray(), redactionCount - before)
        } finally { close() }
    }

    private fun emit(output: ByteArrayOutputStream) {
        val length = lengths[slot(cursor)]
        if (length == 0) output.write(pending[slot(cursor)].toInt() and 255)
        else { output.write(REPLACEMENT); redactionCount++ }
        repeat(maxOf(1, length)) {
            val position = slot(cursor++)
            pending[position] = 0
            lengths[position] = 0
        }
    }

    private fun incompleteAtCursor(): Boolean {
        for (matcher in matchers) {
            var prefix = matcher.matched
            // A completed replacement can have consumed an overlapping prefix.
            // Its KMP suffixes may still begin in the unconsumed byte window.
            while (prefix > 0 && seen - prefix < cursor) prefix = matcher.fallback[prefix - 1]
            if (prefix > 0 && seen - prefix == cursor) return true
        }
        return false
    }

    private fun slot(position: Long): Int = (position % pending.size).toInt()

    /** Abort discards a retained tail; use finish() at EOF so diagnostics survive. */
    @Synchronized override fun close() {
        if (closed) return
        closed = true
        matchers.forEach { it.clear() }
        pending.fill(0)
        lengths.fill(0)
    }

    companion object {
        const val CHUNK_LIMIT = 65_536
        private val REPLACEMENT = "[REDACTED]".toByteArray(Charsets.US_ASCII)
    }
}

private fun strictUtf8Size(chars: CharArray): Int {
    var index = 0
    var size = 0L
    while (index < chars.size) {
        val value = chars[index++].code
        size += when {
            value < 0x80 -> 1
            value < 0x800 -> 2
            value in 0xD800..0xDBFF -> {
                require(index < chars.size && chars[index].code in 0xDC00..0xDFFF) { "Invalid UTF-16 environment or argument" }
                index++
                4
            }
            value in 0xDC00..0xDFFF -> throw IllegalArgumentException("Invalid UTF-16 environment or argument")
            else -> 3
        }
        require(size <= Int.MAX_VALUE) { "UTF-8 value is too large" }
    }
    return size.toInt()
}

private fun strictUtf8(chars: CharArray): ByteArray {
    val result = ByteArray(strictUtf8Size(chars))
    var index = 0
    var output = 0
    while (index < chars.size) {
        var value = chars[index++].code
        when {
            value < 0x80 -> result[output++] = value.toByte()
            value < 0x800 -> {
                result[output++] = (0xC0 or (value shr 6)).toByte()
                result[output++] = (0x80 or (value and 63)).toByte()
            }
            value in 0xD800..0xDBFF -> {
                value = 0x10000 + ((value - 0xD800) shl 10) + chars[index++].code - 0xDC00
                result[output++] = (0xF0 or (value shr 18)).toByte()
                result[output++] = (0x80 or ((value shr 12) and 63)).toByte()
                result[output++] = (0x80 or ((value shr 6) and 63)).toByte()
                result[output++] = (0x80 or (value and 63)).toByte()
            }
            else -> {
                result[output++] = (0xE0 or (value shr 12)).toByte()
                result[output++] = (0x80 or ((value shr 6) and 63)).toByte()
                result[output++] = (0x80 or (value and 63)).toByte()
            }
        }
    }
    return result
}

/** Escaped JSON string contents without quotes; no immutable secret String is built. */
private fun jsonContents(chars: CharArray, solidus: Boolean, separators: Boolean, unicode: Int): ByteArray {
    val expanded = CharArray(chars.size * 6)
    var used = 0
    val digits = if (unicode == 2) "0123456789ABCDEF" else "0123456789abcdef"
    fun unicodeEscape(char: Char) {
        expanded[used++] = '\\'; expanded[used++] = 'u'
        for (shift in 12 downTo 0 step 4) expanded[used++] = digits[(char.code shr shift) and 15]
    }
    try {
        chars.forEach { char ->
            if (unicode != 0) unicodeEscape(char)
            else {
                val escaped = when (char) {
                    '\\' -> '\\'
                    '"' -> '"'
                    '\b' -> 'b'
                    '\u000C' -> 'f'
                    '\n' -> 'n'
                    '\r' -> 'r'
                    '\t' -> 't'
                    '/' -> if (solidus) '/' else null
                    else -> null
                }
                when {
                    escaped != null -> { expanded[used++] = '\\'; expanded[used++] = escaped }
                    char.code < 0x20 || (separators && char in "\u2028\u2029") -> unicodeEscape(char)
                    else -> expanded[used++] = char
                }
            }
        }
        val exact = expanded.copyOf(used)
        return try { strictUtf8(exact) } finally { exact.fill('\u0000') }
    } finally { expanded.fill('\u0000') }
}
