package com.sucrune.probe

import java.io.ByteArrayOutputStream
import java.util.Random

private var passed = 0
private fun test(name: String, run: () -> Unit) { run(); passed++; println("PASS $name") }
private fun reject(run: () -> Unit) {
    try { run() } catch (_: IllegalArgumentException) { return }
    error("Expected bounded validation rejection")
}
private fun closed(run: () -> Unit) {
    try { run() } catch (_: IllegalStateException) { return }
    error("Expected closed-state rejection")
}
private fun secrets(vararg entries: Pair<String, String>) = ExecutionSecrets.capture(emptyList(), emptyList(),
    entries.associate { it.first to it.second.toCharArray() })

private fun filtered(owner: ExecutionSecrets, input: ByteArray, chunks: List<Int>): Pair<ByteArray, Long> {
    val output = ByteArrayOutputStream()
    var count = 0L
    owner.outputFilter().use { filter ->
        var offset = 0
        chunks.forEach { size ->
            val result = filter.feed(input, offset, size)
            output.write(result.bytes)
            count += result.count
            offset += size
        }
        check(offset == input.size)
        val tail = filter.finish()
        output.write(tail.bytes)
        count += tail.count
        check(count == filter.redactionCount)
    }
    return output.toByteArray() to count
}

fun main() {
    test("snapshot copies caller values and public environment; names are sorted") {
        val chars = "synthetic-alpha".toCharArray()
        val public = mutableListOf("HOME=/workspace/private")
        val input = mutableMapOf("z_key" to chars, "A_KEY" to "synthetic-beta".toCharArray())
        ExecutionSecrets.capture(listOf("--version"), public, input).use { owner ->
            chars.fill('x'); public[0] = "HOME=/changed"; input.clear()
            check(owner.names == listOf("A_KEY", "z_key"))
            val launch = owner.launchEnvironment()
            check(launch.contentEquals(arrayOf("HOME=/workspace/private", "A_KEY=synthetic-beta", "z_key=synthetic-alpha")))
            launch.fill("")
            check(owner.launchEnvironment()[2] == "z_key=synthetic-alpha")
            check(!owner.toString().contains("synthetic-"))
        }
    }
    test("reject invalid names, duplicate public names, public-secret conflicts and hidden runtime policy") {
        for (name in listOf("", "9KEY", "A=B", "A-B", "A\u0000B", "SUCRUNE_MEMORY_POLICY", "SUCRUNE_NETWORK_POLICY")) {
            reject { secrets(name to "synthetic") }
        }
        reject { ExecutionSecrets.capture(emptyList(), listOf("X=one", "X=two"), emptyMap()) }
        reject { ExecutionSecrets.capture(emptyList(), listOf("X=one"), mapOf("X" to "two".toCharArray())) }
        reject { ExecutionSecrets.capture(emptyList(), listOf("not-assignment"), emptyMap()) }
        ExecutionSecrets.capture(emptyList(), listOf("SUCRUNE_MEMORY_POLICY=linux-jit"), emptyMap()).close()
    }
    test("reject NUL and malformed UTF-16 without echoing secret text") {
        for (value in listOf("synthetic\u0000token", "synthetic\uD800", "\uDC00synthetic")) {
            reject { secrets("KEY" to value) }
            reject { ExecutionSecrets.capture(listOf(value), emptyList(), emptyMap()) }
            reject { ExecutionSecrets.capture(emptyList(), listOf("KEY=$value"), emptyMap()) }
        }
        try { secrets("KEY" to "synthetic-credential\u0000") } catch (failure: IllegalArgumentException) {
            check(!failure.toString().contains("synthetic-credential"))
        }
    }
    test("UTF-8 per-entry boundary includes NAME equals and supplementary codepoints") {
        secrets("K" to "a".repeat(4094)).close()
        reject { secrets("K" to "a".repeat(4095)) }
        secrets("K" to ("😀".repeat(1023) + "aa")).close()
        reject { secrets("K" to ("😀".repeat(1023) + "aaa")) }
    }
    test("combined argument/public/secret byte budget and entry count") {
        val args = List(15) { "a".repeat(4095) }
        ExecutionSecrets.capture(args, emptyList(), mapOf("K" to "b".repeat(4093).toCharArray())).close()
        reject { ExecutionSecrets.capture(args + "", emptyList(), mapOf("K" to "b".repeat(4093).toCharArray())) }
        ExecutionSecrets.capture(emptyList(), List(63) { "P$it=" }, mapOf("K" to charArrayOf())).close()
        reject { ExecutionSecrets.capture(emptyList(), List(64) { "P$it=" }, mapOf("K" to charArrayOf())) }
        reject { ExecutionSecrets.capture(List(65) { "" }, emptyList(), emptyMap()) }
    }
    test("close is idempotent and clears owned CharArrays without mutating caller") {
        val caller = "synthetic-close".toCharArray()
        val owner = ExecutionSecrets.capture(emptyList(), emptyList(), mapOf("K" to caller))
        val field = ExecutionSecrets::class.java.getDeclaredField("entries").apply { isAccessible = true }
        val entries = field.get(owner) as List<*>
        val owned = (entries.single() as Pair<*, *>).second as CharArray
        check(owned !== caller && owned.contentEquals(caller))
        owner.close(); owner.close()
        check(owned.all { it == '\u0000' } && String(caller) == "synthetic-close")
        closed { owner.launchEnvironment() }; closed { owner.outputFilter() }; closed { owner.sanitizeDiagnostic("error") }
        check(owner.names == listOf("K"))
    }
    test("empty secret remains a valid launch value and does not match empty output") {
        secrets("EMPTY" to "").use { owner ->
            check(owner.launchEnvironment().single() == "EMPTY=")
            val input = "diagnostic preserved".toByteArray()
            val (output, count) = filtered(owner, input, listOf(input.size))
            check(output.contentEquals(input) && count == 0L)
        }
    }
    test("every possible two-chunk boundary and EOF preserve errors but remove full token") {
        secrets("KEY" to "synthetic-boundary-token").use { owner ->
            val input = "HTTP 401: synthetic-boundary-token; retry denied\n".toByteArray()
            for (split in 0..input.size) {
                val (output, count) = filtered(owner, input, listOf(split, input.size - split))
                check(String(output) == "HTTP 401: [REDACTED]; retry denied\n" && count == 1L)
            }
        }
    }
    test("unrelated interactive response is emitted immediately without EOF or padding") {
        secrets("KEY" to "synthetic-".repeat(300)).use { owner ->
            owner.outputFilter().use { filter ->
                val frame = "{\"jsonrpc\":\"2.0\",\"id\":1,\"result\":{}}\n".toByteArray()
                val result = filter.feed(frame)
                check(result.bytes.contentEquals(frame) && result.count == 0L)
                check(filter.finish().bytes.isEmpty())
            }
        }
    }
    test("raw UTF-8 and standard JSON escaped controls quote slash and backslash") {
        val secret = "秘😀\"\\/\n\t\b\u000C\r\u0001"
        val json = "秘😀\\\"\\\\/\\n\\t\\b\\f\\r\\u0001"
        val slash = json.replace("/", "\\/")
        secrets("KEY" to secret).use { owner ->
            val input = (secret + "|" + json + "|" + slash).toByteArray()
            val (output, count) = filtered(owner, input, List(input.size) { 1 })
            check(String(output) == "[REDACTED]|[REDACTED]|[REDACTED]" && count == 3L)
        }
    }
    test("all-code-unit Unicode escapes lower/upper and JSON separator convention") {
        secrets("KEY" to "aé😀\u2028\"").use { owner ->
            val lower = "\\u0061\\u00e9\\ud83d\\ude00\\u2028\\u0022"
            val upper = "\\u0061\\u00E9\\uD83D\\uDE00\\u2028\\u0022"
            val separators = "aé😀\\u2028\\\""
            val input = "$lower|$upper|$separators".toByteArray()
            val (output, count) = filtered(owner, input, List(input.size) { 1 })
            check(String(output) == "[REDACTED]|[REDACTED]|[REDACTED]" && count == 3L)
        }
    }
    test("leftmost longest overlapping patterns and repeated fallback prefixes") {
        secrets("A" to "abc", "B" to "abcdef", "C" to "bcd", "D" to "aaaaab").use { owner ->
            val input = "abcdef|abc|aaaaaaaab|bcd|ab".toByteArray()
            for (split in 0..input.size) {
                val (output, count) = filtered(owner, input, listOf(split, input.size - split))
                check(String(output) == "[REDACTED]|[REDACTED]|aaa[REDACTED]|[REDACTED]|ab" && count == 4L)
            }
        }
    }
    test("independent pipe state survives owner close and incomplete tail is emitted at EOF") {
        val owner = secrets("KEY" to "synthetic-key")
        val first = owner.outputFilter(); val second = owner.outputFilter()
        owner.close()
        check(first.feed("synthetic-".toByteArray()).bytes.isEmpty())
        check(second.feed("HTTP error synthetic-k".toByteArray()).count == 0L)
        val firstHead = first.feed("key".toByteArray())
        val firstTail = first.finish()
        check(String(firstHead.bytes + firstTail.bytes) == "[REDACTED]" && first.redactionCount == 1L)
        val tail = second.finish()
        check(String(tail.bytes).endsWith("synthetic-k") && second.redactionCount == 0L)
        closed { first.feed(byteArrayOf()) }; closed { first.finish() }
    }
    test("chunk range checks are bounded and invalid chunks do not corrupt later filtering") {
        secrets("KEY" to "synthetic").use { owner ->
            owner.outputFilter().use { filter ->
                reject { filter.feed(byteArrayOf(1), -1, 1) }
                reject { filter.feed(byteArrayOf(1), 0, 2) }
                reject { filter.feed(ByteArray(65_537)) }
                val part = filter.feed("synthetic".toByteArray())
                val tail = filter.finish()
                check(String(part.bytes + tail.bytes) == "[REDACTED]")
            }
        }
    }
    test("diagnostic redaction preserves failure/status and explicitly reports truncation") {
        secrets("KEY" to "synthetic-diagnostic").use { owner ->
            val result = owner.sanitizeDiagnostic("AUTH status=401 message=synthetic-diagnostic")
            check(result.text == "AUTH status=401 message=[REDACTED]" && result.count == 1L && !result.truncated)
            val bounded = owner.sanitizeDiagnostic("x".repeat(70_000))
            check(bounded.truncated && bounded.text.length == 65_536 && bounded.count == 0L)
        }
    }
    test("random chunk schedules match independent ASCII leftmost-longest oracle") {
        val random = Random(673921L)
        repeat(150) {
            val patterns = List(1 + random.nextInt(8)) {
                buildString { repeat(1 + random.nextInt(12)) { append(('a'.code + random.nextInt(4)).toChar()) } }
            }.distinct()
            val input = buildString { repeat(300) { append(('a'.code + random.nextInt(5)).toChar()) } }
            val expected = StringBuilder()
            var position = 0; var expectedCount = 0L
            while (position < input.length) {
                val match = patterns.filter { input.startsWith(it, position) }.maxByOrNull { it.length }
                if (match == null) expected.append(input[position++])
                else { expected.append("[REDACTED]"); expectedCount++; position += match.length }
            }
            secrets(*patterns.mapIndexed { index, value -> "K$index" to value }.toTypedArray()).use { owner ->
                var remaining = input.length
                val chunks = ArrayList<Int>()
                while (remaining > 0) { val size = minOf(remaining, 1 + random.nextInt(23)); chunks.add(size); remaining -= size }
                val (output, count) = filtered(owner, input.toByteArray(), chunks)
                check(String(output) == expected.toString() && count == expectedCount)
            }
        }
    }
    test("maximum valid control-heavy secret set constructs bounded filters and streams maximum chunks") {
        val secretMap = (0 until 16).associate { "K$it" to ("\u0001".repeat(3990) + it).toCharArray() }
        ExecutionSecrets.capture(emptyList(), emptyList(), secretMap).use { owner ->
            owner.outputFilter().use { filter ->
                val input = ByteArray(65_536) { 'x'.code.toByte() }
                val first = filter.feed(input)
                val last = filter.finish()
                check((first.bytes + last.bytes).contentEquals(input) && filter.redactionCount == 0L)
            }
        }
    }
    println("SUMMARY $passed/$passed host secret validation/redaction groups passed; no credentials, Binder, JNI or device execution")
}
