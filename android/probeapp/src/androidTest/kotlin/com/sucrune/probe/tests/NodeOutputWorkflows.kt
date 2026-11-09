package com.sucrune.probe.tests

import android.os.SystemClock
import com.sucrune.probe.ExecutionStdout
import com.sucrune.probe.RuntimeClient
import com.sucrune.probe.RuntimeExceptionWithCode
import java.io.ByteArrayOutputStream
import org.json.JSONObject

/** Read whole strict UTF-8 lines; stdout chunks can split Unicode or contain several frames. */
private class OutputLines(private val reader: ExecutionStdout, private val deadline: Long) {
    private var bytes = byteArrayOf()
    private var offset = 0
    private var eof = false
    var consumed = 0
        private set

    fun next(): String? {
        val line = ByteArrayOutputStream()
        while (true) {
            check(SystemClock.elapsedRealtime() < deadline) { "Live stdout deadline expired" }
            if (offset == bytes.size) {
                if (eof) {
                    check(line.size() == 0) { "Unterminated final stdout frame" }
                    return null
                }
                // Use a size unrelated to guest writes, UTF-8 length, or the 4 KiB drainer.
                val chunk = reader.read(3_079)
                bytes = chunk.bytes
                offset = 0
                eof = chunk.eof
                if (bytes.isEmpty() && !eof) SystemClock.sleep(5)
                continue
            }
            val start = offset
            while (offset < bytes.size && bytes[offset] != 10.toByte()) offset++
            val count = offset - start
            check(line.size() + count <= 100_000) { "Unexpectedly large stdout frame" }
            line.write(bytes, start, count)
            consumed += count
            if (offset < bytes.size) {
                offset++
                consumed++
                return line.toByteArray().decodeToString(throwOnInvalidSequence = true)
            }
        }
    }
}

/** start tracks every original Linux Node execution; finishAndCheck verifies runner identity,
 * normal exit 0 and the four manager cleanup barriers. This helper checks the exact streams. */
internal fun nodeOutputWorkflowCases(
    client: RuntimeClient,
    start: (List<String>, Long, ExecutionStdout, Map<String, CharArray>) -> String,
    finishAndCheck: (String) -> JSONObject
): List<Pair<String, () -> String>> {
    fun capturedPrefix(record: JSONObject, prefix: String) {
        val result = record.getJSONObject("result")
        check(record.getString("state") == "exited" && record.getInt("exit_code") == 0)
        check(record.getBoolean("truncated") && result.getBoolean("stdout_truncated") &&
            !result.getBoolean("stderr_truncated") && record.getString("stderr").isEmpty())
        check(record.getString("stdout") == prefix) { "Durable stdout prefix changed" }
        check(result.getBoolean("output_drained") && result.getBoolean("broker_cleanup_confirmed") &&
            result.getBoolean("stdin_feeder_completed") && result.getBoolean("binder_death_confirmed"))
    }
    val source = """
        'use strict';
        const lines = require('node:readline').createInterface({input: process.stdin});
        const marker = process.env.TEST_STDOUT_MARKER;
        if (!marker) throw new Error('missing test marker');
        let seen = 0;
        lines.on('line', line => {
          const {seq} = JSON.parse(line);
          if (seq !== ++seen || seq > 12) throw new Error('unexpected request');
          const payload = String.fromCharCode(64 + seq).repeat(98304) + '中文🙂';
          process.stdout.write(JSON.stringify({seq, payload, marker}) + '\n');
        });
        lines.on('close', () => {
          if (seen !== 12) throw new Error('unexpected input EOF');
          console.log('OUTPUT_END');
        });
        console.log('OUTPUT_READY');
    """.trimIndent()

    return listOf(
        "linux_node_live_stdout_roundtrip" to {
            ExecutionStdout().use { stdout ->
                val fixture = "synthetic-stream-test-643e9a8bd72".toCharArray()
                val id = try { start(listOf("-e", source), 120_000, stdout, mapOf("TEST_STDOUT_MARKER" to fixture)) }
                    finally { fixture.fill('\u0000') }
                val lines = OutputLines(stdout, SystemClock.elapsedRealtime() + 110_000)
                check(lines.next() == "OUTPUT_READY") { "Missing original Node ready frame" }
                var inputBytes = 0
                for (seq in 1..12) {
                    val request = "{\"seq\":$seq}\n".toByteArray()
                    check(client.writeInput(id, request) == request.size)
                    inputBytes += request.size
                    val reply = JSONObject(checkNotNull(lines.next()) { "Missing frame $seq" })
                    val payload = ('A' + seq - 1).toString().repeat(98_304) + "中文🙂"
                    check(reply.length() == 3 && reply.getInt("seq") == seq &&
                        reply.getString("payload") == payload && reply.getString("marker") == "[REDACTED]") {
                        "Incomplete or unredacted stdout frame $seq"
                    }
                }
                check(client.closeInput(id))
                check(lines.next() == "OUTPUT_END" && lines.next() == null) { "Missing final frame or clean EOF" }
                check(lines.consumed > ExecutionStdout.UNREAD_LIMIT)
                val record = finishAndCheck(id)
                val prefix = ("OUTPUT_READY\n{\"seq\":1,\"payload\":\"" + "A".repeat(65_536)).take(65_536)
                capturedPrefix(record, prefix)
                val result = record.getJSONObject("result")
                check(result.getInt("secret_redactions") == 12 &&
                    result.getInt("stdin_bytes_accepted") == inputBytes && result.getInt("stdin_bytes_written") == inputBytes)
                "12 original Node responses, ${lines.consumed} redacted UTF-8 bytes read and clean EOF; durable stdout retained 65536 bytes"
            }
        },
        "linux_node_live_stdout_overflow" to {
            ExecutionStdout().use { stdout ->
                val id = start(listOf("-e", "process.stdout.write(Buffer.alloc(1048577, 90))"), 60_000, stdout, emptyMap())
                val record = finishAndCheck(id)
                capturedPrefix(record, "Z".repeat(65_536))
                repeat(2) {
                    try {
                        stdout.read()
                        error("Missing sticky stdout overflow")
                    } catch (failure: RuntimeExceptionWithCode) {
                        check(failure.code == "output_overflow") { "Unexpected output read status: ${failure.code}" }
                    }
                }
                "Original Node exited and all four barriers completed with no consuming reader; overflow remained explicit after EOF"
            }
        }
    )
}
