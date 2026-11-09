package com.sucrune.probe.tests

import android.os.SystemClock
import com.sucrune.probe.RuntimeClient
import com.sucrune.probe.RuntimeExceptionWithCode
import org.json.JSONObject

/** Original guest Node only. The caller tracks every start and owns project cleanup.
 * finishAndCheck waits for the named state, verifies all four cleanup barriers,
 * and proves project reuse before returning the original execution record. */
internal fun nodeInputWorkflowCases(
    client: RuntimeClient,
    envId: String,
    start: (List<String>, Long) -> String,
    finishAndCheck: (String, String) -> JSONObject
): List<Pair<String, () -> String>> {
    val limit = 1_048_576
    val directory = "/node-input-workflows"
    fun script(name: String, source: String): List<String> {
        client.makeDirectory(envId, directory)
        val path = "$directory/$name.cjs"
        client.writeFile(envId, path, source.trimIndent().toByteArray(Charsets.UTF_8))
        return listOf(path)
    }
    fun live(id: String): JSONObject {
        val record = client.getExecution(id)
        check(record.getString("state") == "running" && !record.getBoolean("truncated")) { record.toString() }
        check(record.getString("stderr").isEmpty()) { record.toString() }
        check(record.getString("stdout").toByteArray(Charsets.UTF_8).size < 65_536) { "Unexpectedly large input-test output" }
        return record
    }
    fun awaitLive(id: String, timeoutMs: Long = 10_000, predicate: (JSONObject) -> Boolean): JSONObject {
        val deadline = SystemClock.elapsedRealtime() + timeoutMs
        while (true) {
            val record = live(id)
            if (predicate(record)) return record
            check(SystemClock.elapsedRealtime() < deadline) { "Interactive input progress timed out: $record" }
            SystemClock.sleep(25)
        }
    }
    fun marker(id: String, text: String, timeoutMs: Long = 10_000): JSONObject =
        awaitLive(id, timeoutMs) { text in it.getString("stdout").lineSequence() }
    fun inputError(code: String, operation: () -> Unit) {
        try { operation() }
        catch (failure: RuntimeExceptionWithCode) {
            check(failure.code == code) { "Expected $code, received ${failure.code}: $failure" }
            return
        }
        error("Expected input operation to fail with $code")
    }
    fun openAndEmpty(record: JSONObject) {
        // This is observed before asking for cancellation or reaching the
        // deadline. EOF here is a real failure, not an allowed cleanup effect.
        check(record.getString("stdout") == "INPUT_WAITING\n") { record.toString() }
        val input = record.getJSONObject("runtime")
        check(input.getInt("stdin_bytes_accepted") == 0 && input.getInt("stdin_bytes_written") == 0 &&
            !input.getBoolean("input_closed") && !input.getBoolean("input_ended") &&
            !input.getBoolean("stdin_feeder_completed")) { record.toString() }
    }
    fun stoppedWaitingOutput(record: JSONObject) {
        // Once stop is requested, feeder closure and worker termination race.
        // The guest may observe that terminal EOF before the worker is killed.
        check(record.getString("stdout") in setOf("INPUT_WAITING\n", "INPUT_WAITING\nINPUT_UNEXPECTED_EOF\n")) {
            record.toString()
        }
    }
    fun checkedFinish(id: String, state: String): JSONObject {
        val record = finishAndCheck(id, state)
        check(record.getString("state") == state && !record.getBoolean("truncated") &&
            record.getString("stderr").isEmpty()) { record.toString() }
        val input = record.getJSONObject("result")
        check(input.getBoolean("input_closed") && input.getBoolean("input_ended") &&
            input.getBoolean("stdin_feeder_completed")) { record.toString() }
        return record
    }
    val waitingSource = """
        'use strict';
        process.stdin.on('data', () => { console.error('INPUT_UNEXPECTED_DATA'); process.exitCode = 2; });
        process.stdin.on('end', () => { console.log('INPUT_UNEXPECTED_EOF'); process.exitCode = 3; });
        process.stdin.resume();
        console.log('INPUT_WAITING');
    """

    return listOf(
        "linux_node_interactive_roundtrip_eof" to {
            val argv = script("roundtrip", """
                'use strict';
                const readline = require('node:readline');
                const lines = readline.createInterface({input: process.stdin, crlfDelay: Infinity});
                const expected = ['snapshot-' + 'x'.repeat(524288) + '-中文🙂', '第二轮🙂'];
                let count = 0;
                function fail(message) { console.error(message); process.exit(1); }
                lines.on('line', line => {
                  let request;
                  try { request = JSON.parse(line); } catch (_) { fail('INPUT_INVALID_JSON'); return; }
                  count++;
                  if (count > 2 || request.sequence !== count || request.text !== expected[count - 1]) {
                    fail('INPUT_COPY_OR_SEQUENCE_MISMATCH'); return;
                  }
                  console.log('INPUT_REPLY ' + count + ' ' + Buffer.byteLength(request.text));
                });
                lines.on('close', () => {
                  if (count !== 2) { fail('INPUT_INCOMPLETE_ROUNDTRIP'); return; }
                  console.log('INPUT_EOF 2');
                });
                console.log('INPUT_READY');
            """)
            val firstText = "snapshot-" + "x".repeat(524_288) + "-中文🙂"
            val first = (JSONObject().put("sequence", 1).put("text", firstText).toString() + "\n")
                .toByteArray(Charsets.UTF_8)
            val secondText = "第二轮🙂"
            val second = (JSONObject().put("sequence", 2).put("text", secondText).toString() + "\n")
                .toByteArray(Charsets.UTF_8)
            check(first.size + second.size < limit)
            val id = start(argv, 30_000)
            // Enqueue before waiting for Node: the caller's array must cease to
            // be shared even while startup/pipe backpressure delays consumption.
            check(client.writeInput(id, first) == first.size)
            first.fill('!'.code.toByte())
            val firstReply = "INPUT_REPLY 1 ${firstText.toByteArray(Charsets.UTF_8).size}"
            val observed = marker(id, firstReply)
            val snapshot = observed.getJSONObject("runtime")
            check(snapshot.getInt("stdin_bytes_accepted") == first.size && !snapshot.getBoolean("input_closed"))
            snapshot.put("stdin_bytes_accepted", -1).put("stdin_bytes_written", -1)
                .put("input_closed", true).put("input_ended", true)
            val fresh = live(id).getJSONObject("runtime")
            check(fresh.getInt("stdin_bytes_accepted") == first.size &&
                fresh.getInt("stdin_bytes_written") in 0..first.size &&
                !fresh.getBoolean("input_closed") && !fresh.getBoolean("input_ended")) { fresh.toString() }

            // This block is smaller than the per-execution limit, but would
            // exceed it cumulatively. No prefix may be accepted or delivered.
            val tooMuch = ByteArray(limit - first.size + 1) { 'Z'.code.toByte() }
            check(tooMuch.size < limit)
            inputError("input_limit") { client.writeInput(id, tooMuch) }
            val afterReject = live(id).getJSONObject("runtime")
            check(afterReject.getInt("stdin_bytes_accepted") == first.size &&
                !afterReject.getBoolean("input_closed") && !afterReject.getBoolean("input_ended")) { afterReject.toString() }
            check(client.writeInput(id, byteArrayOf()) == 0)
            check(client.writeInput(id, second) == second.size)
            val secondReply = "INPUT_REPLY 2 ${secondText.toByteArray(Charsets.UTF_8).size}"
            marker(id, secondReply)
            check(client.closeInput(id))
            try { check(!client.closeInput(id)) }
            catch (failure: RuntimeExceptionWithCode) {
                // Node may consume EOF and finish before this second call.
                check(failure.code == "not_found" && client.getExecution(id).getString("state") == "exited") {
                    "Repeated EOF close failed before normal completion: $failure"
                }
            }
            val record = checkedFinish(id, "exited")
            val accepted = first.size + second.size
            check(record.getInt("exit_code") == 0 && record.getString("stdout") ==
                "INPUT_READY\n$firstReply\n$secondReply\nINPUT_EOF 2\n") { record.toString() }
            check(record.getJSONObject("result").getInt("stdin_bytes_accepted") == accepted &&
                record.getJSONObject("result").getInt("stdin_bytes_written") == accepted) { record.toString() }
            "Node validated copied input, replied to two requests, rejected a cumulative overflow without extra input, and exited only after explicit EOF; snapshots are detached from queue state"
        },
        "linux_node_interactive_empty_cancel" to {
            val id = start(script("empty-cancel", waitingSource), 30_000)
            openAndEmpty(marker(id, "INPUT_WAITING"))
            SystemClock.sleep(250)
            openAndEmpty(live(id))
            check(client.cancel(id))
            val record = checkedFinish(id, "cancelled")
            stoppedWaitingOutput(record)
            check(record.getJSONObject("result").getInt("stdin_bytes_accepted") == 0 &&
                record.getJSONObject("result").getInt("stdin_bytes_written") == 0) { record.toString() }
            "An empty interactive queue kept Node stdin open until cancellation; feeder completion and project reuse were verified"
        },
        "linux_node_interactive_empty_timeout" to {
            val id = start(script("empty-timeout", waitingSource), 5_000)
            openAndEmpty(marker(id, "INPUT_WAITING", 4_000))
            SystemClock.sleep(250)
            openAndEmpty(live(id))
            val record = checkedFinish(id, "timed_out")
            stoppedWaitingOutput(record)
            check(record.getJSONObject("result").getInt("stdin_bytes_accepted") == 0 &&
                record.getJSONObject("result").getInt("stdin_bytes_written") == 0) { record.toString() }
            "The deadline stopped Node while stdin remained open and empty; feeder completion and project reuse were verified"
        },
        "linux_node_interactive_guest_closes_stdin" to {
            val argv = script("guest-close", """
                'use strict';
                const fs = require('node:fs');
                console.log('INPUT_CLOSE_READY');
                setTimeout(() => {
                  fs.closeSync(0);
                  console.log('INPUT_CLOSED');
                }, 1000);
                setInterval(() => {}, 1000);
            """)
            val id = start(argv, 30_000)
            val queued = ByteArray(limit) { 'Q'.code.toByte() }
            check(client.writeInput(id, queued) == queued.size)
            marker(id, "INPUT_CLOSED")
            val stillAlive = awaitLive(id, 5_000) {
                val input = it.getJSONObject("runtime")
                input.getBoolean("stdin_feeder_completed") && input.getBoolean("input_ended")
            }
            val ended = stillAlive.getJSONObject("runtime")
            check(ended.getBoolean("input_closed") && ended.getString("input_end_reason") == "guest_closed" &&
                ended.getInt("stdin_bytes_accepted") == limit &&
                ended.getInt("stdin_bytes_written") in 0..limit) { stillAlive.toString() }
            inputError("input_closed") { client.writeInput(id, byteArrayOf(1)) }
            check(!client.closeInput(id))
            check(client.cancel(id))
            val record = checkedFinish(id, "cancelled")
            check(record.getString("stdout") == "INPUT_CLOSE_READY\nINPUT_CLOSED\n" &&
                record.getJSONObject("result").getString("input_end_reason") == "guest_closed") { record.toString() }
            "Node closed fd 0 and stayed alive; guest-close detection finished the sole feeder, rejected later writes, and cancellation permitted project reuse"
        }
    )
}
