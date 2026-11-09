package com.sucrune.probe.tests

import android.os.SystemClock
import android.util.Base64
import com.sucrune.probe.RuntimeClient
import java.io.ByteArrayOutputStream
import java.util.UUID
import org.json.JSONObject

/** Original Linux Node, synthetic inputs only. start tracks executions; proveReuse
 * runs an independent ordinary execution in the same project after the barriers.
 * No diagnostic or assertion includes a secret, raw event, or execution record. */
internal fun nodeSecretsWorkflowCases(
    client: RuntimeClient,
    envId: String,
    start: (List<String>, Long, Map<String, CharArray>) -> String,
    proveReuse: () -> Unit
): List<Pair<String, () -> String>> {
    val name = "TEST_FIXTURE_PRIVATE"
    val shortName = "TEST_FIXTURE_STATUS"
    val directory = "/node-secrets-workflows"
    fun verify(condition: Boolean, label: String) { if (!condition) throw SecretWorkflowFailure(label) }
    fun script(file: String, text: String): List<String> {
        client.makeDirectory(envId, directory)
        val path = "$directory/$file.cjs"
        client.writeFile(envId, path, text.trimIndent().toByteArray(Charsets.UTF_8))
        return listOf(path)
    }
    fun request(record: JSONObject, short: Boolean) {
        val public = record.getJSONObject("request")
        val keys = public.keys().asSequence().filter { it.startsWith("secret") }.toSet()
        verify(keys == setOf("secret_env_names"), "request secret metadata allowlist")
        val names = public.getJSONArray("secret_env_names")
        val expectedNames = if (short) listOf(name, shortName) else listOf(name)
        verify((0 until names.length()).map { names.getString(it) } == expectedNames, "secret name metadata")
        val env = public.getJSONArray("env")
        verify((0 until env.length()).none { env.getString(it).substringBefore('=') in expectedNames }, "public environment separation")
        verify((0 until env.length()).any { env.getString(it) == "SUCRUNE_MEMORY_POLICY=linux-jit" }, "ordinary public policy retained")
    }
    fun barriers(record: JSONObject, state: String, short: Boolean) {
        verify(record.getString("state") == state && !record.getBoolean("truncated"), "terminal state/capture")
        val result = record.getJSONObject("result")
        verify(result.getBoolean("run_sent") && result.getBoolean("binder_death_confirmed") && result.getBoolean("output_drained") &&
            result.getBoolean("broker_cleanup_confirmed") && result.getBoolean("stdin_feeder_completed"), "four cleanup barriers")
        verify(result.getBoolean("input_closed") && result.getBoolean("input_ended"), "input completion")
        request(record, short)
    }
    fun guarded(run: (remember: (String) -> Unit) -> String): String {
        var id: String? = null
        var problem: Throwable? = null
        try {
            return run { id = it }
        } catch (failure: Throwable) {
            val safe = if (failure is SecretWorkflowFailure) failure else SecretWorkflowFailure("unexpected ${failure.javaClass.simpleName}")
            problem = safe
            throw safe
        } finally {
            val tracked = id
            if (tracked != null) {
                try {
                    if (client.getExecution(tracked).getString("state") == "running") {
                        client.cancel(tracked)
                        val stopped = client.waitFor(tracked, 15_000)
                        verify(stopped.getString("state") != "running", "failure cleanup terminal state")
                    }
                } catch (_: Throwable) {
                    val cleanup = SecretWorkflowFailure("failure cleanup")
                    if (problem == null) throw cleanup else problem.addSuppressed(cleanup)
                }
            }
        }
    }
    fun observe(id: String, expectedOut: String, expectedErr: String, short: Boolean) {
        val deadline = SystemClock.elapsedRealtime() + 20_000
        while (true) {
            val polled = client.poll(id, 0)
            val record = polled.getJSONObject("execution")
            verify(record.getString("state") == "running" && !record.getBoolean("truncated"), "live state/capture")
            request(record, short)
            verify(polled.getBoolean("event_history_available") && !polled.getBoolean("event_history_truncated") &&
                !polled.getBoolean("output_truncated"), "live event retention")
            val stdout = record.getString("stdout")
            val stderr = record.getString("stderr")
            verify(expectedOut.startsWith(stdout) && expectedErr.startsWith(stderr), "live output contains only expected filtered prefix")
            val outBytes = ByteArrayOutputStream(); val errBytes = ByteArrayOutputStream()
            val events = polled.getJSONArray("events")
            for (index in 0 until events.length()) {
                val event = events.getJSONObject(index)
                when (event.getString("type")) {
                    "stdout", "stderr" -> {
                        val bytes = Base64.decode(event.getJSONObject("data").getString("content_base64"), Base64.DEFAULT)
                        (if (event.getString("type") == "stdout") outBytes else errBytes).write(bytes)
                    }
                    "started" -> Unit
                    else -> throw SecretWorkflowFailure("unexpected live event type")
                }
            }
            val fromEventsOut = outBytes.toString("UTF-8"); val fromEventsErr = errBytes.toString("UTF-8")
            verify(expectedOut.startsWith(fromEventsOut) && expectedErr.startsWith(fromEventsErr), "decoded byte events contain only filtered prefix")
            if (stdout == expectedOut && stderr == expectedErr && fromEventsOut == expectedOut && fromEventsErr == expectedErr) return
            verify(SystemClock.elapsedRealtime() < deadline, "live output/event deadline")
            SystemClock.sleep(20)
        }
    }
    fun launch(argv: List<String>, token: String, short: Boolean, remember: (String) -> Unit): String {
        val caller = token.toCharArray()
        val shortValue = charArrayOf('i', 't')
        return try {
            start(argv, 45_000, if (short) mapOf(name to caller, shortName to shortValue) else mapOf(name to caller)).also(remember)
        } finally { caller.fill('\u0000'); shortValue.fill('\u0000') }
    }
    return listOf(
        "linux_node_secret_output_events" to { guarded { remember ->
            val token = "synthetic-${UUID.randomUUID()}-quote\"-slash\\-line\n-finish"
            val argv = script("events", """
                'use strict';
                const fs = require('node:fs');
                const raw = process.env.$name;
                if (!raw || !raw.startsWith('synthetic-') || !raw.includes('\n') || process.env.$shortName !== 'it') process.exit(11);
                const escaped = JSON.stringify(raw).slice(1,-1);
                const cut = Math.floor(raw.length/2), jsonCut = Math.floor(escaped.length/2);
                fs.writeSync(1, '.'.repeat(4093) + ' raw=' + raw.slice(0,cut));
                fs.writeSync(2, 'HTTP 401 message="' + escaped.slice(0,jsonCut));
                process.stdin.once('data', input => {
                  if (input.toString() !== 'continue\n') process.exit(12);
                  fs.writeSync(1, raw.slice(cut) + '\nREADY\n');
                  fs.writeSync(2, escaped.slice(jsonCut) + '"; preserved\n');
                });
                process.stdin.resume();
            """)
            val id = launch(argv, token, true, remember)
            val prefix = ".".repeat(4093) + " raw="
            val errPrefix = "HTTP 401 message=\""
            observe(id, prefix, errPrefix, true)
            val next = "continue\n".toByteArray()
            verify(client.writeInput(id, next) == next.size, "phase-two admission")
            val stdout = prefix + "[REDACTED]\nREADY\n"
            val stderr = errPrefix + "[REDACTED]\"; preserved\n"
            observe(id, stdout, stderr, true)
            verify(client.closeInput(id), "explicit EOF after both replies")
            val record = client.waitFor(id, 20_000)
            barriers(record, "exited", true)
            verify(record.getInt("exit_code") == 0 && record.getString("stdout") == stdout && record.getString("stderr") == stderr,
                "durable sanitized output with original error context")
            val result = record.getJSONObject("result")
            verify(result.getLong("secret_redactions") >= 2L, "both deliberate output redactions counted")
            val native = result.getJSONObject("native")
            verify(native.getString("status") == "exited" && native.getString("kind") == "linux" &&
                native.getString("memory_policy") == "linux-jit", "short secret preserves typed protocol state")
            val reread = client.getExecution(id)
            request(reread, true)
            verify(reread.getString("stdout") == stdout && reread.getString("stderr") == stderr, "reopened durable output")
            proveReuse()
            "Actual guest Node received a copied synthetic value; split raw/JSON text was filtered before live byte events and durable output, retaining HTTP status and two explicit redactions"
        } },
        "linux_node_secret_cancel_cleanup" to { guarded { remember ->
            val token = "synthetic-cancel-${UUID.randomUUID()}"
            val argv = script("cancel", """
                'use strict';
                const fs = require('node:fs');
                const secret = process.env.$name;
                if (!secret || !secret.startsWith('synthetic-cancel-')) process.exit(21);
                fs.writeSync(1, 'SECRET_READY ' + secret + '\n');
                setInterval(() => {}, 1000);
            """)
            val id = launch(argv, token, false, remember)
            val expected = "SECRET_READY [REDACTED]\n"
            observe(id, expected, "", false)
            verify(client.cancel(id), "running cancellation admitted")
            val record = client.waitFor(id, 20_000)
            barriers(record, "cancelled", false)
            val result = record.getJSONObject("result")
            verify(result.getLong("secret_redactions") == 1L && result.getInt("stdin_bytes_accepted") == 0 &&
                result.getInt("stdin_bytes_written") == 0, "cancelled redaction and empty input accounting")
            verify(record.getString("stdout") == expected && record.getString("stderr").isEmpty(), "cancelled output")
            proveReuse()
            "Cancellation released the synthetic secret execution after all four barriers; its durable output remained filtered and the project was reusable"
        } }
    )
}

private class SecretWorkflowFailure(stage: String) : IllegalStateException("Synthetic secret workflow failed: $stage")
