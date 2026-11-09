package com.sucrune.probe.tests

import android.app.Activity
import android.app.Instrumentation
import android.content.Context
import android.content.pm.ApplicationInfo
import android.os.Build
import android.os.Bundle
import android.os.Process
import android.os.SystemClock
import com.sucrune.probe.RuntimeClient
import com.sucrune.probe.RuntimeExceptionWithCode
import org.json.JSONObject
import java.util.UUID

/** Exercises the actual Kotlin manager + Go catalog + isolated native worker. */
internal class RuntimeChecks(private val instrumentation: Instrumentation,
                             private val context: Context, private val arguments: Bundle) {
    private lateinit var client: RuntimeClient
    private val created = ArrayList<String>()
    private val executions = ArrayList<String>()
    private var expectedDebuggable: Boolean? = null
    private var passed = 0
    private var failed = 0
    private var current = 0
    private val summary = StringBuilder()

    fun run() {
        try {
            expectedDebuggable = when (val value = arguments.getString("expect_debuggable")) {
                null -> null
                "true" -> true
                "false" -> false
                else -> error("expect_debuggable must be true or false: $value")
            }
            val debuggable = context.applicationInfo.flags and ApplicationInfo.FLAG_DEBUGGABLE != 0
            expectedDebuggable?.let { check(it == debuggable) { "Target debuggable=$debuggable, expected $it" } }
            check(Build.SUPPORTED_ABIS.firstOrNull() == "arm64-v8a") { "Runtime execution suite requires ARM64; x86_64 is explicitly unsupported" }
            check(Process.myUid() == context.applicationInfo.uid && Process.myUid() != 0)
            client = RuntimeClient.get(context)
            val suffix = UUID.randomUUID().toString().take(8)
            val a = create("测试🍬-$suffix-A")
            val b = create("测试🍬-$suffix-B")
            case("parallel_project_isolation") { parallel(a, b) }
            case("file_api_unicode_persistence") { files(a, b) }
            case("script_file_and_reuse") { scriptFile(a) }
            case("quotes_redirection_cwd") { quoting(a) }
            case("unsupported_is_explicit") { unsupported(a) }
            case("timeout_and_reuse") { timeout(a) }
            case("cancel_and_reuse") { cancel(a) }
            case("event_cursor_and_no_subscriber") { events(a) }
            case("bounded_output_drains") { boundedOutput(a) }
            case("workspace_boundaries_and_busy") { boundaries(a) }
        } catch (failure: Throwable) {
            failed++
            summary.append("Runner failed: ").append(failure).append('\n')
        } finally {
            if (::client.isInitialized) {
                for (id in executions) {
                    try {
                        if (client.getExecution(id).getString("state") == "running") {
                            client.cancel(id)
                            check(client.waitFor(id, 8_000).getString("state") != "running")
                        }
                    } catch (failure: Throwable) { failed++; summary.append("Cleanup execution $id: $failure\n") }
                }
                for (env in created) {
                    try { client.deleteEnvironment(env) }
                    catch (failure: Throwable) { failed++; summary.append("Cleanup environment $env: $failure\n") }
                }
            }
            instrumentation.finish(if (passed == TOTAL && failed == 0) Activity.RESULT_OK else Activity.RESULT_CANCELED,
                Bundle().apply {
                    putInt("passed", passed); putInt("failed", failed); putInt("expected_tests", TOTAL)
                    putString("probe", "runtime")
                    putString("stream", "\n$summary\nPassed: $passed; failed: $failed\n")
                })
        }
    }

    private fun create(name: String): String {
        val result = client.createEnvironment(name)
        check(result.getString("name") == name)
        return result.getString("id").also { created.add(it) }
    }

    private fun start(env: String, script: String, timeout: Long = 20_000, cwd: String = "/"): String =
        client.execute(env, script, cwd, timeout).also { executions.add(it) }

    private fun completed(id: String, expectedExit: Int = 0): JSONObject {
        val record = client.waitFor(id, 25_000)
        check(record.getString("execution_id") == id && record.getInt("schema_version") == 1)
        check(record.getString("state") == "exited") { record.toString() }
        check(record.getInt("exit_code") == expectedExit) { record.toString() }
        evidence(record)
        val native = record.getJSONObject("result").getJSONObject("native")
        check(native.getInt("schema_version") == 1 && native.getString("kind") == "shell")
        check(native.getString("status") == "exited" && native.getInt("exit_code") == expectedExit)
        check(native.getLong("syscalls") > 0)
        check(native.getString("execution_id") == id)
        val worker = record.getJSONObject("result").getJSONObject("worker")
        check(native.getInt("pid") == worker.getInt("pid") && native.getInt("uid") == worker.getInt("uid"))
        check(native.getBoolean("returned_to_host") && native.getBoolean("thread_joined"))
        check(native.getBoolean("handler_restored") && native.getBoolean("on_alt_stack"))
        return record
    }

    private fun evidence(record: JSONObject) {
        val result = record.getJSONObject("result")
        check(result.getBoolean("binder_death_confirmed")) { "Worker death was not established: $record" }
        check(result.getBoolean("run_sent") && result.getBoolean("output_drained"))
        check(result.getBoolean("broker_cleanup_confirmed"))
        check(!result.getBoolean("worker_never_started"))
        val worker = result.getJSONObject("worker")
        check(worker.getString("identity") == "isolated_runtime")
        check(worker.getInt("uid") != 0 && worker.getInt("uid") != context.applicationInfo.uid)
        check(worker.getInt("pid") > 0 && worker.getInt("pid") != Process.myPid())
        check(worker.getInt("api_level") == Build.VERSION.SDK_INT)
        check(worker.getString("abi") == "arm64-v8a")
        val appDebuggable = context.applicationInfo.flags and ApplicationInfo.FLAG_DEBUGGABLE != 0
        check(worker.getBoolean("debuggable") == appDebuggable)
        expectedDebuggable?.let { check(worker.getBoolean("debuggable") == it) }
    }

    private fun parallel(a: String, b: String): String {
        client.writeFile(a, "shared.txt", "project-A 🍬\n".toByteArray())
        client.writeFile(b, "shared.txt", "project-B 🍬\n".toByteArray())
        val aId = start(a, "cat shared.txt; sleep 2; echo A-done")
        val bId = start(b, "cat shared.txt; sleep 2; echo B-done")
        val aResult = completed(aId)
        val bResult = completed(bId)
        check(aResult.getString("stdout") == "project-A 🍬\nA-done\n")
        check(bResult.getString("stdout") == "project-B 🍬\nB-done\n")
        val aw = aResult.getJSONObject("result").getJSONObject("worker")
        val bw = bResult.getJSONObject("result").getJSONObject("worker")
        check(aw.getInt("pid") != bw.getInt("pid") && aw.getInt("uid") != bw.getInt("uid"))
        val an = aResult.getJSONObject("result").getJSONObject("native")
        val bn = bResult.getJSONObject("result").getJSONObject("native")
        val overlap = minOf(an.getLong("native_finished_at_elapsed_ms"), bn.getLong("native_finished_at_elapsed_ms")) -
            maxOf(an.getLong("native_started_at_elapsed_ms"), bn.getLong("native_started_at_elapsed_ms"))
        check(overlap >= 500) { "No meaningful concurrent native interval: $overlap ms" }
        return "overlap=${overlap}ms; PIDs=${aw.getInt("pid")},${bw.getInt("pid")}; UIDs=${aw.getInt("uid")},${bw.getInt("uid")}"
    }

    private fun files(a: String, b: String): String {
        client.makeDirectory(a, "目录🍬")
        val bytes = "中文和 emoji 🍬\n".toByteArray(Charsets.UTF_8)
        client.writeFile(a, "目录🍬/文本.txt", bytes)
        check(client.readFile(a, "目录🍬/文本.txt").contentEquals(bytes))
        val entries = client.listFiles(a, "目录🍬").getJSONArray("entries")
        check(entries.length() == 1 && entries.getJSONObject(0).getString("name") == "文本.txt")
        expectCode("not_found") { client.readFile(b, "目录🍬/文本.txt") }
        val record = completed(start(a, "cat '目录🍬/文本.txt'"))
        check(record.getString("stdout") == String(bytes, Charsets.UTF_8))
        return "Go file API and guest shell preserve UTF-8; second project cannot see first project's path"
    }

    private fun scriptFile(env: String): String {
        client.writeFile(env, "hello.sh", "echo 'from script 🍬' > saved.txt\ncat saved.txt\n".toByteArray())
        val first = completed(start(env, "sh hello.sh"))
        check(first.getString("stdout") == "from script 🍬\n")
        val second = completed(start(env, "cat saved.txt"))
        check(second.getString("stdout") == "from script 🍬\n")
        check(client.readFile(env, "saved.txt").toString(Charsets.UTF_8) == "from script 🍬\n")
        return "Script file executes and output file survives replacement of worker process"
    }

    private fun quoting(env: String): String {
        val result = completed(start(env,
            "mkdir quoted; cd quoted; echo 'hello world' > note; echo tail >> note; cat note; pwd; false || echo recovered; true && echo done"))
        check(result.getString("stdout") == "hello world\ntail\n/quoted\nrecovered\ndone\n") { result.toString() }
        val second = completed(start(env, "pwd; cat note", cwd = "/quoted"))
        check(second.getString("stdout") == "/quoted\nhello world\ntail\n")
        return "Quoted arguments, redirection, conditional lists, cd and supplied cwd work"
    }

    private fun unsupported(env: String): String {
        val result = completed(start(env, "echo forbidden | cat"), 2)
        check(result.getString("stdout").isEmpty())
        check(result.getString("stderr").contains("sucrune-sh:"))
        val missing = completed(start(env, "definitely_not_a_host_command"), 127)
        check(missing.getString("stderr").contains("sucrune-sh:"))
        return "Pipeline is rejected with exit 2; unknown executable returns 127"
    }

    private fun timeout(env: String): String {
        val id = start(env, "echo timeout-start; sleep 30", 3_000)
        waitUntil(id) { it.optJSONObject("runtime")?.optString("phase") == "executing" }
        val result = client.waitFor(id, 10_000)
        check(result.getString("state") == "timed_out") { result.toString() }
        evidence(result)
        check(result.getString("stdout").contains("timeout-start"))
        check(completed(start(env, "echo after-timeout")).getString("stdout") == "after-timeout\n")
        return "Deadline kills worker, confirms Binder death and permits project reuse"
    }

    private fun cancel(env: String): String {
        val early = start(env, "sleep 30", 60_000)
        check(client.cancel(early))
        val earlyResult = client.waitFor(early, 10_000)
        check(earlyResult.getString("state") == "cancelled") { earlyResult.toString() }
        val earlyEvidence = earlyResult.getJSONObject("result")
        check(earlyEvidence.getBoolean("output_drained") && earlyEvidence.getBoolean("broker_cleanup_confirmed"))
        check(earlyEvidence.getBoolean("binder_death_confirmed") || earlyEvidence.getBoolean("worker_never_started"))
        val id = start(env, "echo cancel-start; sleep 30", 60_000)
        waitUntil(id) { it.getString("stdout").contains("cancel-start") }
        check(client.cancel(id))
        val result = client.waitFor(id, 10_000)
        check(result.getString("state") == "cancelled") { result.toString() }
        evidence(result)
        check(!client.cancel(id))
        check(completed(start(env, "echo after-cancel")).getString("stdout") == "after-cancel\n")
        return "Immediate and executing cancellation clean all resources before environment reuse"
    }

    private fun events(env: String): String {
        val id = start(env, "echo before; sleep 2; echo after")
        waitUntil(id) { it.getString("stdout").contains("before") }
        val first = client.poll(id)
        check(first.getBoolean("event_history_available"))
        check(first.getJSONArray("events").length() > 0)
        val cursor = first.getLong("next_cursor")
        val next = client.poll(id, cursor)
        for (i in 0 until next.getJSONArray("events").length()) {
            check(next.getJSONArray("events").getJSONObject(i).getLong("cursor") > cursor)
        }
        // No subscription or further polls while the worker writes the final line.
        val result = completed(id)
        check(result.getString("stdout") == "before\nafter\n")
        val persisted = client.poll(id, cursor)
        check(!persisted.getBoolean("event_history_available"))
        check(persisted.getJSONObject("execution").getString("stdout") == result.getString("stdout"))
        return "Cursors do not repeat events; unsubscribed execution persists complete output"
    }

    private fun boundedOutput(env: String): String {
        client.writeFile(env, "large.txt", ByteArray(100_000) { 'x'.code.toByte() })
        val noisy = "line='${"z".repeat(1_000)}'\ncat large.txt\n" +
            List(80) { "\"\$line\"" }.joinToString("\n") + "\necho done\n"
        val id = start(env, noisy, 30_000)
        // waitFor is not an output reader: manager drainers must make progress independently.
        val result = completed(id)
        check(result.getString("stdout").toByteArray(Charsets.UTF_8).size == 65_536)
        check(result.getBoolean("truncated"))
        check(result.getJSONObject("result").getBoolean("stdout_truncated"))
        check(result.getJSONObject("result").getBoolean("stderr_truncated"))
        check(result.getString("stderr").toByteArray(Charsets.UTF_8).size == 65_536)
        check(result.getString("stderr").contains("sucrune-sh:"))
        check(client.getExecution(id).getString("stdout") == result.getString("stdout"))
        return "Both output streams exceed 64 KiB, drain independently and retain explicit bounded prefixes"
    }

    private fun boundaries(env: String): String {
        expectCode("unsafe_path") { client.writeFile(env, "../escape", byteArrayOf(1)) }
        val denied = completed(start(env, "cat /proc/self/status"), 1)
        check(denied.getString("stdout").isEmpty())
        val id = start(env, "echo busy; sleep 30", 60_000)
        waitUntil(id) { it.getString("stdout").contains("busy") }
        expectCode("conflict") { client.execute(env, "echo second") }
        expectCode("conflict") { client.deleteEnvironment(env) }
        check(client.cancel(id))
        val stopped = client.waitFor(id, 10_000)
        check(stopped.getString("state") == "cancelled")
        evidence(stopped)
        return "Traversal and host proc lookup fail; concurrent execution/deletion of busy project is rejected"
    }

    private fun waitUntil(id: String, predicate: (JSONObject) -> Boolean) {
        val deadline = SystemClock.elapsedRealtime() + 8_000
        while (true) {
            val record = client.getExecution(id)
            if (predicate(record)) return
            check(record.getString("state") == "running") { "Execution ended before expected evidence: $record" }
            check(SystemClock.elapsedRealtime() < deadline) { "Timed out waiting for live evidence: $record" }
            SystemClock.sleep(25)
        }
    }

    private fun expectCode(code: String, action: () -> Any) {
        try { action() } catch (failure: RuntimeExceptionWithCode) {
            check(failure.code == code) { "Expected $code, got ${failure.code}: ${failure.message}" }
            return
        }
        error("Expected failure $code")
    }

    private fun case(name: String, body: () -> String) {
        current++
        publish(1, name, "Starting $name")
        try {
            val detail = body()
            passed++; summary.append("$name: PASS $detail\n")
            publish(0, name, detail)
        } catch (failure: Throwable) {
            failed++; summary.append("$name: FAIL $failure\n")
            publish(-2, name, failure.toString())
        }
    }

    private fun publish(code: Int, name: String, detail: String) {
        instrumentation.sendStatus(code, Bundle().apply {
            putString("id", "SucruneRuntime"); putString("class", RuntimeChecks::class.java.name)
            putString("test", name); putInt("current", current); putInt("numtests", TOTAL)
            putString("stream", "\n$name: $detail\n")
        })
    }

    companion object { private const val TOTAL = 10 }
}
