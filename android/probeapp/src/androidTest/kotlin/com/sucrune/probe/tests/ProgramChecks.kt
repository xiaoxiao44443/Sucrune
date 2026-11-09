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

/** Runs the bundled genuine musl executable through the same public runtime API. */
internal class ProgramChecks(private val instrumentation: Instrumentation,
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
            expectedDebuggable?.let { check(it == debuggable) }
            check(Build.SUPPORTED_ABIS.firstOrNull() == "arm64-v8a") { "Program execution requires ARM64" }
            check(Process.myUid() == context.applicationInfo.uid && Process.myUid() != 0)
            client = RuntimeClient.get(context)
            val suffix = UUID.randomUUID().toString().take(8)
            val a = create("libc-中文🙂-$suffix-A")
            val b = create("libc-中文🙂-$suffix-B")
            case("musl_tls_memory_files_utf8") { selftest(a) }
            case("program_cwd_and_shell_reuse") { cwd(a, b) }
            case("parallel_program_workers") { parallel(a, b) }
            case("program_timeout_and_reuse") { timeout(a) }
            case("program_cancel_and_reuse") { cancel(a) }
            case("program_fault_cleanup") { fault(a) }
            case("program_request_boundaries") { boundaries(a) }
        } catch (failure: Throwable) {
            failed++; summary.append("Runner failed: $failure\n")
        } finally {
            if (::client.isInitialized) {
                executions.forEach { id ->
                    try {
                        if (client.getExecution(id).getString("state") == "running") {
                            client.cancel(id)
                            check(client.waitFor(id, 8_000).getString("state") != "running")
                        }
                    } catch (failure: Throwable) { failed++; summary.append("Cleanup execution $id: $failure\n") }
                }
                created.forEach { env ->
                    try { client.deleteEnvironment(env) }
                    catch (failure: Throwable) { failed++; summary.append("Cleanup environment $env: $failure\n") }
                }
            }
            instrumentation.finish(if (passed == TOTAL && failed == 0) Activity.RESULT_OK else Activity.RESULT_CANCELED,
                Bundle().apply {
                    putInt("passed", passed); putInt("failed", failed); putInt("expected_tests", TOTAL)
                    putString("probe", "program")
                    putString("stream", "\n$summary\nPassed: $passed; failed: $failed\n")
                })
        }
    }

    private fun create(name: String): String = client.createEnvironment(name).getString("id").also { created.add(it) }
    private fun start(env: String, argv: List<String> = emptyList(), variables: List<String> = emptyList(),
                      cwd: String = "/", timeout: Long = 20_000): String =
        client.executeProgram(env, "musl-smoke", argv, variables, cwd, timeout).also { executions.add(it) }

    private fun completed(id: String, exit: Int = 0): JSONObject {
        val record = client.waitFor(id, 25_000)
        check(record.getString("execution_id") == id && record.getInt("schema_version") == 1)
        check(record.getString("state") == "exited" && record.getInt("exit_code") == exit) { record.toString() }
        evidence(record)
        val native = record.getJSONObject("result").getJSONObject("native")
        check(native.getInt("schema_version") == 1 && native.getString("kind") == "program")
        check(native.getString("status") == "exited" && native.getInt("exit_code") == exit)
        check(native.getLong("syscalls") > 0 && native.getString("execution_id") == id)
        val worker = record.getJSONObject("result").getJSONObject("worker")
        check(native.getInt("pid") == worker.getInt("pid") && native.getInt("uid") == worker.getInt("uid"))
        check(native.getBoolean("returned_to_host") && native.getBoolean("thread_joined"))
        check(native.getBoolean("handler_restored") && native.getBoolean("on_alt_stack"))
        return record
    }

    private fun evidence(record: JSONObject) {
        val result = record.getJSONObject("result")
        check(result.getBoolean("binder_death_confirmed")) { record.toString() }
        check(result.getBoolean("run_sent") && result.getBoolean("output_drained"))
        check(result.getBoolean("broker_cleanup_confirmed") && !result.getBoolean("worker_never_started"))
        val worker = result.getJSONObject("worker")
        check(worker.getString("identity") == "isolated_runtime")
        check(worker.getInt("uid") != 0 && worker.getInt("uid") != context.applicationInfo.uid)
        check(worker.getInt("pid") > 0 && worker.getInt("pid") != Process.myPid())
        check(worker.getInt("api_level") == Build.VERSION.SDK_INT && worker.getString("abi") == "arm64-v8a")
        check(worker.getBoolean("debuggable") == (context.applicationInfo.flags and ApplicationInfo.FLAG_DEBUGGABLE != 0))
        expectedDebuggable?.let { check(worker.getBoolean("debuggable") == it) }
    }

    private fun selftest(env: String): String {
        val argv = listOf("selftest", "参数中文🙂")
        val variables = listOf("SUCRUNE_TEST=环境中文🙂")
        val record = completed(start(env, argv, variables), 42)
        val native = record.getJSONObject("result").getJSONObject("native")
        check(native.getBoolean("guest_tls_seen") && native.getBoolean("host_tls_restored")) { native.toString() }
        check(native.getLong("signal_gate_entries") > 0 && native.getLong("heap_peak_bytes") >= 1_048_576) { native.toString() }
        check(native.getInt("program_parser_checks") >= 20) { native.toString() }
        check(native.getBoolean("image_collision_rejected")) { native.toString() }
        check(record.getString("stdout") == "musl:argv=参数中文🙂\nmusl:env=环境中文🙂\nmusl:tls=ok\nmusl:memory=ok\nmusl:file=ok\nmusl:ok\n") { record.toString() }
        check(record.getString("stderr") == "musl:stderr=ok\n")
        check(client.readFile(env, "libc-result.txt").toString(Charsets.UTF_8) == FILE_CONTENT)
        val request = record.getJSONObject("request")
        check(request.getString("kind") == "program" && request.getString("program_id") == "musl-smoke")
        check(request.getJSONArray("argv").getString(1) == argv[1])
        check(request.getJSONArray("env").getString(0) == variables[0])
        return "Real musl main/stdio, TLS+errno, large malloc and file I/O passed; UTF-8 argv/env and exit 42 persisted"
    }

    private fun cwd(a: String, b: String): String {
        client.makeDirectory(a, "子目录🙂")
        completed(start(a, listOf("selftest"), cwd = "/子目录🙂"), 42)
        check(client.readFile(a, "子目录🙂/libc-result.txt").toString(Charsets.UTF_8) == FILE_CONTENT)
        expectCode("not_found") { client.readFile(b, "libc-result.txt") }
        val id = client.execute(a, "cat '子目录🙂/libc-result.txt'").also { executions.add(it) }
        val shell = client.waitFor(id, 25_000)
        check(shell.getString("state") == "exited" && shell.getInt("exit_code") == 0) { shell.toString() }
        evidence(shell)
        check(shell.getJSONObject("result").getJSONObject("native").getString("kind") == "shell")
        check(shell.getString("stdout") == FILE_CONTENT)
        return "Program cwd is rooted, file survives worker exit, second project cannot see it, Shell reads the same artifact"
    }

    private fun parallel(a: String, b: String): String {
        val aId = start(a, listOf("sleep", "2"))
        val bId = start(b, listOf("sleep", "2"))
        val ar = completed(aId); val br = completed(bId)
        val expected = "musl:sleep=start\nmusl:sleep=done\n"
        check(ar.getString("stdout") == expected && br.getString("stdout") == expected)
        val aw = ar.getJSONObject("result").getJSONObject("worker")
        val bw = br.getJSONObject("result").getJSONObject("worker")
        check(aw.getInt("pid") != bw.getInt("pid") && aw.getInt("uid") != bw.getInt("uid"))
        val an = ar.getJSONObject("result").getJSONObject("native")
        val bn = br.getJSONObject("result").getJSONObject("native")
        val overlap = minOf(an.getLong("native_finished_at_elapsed_ms"), bn.getLong("native_finished_at_elapsed_ms")) -
            maxOf(an.getLong("native_started_at_elapsed_ms"), bn.getLong("native_started_at_elapsed_ms"))
        check(overlap >= 500) { "No meaningful native overlap: $overlap ms" }
        return "overlap=${overlap}ms; PIDs=${aw.getInt("pid")},${bw.getInt("pid")}; UIDs=${aw.getInt("uid")},${bw.getInt("uid")}"
    }

    private fun timeout(env: String): String {
        val id = start(env, listOf("sleep", "30"), timeout = 3_000)
        waitForStart(id)
        val result = client.waitFor(id, 10_000)
        check(result.getString("state") == "timed_out" && !result.has("exit_code")) { result.toString() }
        evidence(result)
        check(!result.getString("stdout").contains("musl:sleep=done"))
        check(completed(start(env, listOf("echo", "after-timeout"))).getString("stdout") == "after-timeout\n")
        return "libc sleep started, deadline terminated worker and same project successfully executed again"
    }

    private fun cancel(env: String): String {
        val early = start(env, listOf("sleep", "30"), timeout = 60_000)
        check(client.cancel(early))
        val earlyResult = client.waitFor(early, 10_000)
        check(earlyResult.getString("state") == "cancelled") { earlyResult.toString() }
        val earlyEvidence = earlyResult.getJSONObject("result")
        check(earlyEvidence.getBoolean("output_drained") && earlyEvidence.getBoolean("broker_cleanup_confirmed"))
        check(earlyEvidence.getBoolean("binder_death_confirmed") || earlyEvidence.getBoolean("worker_never_started"))
        val id = start(env, listOf("sleep", "30"), timeout = 60_000)
        waitForStart(id)
        expectCode("conflict") { client.execute(env, "echo forbidden-overlap") }
        check(client.cancel(id))
        val result = client.waitFor(id, 10_000)
        check(result.getString("state") == "cancelled" && !result.has("exit_code")) { result.toString() }
        evidence(result)
        check(!client.cancel(id))
        check(completed(start(env, listOf("echo", "after-cancel"))).getString("stdout") == "after-cancel\n")
        return "Immediate and active libc cancellation cleanly terminate; mixed Shell/program overlap is rejected"
    }

    private fun boundaries(env: String): String {
        val before = client.listExecutions(env).length()
        expectCode("unsupported_program") { client.executeProgram(env, "/system/bin/sh") }
        expectInvalid { client.executeProgram(env, "musl-smoke", listOf("bad\u0000arg")) }
        expectInvalid { client.executeProgram(env, "musl-smoke", List(65) { "x" }) }
        expectInvalid { client.executeProgram(env, "musl-smoke", listOf("中".repeat(1_366))) }
        expectInvalid { client.executeProgram(env, "musl-smoke", List(17) { "x".repeat(4_096) }) }
        expectInvalid { client.executeProgram(env, "musl-smoke", env = listOf("invalid")) }
        expectInvalid { client.executeProgram(env, "musl-smoke", env = listOf("A=1", "A=2")) }
        expectInvalid { client.executeProgram(env, "musl-smoke", cwd = "relative") }
        check(client.listExecutions(env).length() == before) { "Invalid program request reserved an execution" }
        val echo = completed(start(env, listOf("echo", "a b", "", "中文🙂")))
        check(echo.getString("stdout") == "a b  中文🙂\n") { echo.toString() }
        return "Unknown program and invalid/big inputs rejected before reservation; argv boundaries and empty arguments preserved"
    }

    private fun fault(env: String): String {
        val id = start(env, listOf("fault"))
        val result = client.waitFor(id, 15_000)
        check(result.getString("state") == "lost" && !result.has("exit_code")) { result.toString() }
        check(result.getString("stdout") == "musl:fault=start\n") { result.toString() }
        evidence(result)
        check(result.getJSONObject("result").isNull("native")) { "Fault unexpectedly produced a normal native report: $result" }
        check(completed(start(env, listOf("echo", "after-fault"))).getString("stdout") == "after-fault\n")
        return "Real guest SIGSEGV under musl TLS kills worker; Binder death, both stream EOFs and broker EOF precede reuse"
    }

    private fun waitForStart(id: String) {
        val deadline = SystemClock.elapsedRealtime() + 8_000
        while (true) {
            val record = client.getExecution(id)
            if (record.getString("stdout").contains("musl:sleep=start\n")) return
            check(record.getString("state") == "running" && SystemClock.elapsedRealtime() < deadline) { record.toString() }
            SystemClock.sleep(25)
        }
    }
    private fun expectCode(code: String, action: () -> Any) {
        try { action() } catch (failure: RuntimeExceptionWithCode) {
            check(failure.code == code) { "Expected $code, got ${failure.code}: ${failure.message}" }; return
        }
        error("Expected $code")
    }
    private fun expectInvalid(action: () -> Any) {
        try { action() } catch (_: IllegalArgumentException) { return }
        error("Expected invalid argument")
    }
    private fun case(name: String, body: () -> String) {
        current++; publish(1, name, "Starting $name")
        try {
            val detail = body(); passed++; summary.append("$name: PASS $detail\n"); publish(0, name, detail)
        } catch (failure: Throwable) {
            failed++; summary.append("$name: FAIL $failure\n"); publish(-2, name, failure.toString())
        }
    }
    private fun publish(code: Int, name: String, detail: String) = instrumentation.sendStatus(code, Bundle().apply {
        putString("id", "SucruneProgram"); putString("class", ProgramChecks::class.java.name)
        putString("test", name); putInt("current", current); putInt("numtests", TOTAL)
        putString("stream", "\n$name: $detail\n")
    })
    companion object {
        private const val TOTAL = 7
        private const val FILE_CONTENT = "Sucrune musl: 中文🙂\n"
    }
}
