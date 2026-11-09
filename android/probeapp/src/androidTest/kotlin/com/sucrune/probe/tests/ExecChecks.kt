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

/** True guest execve transitions, exercised through one supervised execution. */
internal class ExecChecks(private val instrumentation: Instrumentation,
                          private val context: Context, private val arguments: Bundle) {
    private lateinit var client: RuntimeClient
    private val environments = ArrayList<String>()
    private val executions = ArrayList<String>()
    private val summary = StringBuilder()
    private var passed = 0
    private var failed = 0
    private var current = 0

    fun run() {
        try {
            check(Build.SUPPORTED_ABIS.firstOrNull() == "arm64-v8a")
            val debug = context.applicationInfo.flags and ApplicationInfo.FLAG_DEBUGGABLE != 0
            arguments.getString("expect_debuggable")?.let { check(it == debug.toString()) }
            check(Process.myUid() == context.applicationInfo.uid && Process.myUid() != 0)
            client = RuntimeClient.get(context)
            val suffix = UUID.randomUUID().toString().take(8)
            val a = create("exec-中文-$suffix-A")
            val b = create("exec-中文-$suffix-B")
            case("exec_shell_lua_artifacts") { artifacts(a, b) }
            case("exec_failure_and_redirection") { failedAndRedirected(a) }
            case("exec_static_shell_static_chain") { mixedChain(a) }
            case("exec_nested_shell_replacement") { nested(a) }
            case("exec_native_state_preserved") { state(a) }
            case("exec_invalid_requests_preserve_image") { fixture(a, "--exec-errors", "exec:errors=ok\n", 0) }
            case("exec_standard_stream_cloexec") { standardCloexec(a) }
            case("exec_chain_limit") { fixture(a, "--exec-chain", "exec:chain=32\n", 32) }
            case("exec_deadline_and_reuse") { deadline(a) }
            case("exec_cancel_and_reuse") { cancellation(a) }
            case("exec_parallel_projects") { parallel(a, b) }
        } catch (failure: Throwable) {
            failed++; summary.append("Runner failed: $failure\n")
        } finally {
            if (::client.isInitialized) {
                executions.forEach { id ->
                    try {
                        if (client.getExecution(id).getString("state") == "running") {
                            client.cancel(id)
                            check(client.waitFor(id, 10_000).getString("state") != "running")
                        }
                    } catch (failure: Throwable) { failed++; summary.append("Cleanup execution $id: $failure\n") }
                }
                environments.forEach { id ->
                    try { client.deleteEnvironment(id) }
                    catch (failure: Throwable) { failed++; summary.append("Cleanup environment $id: $failure\n") }
                }
            }
            instrumentation.finish(if (passed == TOTAL && failed == 0) Activity.RESULT_OK else Activity.RESULT_CANCELED,
                Bundle().apply {
                    putInt("passed", passed); putInt("failed", failed); putInt("expected_tests", TOTAL)
                    putString("probe", "exec"); putString("stream", "\n$summary\nPassed: $passed; failed: $failed\n")
                })
        }
    }

    private fun create(name: String) = client.createEnvironment(name).getString("id").also { environments.add(it) }
    private fun shell(env: String, script: String, timeout: Long = 20_000) =
        client.execute(env, script, "/", timeout).also { executions.add(it) }
    private fun program(env: String, argv: List<String>, stdin: ByteArray = byteArrayOf(),
                        variables: List<String> = emptyList(), timeout: Long = 20_000) =
        client.executeProgram(env, "musl-smoke", argv, variables, "/", timeout, stdin).also { executions.add(it) }

    private fun evidence(record: JSONObject) {
        val result = record.getJSONObject("result")
        check(result.getBoolean("binder_death_confirmed") && result.getBoolean("run_sent")) { record.toString() }
        check(result.getBoolean("output_drained") && result.getBoolean("broker_cleanup_confirmed"))
        check(result.getBoolean("stdin_feeder_completed") && !result.getBoolean("worker_never_started"))
        val worker = result.getJSONObject("worker")
        check(worker.getString("identity") == "isolated_runtime")
        check(worker.getInt("uid") != 0 && worker.getInt("uid") != Process.myUid())
        check(worker.getInt("pid") != Process.myPid())
    }

    private fun completed(id: String, count: Int, last: String, exit: Int = 0): JSONObject {
        val record = client.waitFor(id, 30_000)
        check(record.getString("execution_id") == id)
        check(record.getString("state") == "exited" && record.getInt("exit_code") == exit) { record.toString() }
        evidence(record)
        val native = record.getJSONObject("result").getJSONObject("native")
        check(native.getInt("exec_count") == count && native.getString("last_program") == last) { native.toString() }
        check(native.getInt("exec_limit") == 32)
        check(native.getInt("host_context_restores") == count + 1) { native.toString() }
        check(native.getBoolean("returned_to_host") && native.getBoolean("host_tls_restored"))
        check(native.getBoolean("thread_joined") && native.getBoolean("handler_restored"))
        check(native.getBoolean("on_alt_stack"))
        val worker = record.getJSONObject("result").getJSONObject("worker")
        check(native.getInt("pid") == worker.getInt("pid") && native.getInt("uid") == worker.getInt("uid"))
        return record
    }

    private fun artifacts(a: String, b: String): String {
        val catalog = client.listPrograms()
        val paths = (0 until catalog.length()).associate {
            val entry = catalog.getJSONObject(it)
            entry.getString("program_id") to entry.getString("path")
        }
        check(paths == mapOf("lua" to "/bin/lua", "musl-smoke" to "/bin/musl-smoke"))
        client.makeDirectory(a, "exec输出")
        val source = """
            assert(arg[1]=='参数 中文🙂')
            assert(os.getenv('PROJECT_VALUE')=='环境🙂')
            local f=assert(io.open('artifact.txt','w'));f:write(arg[1]..'\n');f:close()
            print('lua:artifact')
        """.trimIndent()
        client.writeFile(a, "exec输出/work.lua", source.toByteArray(Charsets.UTF_8))
        val result = completed(shell(a, "cd 'exec输出'; PROJECT_VALUE='环境🙂'; exec /bin/lua work.lua '参数 中文🙂'; echo forbidden"), 1, "lua")
        check(result.getString("stdout") == "lua:artifact\n" && result.getString("stderr").isEmpty()) { result.toString() }
        check(result.getJSONObject("result").getJSONObject("native").getString("kind") == "shell")
        check(client.readFile(a, "exec输出/artifact.txt").toString(Charsets.UTF_8) == "参数 中文🙂\n")
        expectMissing { client.readFile(b, "exec输出/artifact.txt") }
        val read = completed(shell(a, "cat 'exec输出/artifact.txt'"), 0, "sucrune-sh")
        check(read.getString("stdout") == "参数 中文🙂\n")
        return "Shell execs upstream Lua with UTF-8 argv/env/cwd, never returns, and persists an isolated artifact readable by a later Shell"
    }

    private fun failedAndRedirected(a: String): String {
        val missing = completed(shell(a, "exec /system/bin/sh || echo denied; exec /missing || echo missing; echo alive"), 0, "sucrune-sh")
        check(missing.getString("stdout") == "denied\nmissing\nalive\n") { missing.toString() }
        completed(shell(a, "exec /missing"), 0, "sucrune-sh", 127)
        client.writeFile(a, "redirect.lua", "print('redirected')\n".toByteArray())
        val redirected = completed(shell(a, "exec /bin/lua redirect.lua > keep.txt"), 1, "lua")
        check(redirected.getString("stdout").isEmpty() && redirected.getString("stderr").isEmpty())
        check(client.readFile(a, "keep.txt").toString(Charsets.UTF_8) == "redirected\n")
        val inherited = completed(shell(a, "sh -c 'exec /bin/lua redirect.lua' > inherited.txt"), 1, "lua")
        check(inherited.getString("stdout").isEmpty() && inherited.getString("stderr").isEmpty())
        check(client.readFile(a, "inherited.txt").toString(Charsets.UTF_8) == "redirected\n")
        return "Missing/host paths return 127 without replacing the image; direct and inherited exec stdout redirection now persist the real Lua output"
    }

    private fun mixedChain(a: String): String {
        val input = "assert(os.getenv('CHAIN')=='环境🙂');print('chain:ok')\n".toByteArray(Charsets.UTF_8)
        val result = completed(program(a, listOf("exec-path", "/bin/sucrune-sh", "-c", "exec /bin/lua -; echo forbidden"),
            input, listOf("CHAIN=环境🙂")), 2, "lua")
        check(result.getString("stdout") == "chain:ok\n") { result.toString() }
        check(result.getJSONObject("result").getJSONObject("native").getString("kind") == "program")
        check(result.getJSONObject("result").getJSONObject("native").getInt("stdin_bytes_read") == input.size)
        return "Static libc -> relocated Shell -> static Lua preserves stdin/env under one execution and restores host TLS"
    }

    private fun nested(a: String): String {
        client.writeFile(a, "nested.lua", "print('nested:ok')\n".toByteArray())
        val result = completed(shell(a, "sh -c 'exec /bin/lua nested.lua; echo forbidden-child'; echo forbidden-parent"), 1, "lua")
        check(result.getString("stdout") == "nested:ok\n") { result.toString() }
        return "Successful exec inside nested Shell replaces the whole guest and returns to neither child nor parent script"
    }

    private fun state(a: String): String {
        fixture(a, "--exec-state", "exec:state=ok\n", 1, "prefix:remaining\n".toByteArray())
        return "Same PID/TID; cwd and non-CLOEXEC FD offset survive; file/stderr CLOEXEC apply; fresh TLS/BSS/memory and remaining stdin verified inside guest"
    }

    private fun fixture(a: String, flag: String, output: String, count: Int, stdin: ByteArray = byteArrayOf()): String {
        val result = completed(program(a, listOf(flag), stdin), count, "musl-smoke")
        check(result.getString("stdout") == output && result.getString("stderr").isEmpty()) { result.toString() }
        return "$flag: guest assertions and four cleanup barriers passed, exec_count=$count"
    }

    private fun standardCloexec(a: String): String {
        fixture(a, "--exec-stdin-cloexec", "exec:stdin-cloexec=ok\n", 1, ByteArray(1_048_576))
        val outputClosed = completed(program(a, listOf("--exec-stdout-cloexec")), 1, "musl-smoke")
        check(outputClosed.getString("stdout").isEmpty())
        check(outputClosed.getString("stderr") == "exec:stdout-cloexec=ok\n") { outputClosed.toString() }
        return "stdin and stdout CLOEXEC independently become EBADF across exec, with input completion and output-drain ownership preserved"
    }

    private fun prepareLoop(a: String) {
        client.writeFile(a, "loop.lua", "print('exec:loop');io.stdout:flush();while true do end\n".toByteArray())
    }

    private fun deadline(a: String): String {
        prepareLoop(a)
        val began = SystemClock.elapsedRealtime()
        val id = shell(a, "sleep 2; exec /bin/lua loop.lua", 3_000)
        waitForOutput(id, "exec:loop\n")
        val result = client.waitFor(id, 10_000)
        val elapsed = SystemClock.elapsedRealtime() - began
        check(result.getString("state") == "timed_out" && !result.has("exit_code")) { result.toString() }
        check(elapsed in 2_500..4_500) { "Original absolute deadline was not retained: $elapsed ms" }
        evidence(result)
        check(completed(shell(a, "echo after-deadline"), 0, "sucrune-sh").getString("stdout") == "after-deadline\n")
        return "Original 3000ms deadline survives exec (elapsed=${elapsed}ms); CPU-only successor is killed before project reuse"
    }

    private fun cancellation(a: String): String {
        prepareLoop(a)
        val id = program(a, listOf("exec-path", "/bin/lua", "loop.lua"), ByteArray(1_048_576), timeout = 30_000)
        waitForOutput(id, "exec:loop\n")
        check(client.cancel(id))
        val result = client.waitFor(id, 10_000)
        check(result.getString("state") == "cancelled" && !result.has("exit_code")) { result.toString() }
        evidence(result)
        check(result.getJSONObject("result").getInt("stdin_bytes_written") < 1_048_576)
        check(completed(shell(a, "echo after-cancel"), 0, "sucrune-sh").getString("stdout") == "after-cancel\n")
        return "Cancellation kills replaced CPU-only image with backpressured input; all streams/broker/feeder finish before reuse"
    }

    private fun parallel(a: String, b: String): String {
        fun script(value: String) = "local f=assert(io.open('exec-parallel.txt','w'));f:write('$value');f:close();" +
            "local t=os.clock()+0.6;while os.clock()<t do end;print('$value')"
        client.writeFile(a, "parallel.lua", script("A").toByteArray())
        client.writeFile(b, "parallel.lua", script("B").toByteArray())
        val ai = shell(a, "exec /bin/lua parallel.lua")
        val bi = shell(b, "exec /bin/lua parallel.lua")
        val ar = completed(ai, 1, "lua"); val br = completed(bi, 1, "lua")
        check(ar.getString("stdout") == "A\n" && br.getString("stdout") == "B\n")
        check(client.readFile(a, "exec-parallel.txt").toString(Charsets.UTF_8) == "A")
        check(client.readFile(b, "exec-parallel.txt").toString(Charsets.UTF_8) == "B")
        val aw = ar.getJSONObject("result").getJSONObject("worker")
        val bw = br.getJSONObject("result").getJSONObject("worker")
        check(aw.getInt("pid") != bw.getInt("pid") && aw.getInt("uid") != bw.getInt("uid"))
        val an = ar.getJSONObject("result").getJSONObject("native")
        val bn = br.getJSONObject("result").getJSONObject("native")
        val overlap = minOf(an.getLong("native_finished_at_elapsed_ms"), bn.getLong("native_finished_at_elapsed_ms")) -
            maxOf(an.getLong("native_started_at_elapsed_ms"), bn.getLong("native_started_at_elapsed_ms"))
        check(overlap >= 100) { "Insufficient native overlap: $overlap ms" }
        return "overlap=${overlap}ms; distinct worker PIDs/UIDs and project artifacts after independent image replacements"
    }

    private fun waitForOutput(id: String, text: String) {
        val until = SystemClock.elapsedRealtime() + 8_000
        while (true) {
            val record = client.getExecution(id)
            if (record.getString("stdout").contains(text)) return
            check(record.getString("state") == "running" && SystemClock.elapsedRealtime() < until) { record.toString() }
            SystemClock.sleep(25)
        }
    }
    private fun expectMissing(body: () -> Any) {
        try { body() } catch (failure: RuntimeExceptionWithCode) { check(failure.code == "not_found"); return }
        error("Expected missing file")
    }
    private fun case(name: String, body: () -> String) {
        current++; publish(1, name, "Starting $name")
        try { val detail = body(); passed++; summary.append("$name: PASS $detail\n"); publish(0, name, detail) }
        catch (failure: Throwable) { failed++; summary.append("$name: FAIL $failure\n"); publish(-2, name, failure.toString()) }
    }
    private fun publish(code: Int, name: String, detail: String) = instrumentation.sendStatus(code, Bundle().apply {
        putString("id", "SucruneExec"); putString("class", ExecChecks::class.java.name)
        putString("test", name); putInt("current", current); putInt("numtests", TOTAL)
        putString("stream", "\n$name: $detail\n")
    })
    companion object { private const val TOTAL = 11 }
}
