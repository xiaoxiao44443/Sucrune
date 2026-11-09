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

/** Real guest descriptor aliases, redirection and ownership under supervision. */
internal class IOChecks(private val instrumentation: Instrumentation,
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
            val a = create("io-中文-$suffix-A")
            val b = create("io-中文-$suffix-B")
            case("io_shell_lua_file_streams") { fileStreams(a, b) }
            case("io_builtin_restore_append") { restoreAndAppend(a) }
            case("io_redirection_errors_and_order") { errorsAndOrder(a) }
            case("io_nested_exec_redirection") { nested(a) }
            case("io_shared_offsets_flags") { fixture(a, "--fd-aliases", "fd:aliases=ok\n") }
            case("io_errors_capacity_recovery") { capacity(a) }
            case("io_aliases_across_exec") { fixture(a, "--fd-exec-aliases", "fd:exec-aliases=ok\n", execs = 1) }
            case("io_standard_stream_aliases") { standardAliases(a) }
            case("io_last_stdin_alias_close") { lastInputAlias(a) }
            case("io_exec_closes_saved_input") { savedInput(a) }
            case("io_repeated_redirect_no_leak") { repeated(a) }
            case("io_parallel_project_streams") { parallel(a, b) }
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
                    putString("probe", "io"); putString("stream", "\n$summary\nPassed: $passed; failed: $failed\n")
                })
        }
    }

    private fun create(name: String) = client.createEnvironment(name).getString("id").also { environments.add(it) }
    private fun shell(env: String, script: String) = client.execute(env, script).also { executions.add(it) }
    private fun program(env: String, argv: List<String>, stdin: ByteArray = byteArrayOf()) =
        client.executeProgram(env, "musl-smoke", argv, stdin = stdin).also { executions.add(it) }
    private fun write(env: String, path: String, text: String) = client.writeFile(env, path, text.toByteArray(Charsets.UTF_8))
    private fun read(env: String, path: String) = client.readFile(env, path).toString(Charsets.UTF_8)

    private fun barriers(record: JSONObject) {
        val result = record.getJSONObject("result")
        check(result.getBoolean("binder_death_confirmed") && result.getBoolean("run_sent")) { record.toString() }
        check(result.getBoolean("output_drained") && result.getBoolean("broker_cleanup_confirmed"))
        check(result.getBoolean("stdin_feeder_completed") && !result.getBoolean("worker_never_started"))
        val worker = result.getJSONObject("worker")
        check(worker.getString("identity") == "isolated_runtime")
        check(worker.getInt("uid") != 0 && worker.getInt("uid") != Process.myUid())
        check(worker.getInt("pid") != Process.myPid())
    }
    private fun complete(id: String, execs: Int = 0, exit: Int = 0): JSONObject {
        val record = client.waitFor(id, 35_000)
        check(record.getString("state") == "exited" && record.getInt("exit_code") == exit) { record.toString() }
        barriers(record)
        val native = record.getJSONObject("result").getJSONObject("native")
        check(native.getInt("exec_count") == execs && native.getInt("host_context_restores") == execs + 1)
        check(native.getInt("fd_limit") == 64 && native.getInt("fd_peak") in 3..64)
        check(native.getInt("fds_live") == 0 && native.getInt("resources_live") == 0) { native.toString() }
        check(native.getBoolean("returned_to_host") && native.getBoolean("host_tls_restored"))
        check(native.getBoolean("thread_joined") && native.getBoolean("handler_restored") && native.getBoolean("on_alt_stack"))
        return record
    }
    private fun fixture(a: String, flag: String, output: String, stdin: ByteArray = byteArrayOf(), execs: Int = 0): String {
        val result = complete(program(a, listOf(flag), stdin), execs)
        check(result.getString("stdout") == output && result.getString("stderr").isEmpty()) { result.toString() }
        return "$flag: native guest assertions, capture streams and cleanup barriers passed"
    }

    private fun fileStreams(a: String, b: String): String {
        write(a, "输入🙂.txt", "10\n20\n12\n")
        write(a, "sum.lua", "local sum=0;for line in io.lines() do sum=sum+assert(tonumber(line)) end;print('sum='..sum)")
        val result = complete(shell(a, "exec /bin/lua sum.lua < '输入🙂.txt' > '产物🙂.txt'"), 1)
        check(result.getString("stdout").isEmpty() && result.getString("stderr").isEmpty()) { result.toString() }
        check(read(a, "产物🙂.txt") == "sum=42\n")
        expectMissing { read(b, "产物🙂.txt") }
        return "Real Lua reads fd0 from a Unicode project file and writes fd1 to a persistent artifact; project B cannot see it"
    }

    private fun restoreAndAppend(a: String): String {
        val result = complete(shell(a, "echo before; echo one > lines.txt; echo two >> lines.txt; cat < lines.txt; echo after"))
        check(result.getString("stdout") == "before\none\ntwo\nafter\n") { result.toString() }
        check(read(a, "lines.txt") == "one\ntwo\n")
        write(a, "-", "dash-file\n")
        val dash = complete(shell(a, "cat ./-; cat - < lines.txt; cat -- < lines.txt"))
        check(dash.getString("stdout") == "dash-file\none\ntwo\none\ntwo\n") { dash.toString() }
        return "Builtin redirects restore original stdout/stdin; append persists; cat no-args and '-' read stdin while './-' names a file"
    }

    private fun errorsAndOrder(a: String): String {
        write(a, "ordered.txt", "keep")
        complete(shell(a, "echo x < absent-input > ordered.txt"), exit = 1)
        check(read(a, "ordered.txt") == "keep")
        complete(shell(a, "echo x > ordered.txt < absent-input"), exit = 1)
        check(read(a, "ordered.txt").isEmpty())
        val failed = complete(shell(a, "exec /missing > failed-exec.txt || echo restored; echo alive"))
        check(failed.getString("stdout") == "restored\nalive\n" && failed.getString("stderr").isNotEmpty()) { failed.toString() }
        check(read(a, "failed-exec.txt").isEmpty())
        write(a, "no-truncate.txt", "unchanged")
        complete(shell(a, "echo x > no-truncate.txt > second.txt"), exit = 2)
        complete(shell(a, "cat < no-truncate.txt < second.txt"), exit = 2)
        complete(shell(a, "cat << no-truncate.txt"), exit = 2)
        complete(shell(a, "echo x 2> no-truncate.txt"), exit = 2)
        check(read(a, "no-truncate.txt") == "unchanged")
        expectMissing { read(a, "second.txt") }
        return "Lexical redirect order is respected; failed exec restores streams; duplicate/heredoc/descriptor syntax is rejected before file side effects"
    }

    private fun nested(a: String): String {
        write(a, "nested-in.txt", "nested\n")
        val nested = complete(shell(a, "sh -c 'cat; echo child' < nested-in.txt > nested-out.txt; echo parent"))
        check(nested.getString("stdout") == "parent\n" && read(a, "nested-out.txt") == "nested\nchild\n")
        write(a, "nested-copy.lua", "io.write(assert(io.read('*a')));print('lua-end')")
        val replaced = complete(shell(a, "sh -c 'exec /bin/lua nested-copy.lua' < nested-in.txt > nested-exec.txt; echo forbidden"), 1)
        check(replaced.getString("stdout").isEmpty())
        check(read(a, "nested-exec.txt") == "nested\nlua-end\n")
        return "Nested Shell inherits actual fd0/fd1; returned frames restore them, successful nested exec retains them without returning"
    }

    private fun capacity(a: String): String {
        fixture(a, "--fd-errors", "fd:errors=ok\n")
        val result = complete(program(a, listOf("--fd-capacity")))
        check(result.getJSONObject("result").getJSONObject("native").getInt("fd_peak") == 64)
        check(result.getString("stdout").isEmpty() && result.getString("stderr").isEmpty()) { result.toString() }
        check(read(a, "fd-capacity-result.txt") == "fd:capacity=64\n")
        check(complete(shell(a, "echo after-capacity")).getString("stdout") == "after-capacity\n")
        return "Invalid dup requests preserve descriptors; 64 unique file resources including reused std numbers exhaust/recover correctly and project is reusable"
    }

    private fun standardAliases(a: String): String {
        val input = "stdio-input\n".toByteArray()
        val result = complete(program(a, listOf("--fd-stdio"), input))
        check(result.getString("stdout") == "fd:stdout-alias\nfd:stdio=ok\n") { result.toString() }
        check(result.getString("stderr") == "fd:stderr-alias\n")
        check(result.getJSONObject("result").getJSONObject("native").getInt("stdin_bytes_read") == input.size)
        return "Duplicated standard streams route by original resource, file remapping supports stat/seek/access modes, and aliased stdin bytes are counted"
    }

    private fun lastInputAlias(a: String): String {
        val id = program(a, listOf("--fd-stdin-alias-loop"), ByteArray(1_048_576))
        val open = waitFor(id) { it.getString("stdout").contains("fd:alias-open\n") }
        check(open.getString("state") == "running")
        check(!open.getJSONObject("runtime").getBoolean("stdin_feeder_completed")) { open.toString() }
        val closed = waitFor(id) {
            it.getString("stdout").contains("fd:alias-closed\n") &&
                it.optJSONObject("runtime")?.optBoolean("stdin_feeder_completed") == true
        }
        check(closed.getString("state") == "running")
        check(closed.getJSONObject("runtime").getInt("stdin_bytes_written") < 1_048_576)
        check(client.cancel(id))
        val stopped = client.waitFor(id, 10_000)
        check(stopped.getString("state") == "cancelled" && !stopped.has("exit_code"))
        barriers(stopped)
        check(complete(shell(a, "echo after-alias")).getString("stdout") == "after-alias\n")
        return "Closing fd0 keeps its live alias readable; last alias close ends the blocked feeder while guest stays alive, then cancellation and reuse succeed"
    }

    private fun savedInput(a: String): String {
        write(a, "loop-input.txt", "input-from-file")
        write(a, "redirect-loop.lua", "assert(io.read('*a')=='input-from-file');print('artifact-ready');io.stdout:flush();" +
            "io.stderr:write('redirect:ready\\n');io.stderr:flush();while true do end")
        val command = "exec /bin/lua redirect-loop.lua < loop-input.txt > loop-artifact.txt"
        val id = program(a, listOf("exec-path", "/bin/sucrune-sh", "-c", command), ByteArray(1_048_576))
        val live = waitFor(id) {
            it.getString("stderr").contains("redirect:ready\n") &&
                it.optJSONObject("runtime")?.optBoolean("stdin_feeder_completed") == true
        }
        check(live.getString("state") == "running" && live.getString("stdout").isEmpty())
        check(live.getJSONObject("runtime").getInt("stdin_bytes_written") < 1_048_576)
        check(client.cancel(id))
        val stopped = client.waitFor(id, 10_000)
        check(stopped.getString("state") == "cancelled")
        barriers(stopped)
        check(read(a, "loop-artifact.txt") == "artifact-ready\n")
        return "Redirected exec closes Shell's CLOEXEC saved-input alias, so no hidden reader blocks feeder completion; redirected artifact survives cancellation"
    }

    private fun repeated(a: String): String {
        val script = buildString {
            repeat(100) { append("echo item > repeated.txt; cat < repeated.txt > repeated-copy.txt; ") }
            append("echo finished")
        }
        val result = complete(shell(a, script))
        check(result.getString("stdout") == "finished\n" && result.getString("stderr").isEmpty()) { result.toString() }
        check(read(a, "repeated-copy.txt") == "item\n")
        return "200 redirected commands complete within a 64-FD table without leaking saved descriptors or resources"
    }

    private fun parallel(a: String, b: String): String {
        val source = "local data=assert(io.read('*a'));local t=os.clock()+0.6;while os.clock()<t do end;io.write(data)"
        write(a, "parallel.lua", source); write(b, "parallel.lua", source)
        write(a, "parallel-input.txt", "A中文\n"); write(b, "parallel-input.txt", "B中文\n")
        val command = "exec /bin/lua parallel.lua < parallel-input.txt > parallel-output.txt"
        val ai = shell(a, command); val bi = shell(b, command)
        val ar = complete(ai, 1); val br = complete(bi, 1)
        check(ar.getString("stdout").isEmpty() && br.getString("stdout").isEmpty())
        check(read(a, "parallel-output.txt") == "A中文\n" && read(b, "parallel-output.txt") == "B中文\n")
        val aw = ar.getJSONObject("result").getJSONObject("worker")
        val bw = br.getJSONObject("result").getJSONObject("worker")
        check(aw.getInt("pid") != bw.getInt("pid") && aw.getInt("uid") != bw.getInt("uid"))
        val an = ar.getJSONObject("result").getJSONObject("native")
        val bn = br.getJSONObject("result").getJSONObject("native")
        val overlap = minOf(an.getLong("native_finished_at_elapsed_ms"), bn.getLong("native_finished_at_elapsed_ms")) -
            maxOf(an.getLong("native_started_at_elapsed_ms"), bn.getLong("native_started_at_elapsed_ms"))
        check(overlap >= 100) { "Insufficient overlap: $overlap ms" }
        return "overlap=${overlap}ms; separate worker PIDs/UIDs and independent redirected input/output files"
    }

    private fun waitFor(id: String, predicate: (JSONObject) -> Boolean): JSONObject {
        val until = SystemClock.elapsedRealtime() + 8_000
        while (true) {
            val record = client.getExecution(id)
            if (predicate(record)) return record
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
        putString("id", "SucruneIO"); putString("class", IOChecks::class.java.name)
        putString("test", name); putInt("current", current); putInt("numtests", TOTAL)
        putString("stream", "\n$name: $detail\n")
    })
    companion object { private const val TOTAL = 12 }
}
