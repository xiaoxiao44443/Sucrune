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
import java.security.MessageDigest
import java.util.UUID

/** Real upstream Lua and finite stdin, exercised through the public runtime API. */
internal class ToolsChecks(private val instrumentation: Instrumentation,
                           private val context: Context, private val arguments: Bundle) {
    private lateinit var client: RuntimeClient
    private val environments = ArrayList<String>()
    private val executions = ArrayList<String>()
    private var passed = 0
    private var failed = 0
    private var current = 0
    private val summary = StringBuilder()

    fun run() {
        try {
            check(Build.SUPPORTED_ABIS.firstOrNull() == "arm64-v8a")
            val debug = context.applicationInfo.flags and ApplicationInfo.FLAG_DEBUGGABLE != 0
            arguments.getString("expect_debuggable")?.let { check(it == debug.toString()) }
            check(Process.myUid() == context.applicationInfo.uid && Process.myUid() != 0)
            client = RuntimeClient.get(context)
            val suffix = UUID.randomUUID().toString().take(8)
            val a = create("lua-工具-$suffix-A")
            val b = create("lua-工具-$suffix-B")
            case("tool_catalog_and_input_limits") { catalog(a) }
            case("lua_language_arguments_environment") { language(a) }
            case("lua_script_modules_project_files") { files(a, b) }
            case("lua_stdin_script_and_eof") { stdinScript(a) }
            case("lua_binary_stdin_backpressure") { binaryInput(a) }
            case("tool_ignored_and_closed_stdin") { closedInput(a) }
            case("lua_timeout_full_stdin_and_reuse") { timeout(a) }
            case("lua_errors_and_unsupported_operations") { errors(a) }
            case("lua_cpu_clock_and_calendar") { clocks(a) }
            case("lua_parallel_projects") { parallel(a, b) }
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
                    putString("probe", "tools"); putString("stream", "\n$summary\nPassed: $passed; failed: $failed\n")
                })
        }
    }

    private fun create(name: String): String = client.createEnvironment(name).getString("id").also { environments.add(it) }
    private fun start(envId: String, argv: List<String> = emptyList(), env: List<String> = emptyList(),
                      cwd: String = "/", timeout: Long = 20_000, stdin: ByteArray = byteArrayOf()): String =
        client.executeProgram(envId, "lua", argv, env, cwd, timeout, stdin).also { executions.add(it) }
    private fun code(envId: String, source: String, stdin: ByteArray = byteArrayOf(), timeout: Long = 20_000): String =
        start(envId, listOf("-e", source), timeout = timeout, stdin = stdin)

    private fun complete(id: String, exit: Int = 0): JSONObject {
        val record = client.waitFor(id, 30_000)
        check(record.getString("state") == "exited" && record.getInt("exit_code") == exit) { record.toString() }
        evidence(record)
        val native = record.getJSONObject("result").getJSONObject("native")
        check(native.getString("kind") == "program" && native.getString("status") == "exited")
        check(native.getInt("exit_code") == exit && native.getBoolean("returned_to_host"))
        check(native.getBoolean("thread_joined") && native.getBoolean("handler_restored"))
        check(native.getBoolean("on_alt_stack") && native.getBoolean("guest_tls_seen") && native.getBoolean("host_tls_restored"))
        return record
    }

    private fun evidence(record: JSONObject) {
        val result = record.getJSONObject("result")
        check(result.getBoolean("binder_death_confirmed") && result.getBoolean("run_sent")) { record.toString() }
        check(result.getBoolean("output_drained") && result.getBoolean("broker_cleanup_confirmed"))
        check(result.getBoolean("stdin_feeder_completed"))
        val worker = result.getJSONObject("worker")
        check(worker.getString("identity") == "isolated_runtime")
        check(worker.getInt("uid") != 0 && worker.getInt("uid") != context.applicationInfo.uid)
        check(worker.getInt("pid") > 0 && worker.getInt("pid") != Process.myPid())
        check(worker.getString("abi") == "arm64-v8a" && worker.getInt("api_level") == Build.VERSION.SDK_INT)
        check(worker.getBoolean("debuggable") == (context.applicationInfo.flags and ApplicationInfo.FLAG_DEBUGGABLE != 0))
    }

    private fun catalog(a: String): String {
        val catalog = client.listPrograms()
        val ids = (0 until catalog.length()).map { catalog.getJSONObject(it).getString("program_id") }
        check(ids.toSet().size == ids.size && ids.containsAll(listOf("musl-smoke", "lua")))
        val lua = (0 until catalog.length()).map { catalog.getJSONObject(it) }.single { it.getString("program_id") == "lua" }
        check(lua.getString("name") == "Lua" && lua.getString("version") == "5.4.9")
        val before = client.listExecutions(a).length()
        expectCode("unsupported_program") { client.executeProgram(a, "/system/bin/sh") }
        try { start(a, stdin = ByteArray(1_048_577)); error("Oversized input accepted") }
        catch (_: IllegalArgumentException) {}
        check(client.listExecutions(a).length() == before)
        return "Native catalog identifies Lua 5.4.9; unknown tool and >1 MiB stdin rejected before reservation"
    }

    private fun language(a: String): String {
        val source = "local function make(n) return function(x) return x+n end end; " +
            "local t={};for i=1,5 do t[i]=make(7)(i) end; " +
            "assert(table.concat(t,',')=='8,9,10,11,12');assert(math.sqrt(81)==9); " +
            "assert(utf8.len('中文🙂')==3);assert(os.getenv('SUCRUNE_TEST')=='环境中文🙂'); " +
            "print(_VERSION);print('language:ok')"
        val record = complete(start(a, listOf("-e", source), listOf("SUCRUNE_TEST=环境中文🙂")))
        check(record.getString("stdout") == "Lua 5.4\nlanguage:ok\n" && record.getString("stderr").isEmpty()) { record.toString() }
        return "Upstream Lua executes closures, loops, tables, math, UTF-8 and environment lookup"
    }

    private fun files(a: String, b: String): String {
        client.makeDirectory(a, "脚本🙂")
        client.makeDirectory(a, "脚本🙂/modules")
        client.writeFile(a, "脚本🙂/modules/util.lua", "return {sum=function(a,b) return a+b end}\n".toByteArray())
        val script = "local m=require('util');assert(m.sum(19,23)==42);assert(arg[1]=='参数🙂'); " +
            "local f=assert(io.open('result.txt','w+'));assert(f:write('产物🙂\\n'));assert(f:seek('set',0)==0); " +
            "assert(f:read('*a')=='产物🙂\\n');assert(f:close());assert(os.rename('result.txt','final.txt')); " +
            "print('files:ok')"
        client.writeFile(a, "脚本🙂/main.lua", script.toByteArray(Charsets.UTF_8))
        val result = complete(start(a, listOf("main.lua", "参数🙂"), listOf("LUA_PATH=./modules/?.lua"), cwd = "/脚本🙂"))
        check(result.getString("stdout") == "files:ok\n") { result.toString() }
        check(client.readFile(a, "脚本🙂/final.txt").toString(Charsets.UTF_8) == "产物🙂\n")
        expectCode("not_found") { client.readFile(b, "脚本🙂/final.txt") }
        val shellId = client.execute(a, "cat '脚本🙂/final.txt'").also { executions.add(it) }
        val shell = client.waitFor(shellId, 20_000)
        check(shell.getString("state") == "exited" && shell.getInt("exit_code") == 0 && shell.getString("stdout") == "产物🙂\n")
        return "Lua script and require module load from project cwd; seek/write/rename persist a Unicode artifact readable by Shell"
    }

    private fun stdinScript(a: String): String {
        val source = "print('stdin:中文🙂')\n".toByteArray(Charsets.UTF_8)
        val result = complete(start(a, listOf("-"), stdin = source))
        check(result.getString("stdout") == "stdin:中文🙂\n") { result.toString() }
        check(result.getJSONObject("result").getInt("stdin_bytes_written") == source.size)
        val empty = complete(start(a))
        check(empty.getString("stdout").isEmpty() && empty.getString("stderr").isEmpty())
        check(empty.getJSONObject("result").getInt("stdin_bytes_written") == 0)
        return "Lua '-' reads a UTF-8 script and EOF; omitted empty stdin exits normally without waiting for a terminal"
    }

    private fun binaryInput(a: String): String {
        val input = ByteArray(1_048_576) { (it % 256).toByte() }
        val expected = input.copyOf()
        val hash = MessageDigest.getInstance("SHA-256").digest(expected).joinToString("") { "%02x".format(it.toInt() and 255) }
        val source = "io.stderr:write('binary:start\\n');io.stderr:flush();local s=assert(io.read('*a')); " +
            "local f=assert(io.open('stdin.bin','wb'));assert(f:write(s));assert(f:close());print(#s)"
        val id = code(a, source, input)
        input.fill(17) // Caller mutation must not alter the already accepted execution.
        val record = complete(id)
        check(record.getString("stdout") == "1048576\n" && record.getString("stderr") == "binary:start\n") { record.toString() }
        check(client.readFile(a, "stdin.bin").contentEquals(expected))
        check(record.getJSONObject("result").getInt("stdin_bytes_written") == expected.size)
        check(record.getJSONObject("result").getJSONObject("native").getInt("stdin_bytes_read") == expected.size)
        val request = record.getJSONObject("request")
        check(request.getInt("stdin_bytes") == expected.size && request.getString("stdin_sha256") == hash)
        check(!request.has("stdin") && !request.has("stdin_base64"))
        return "1 MiB binary stdin, including NUL, exceeds transport capacity and round-trips exactly; input copy/hash and feeder completion verified"
    }

    private fun closedInput(a: String): String {
        val input = ByteArray(1_048_576) { 23 }
        val ignored = complete(code(a, "print('ignored')", input))
        check(ignored.getString("stdout") == "ignored\n")
        // Upstream Lua intentionally refuses to close standard files. The trusted
        // native fixture issues close(0), then remains alive without further syscalls.
        val id = client.executeProgram(a, "musl-smoke", listOf("--close-stdin-loop"),
            timeoutMs = 30_000, stdin = input).also { executions.add(it) }
        waitFor(id) { it.getString("stdout").contains("closed\n") &&
            it.optJSONObject("runtime")?.optBoolean("stdin_feeder_completed") == true }
        val live = client.getExecution(id)
        check(live.getString("state") == "running")
        check(live.getJSONObject("runtime").getInt("stdin_bytes_written") < input.size)
        check(client.cancel(id))
        val stopped = client.waitFor(id, 10_000)
        check(stopped.getString("state") == "cancelled" && !stopped.has("exit_code"))
        evidence(stopped)
        check(complete(code(a, "print('after-close')")).getString("stdout") == "after-close\n")
        return "Lua ignores stdin without blocking exit; native musl fixture close(0) ends feeder before worker kill, cancellation and Lua reuse succeed"
    }

    private fun timeout(a: String): String {
        val cancelled = code(a, "print('cancel:start');io.stdout:flush();while true do end", ByteArray(1_048_576))
        var previousBytes = -1
        var stableSince = SystemClock.elapsedRealtime()
        waitFor(cancelled) { record ->
            val runtime = record.optJSONObject("runtime")
            val written = runtime?.optInt("stdin_bytes_written") ?: 0
            if (written != previousBytes) { previousBytes = written; stableSince = SystemClock.elapsedRealtime() }
            record.getString("stdout").contains("cancel:start\n") && written > 0 && written < 1_048_576 &&
                runtime?.optBoolean("stdin_feeder_completed") == false &&
                SystemClock.elapsedRealtime() - stableSince >= 150
        }
        check(client.cancel(cancelled))
        val cancelledRecord = client.waitFor(cancelled, 10_000)
        check(cancelledRecord.getString("state") == "cancelled" && !cancelledRecord.has("exit_code"))
        evidence(cancelledRecord)
        val id = code(a, "print('loop:start');io.stdout:flush();while true do end", ByteArray(1_048_576), 2_000)
        waitFor(id) { it.getString("stdout").contains("loop:start\n") }
        val record = client.waitFor(id, 10_000)
        check(record.getString("state") == "timed_out" && !record.has("exit_code")) { record.toString() }
        evidence(record)
        check(record.getJSONObject("result").getInt("stdin_bytes_written") < 1_048_576)
        check(complete(code(a, "print('after-timeout')")).getString("stdout") == "after-timeout\n")
        return "Cancel and deadline stop CPU-only Lua with backpressured unread stdin; input writer closes before project reuse"
    }

    private fun errors(a: String): String {
        val syntax = complete(code(a, "local = broken"), 1)
        check(syntax.getString("stderr").isNotEmpty())
        val runtime = complete(code(a, "error('expected-error')"), 1)
        check(runtime.getString("stderr").contains("expected-error"))
        val source = "local ok=os.execute('echo forbidden > forbidden.txt');assert(ok~=true); " +
            "local f,msg=package.loadlib('missing.so','entry');assert(f==nil and type(msg)=='string'); " +
            "local opened,p=pcall(io.popen,'echo forbidden');assert(not opened or p==nil); " +
            "assert(io.open('/proc/self/status','r')==nil);print('unsupported:ok')"
        val result = complete(code(a, source))
        check(result.getString("stdout") == "unsupported:ok\n") { result.toString() }
        expectCode("not_found") { client.readFile(a, "forbidden.txt") }
        return "Syntax/runtime errors exit nonzero; process execution, dynamic modules and popen fail; host proc lookup does not escape workspace"
    }

    private fun clocks(a: String): String {
        val source = "local a=os.clock();assert(a>=0);local sum=0;for i=1,100000 do sum=sum+i end; " +
            "assert(os.clock()>=a);local t=os.time();assert(type(t)=='number' and t>0); " +
            "local d=os.date('!*t',t);assert(d.year>=2026);print('clock:ok')"
        val result = complete(code(a, source))
        check(result.getString("stdout") == "clock:ok\n") { result.toString() }
        return "Lua os.clock/process CPU time and UTC calendar functions work with the libc time path"
    }

    private fun parallel(a: String, b: String): String {
        fun script(value: String) = "local f=assert(io.open('parallel.txt','w'));f:write('$value');f:close(); " +
            "local until_time=os.clock()+0.6;while os.clock()<until_time do end;print('$value')"
        val aId = code(a, script("A")); val bId = code(b, script("B"))
        val ar = complete(aId); val br = complete(bId)
        check(ar.getString("stdout") == "A\n" && br.getString("stdout") == "B\n")
        check(client.readFile(a, "parallel.txt").toString(Charsets.UTF_8) == "A")
        check(client.readFile(b, "parallel.txt").toString(Charsets.UTF_8) == "B")
        val aw = ar.getJSONObject("result").getJSONObject("worker")
        val bw = br.getJSONObject("result").getJSONObject("worker")
        check(aw.getInt("pid") != bw.getInt("pid") && aw.getInt("uid") != bw.getInt("uid"))
        val an = ar.getJSONObject("result").getJSONObject("native")
        val bn = br.getJSONObject("result").getJSONObject("native")
        val overlap = minOf(an.getLong("native_finished_at_elapsed_ms"), bn.getLong("native_finished_at_elapsed_ms")) -
            maxOf(an.getLong("native_started_at_elapsed_ms"), bn.getLong("native_started_at_elapsed_ms"))
        check(overlap >= 100) { "Native overlap too short: $overlap ms" }
        return "overlap=${overlap}ms; PIDs=${aw.getInt("pid")},${bw.getInt("pid")}; UIDs=${aw.getInt("uid")},${bw.getInt("uid")}"
    }

    private fun waitFor(id: String, ready: (JSONObject) -> Boolean) {
        val deadline = SystemClock.elapsedRealtime() + 8_000
        while (true) {
            val record = client.getExecution(id)
            if (ready(record)) return
            check(record.getString("state") == "running" && SystemClock.elapsedRealtime() < deadline) { record.toString() }
            SystemClock.sleep(25)
        }
    }
    private fun expectCode(code: String, action: () -> Any) {
        try { action() } catch (failure: RuntimeExceptionWithCode) { check(failure.code == code); return }
        error("Expected $code")
    }
    private fun case(name: String, body: () -> String) {
        current++; publish(1, name, "Starting $name")
        try { val detail = body(); passed++; summary.append("$name: PASS $detail\n"); publish(0, name, detail) }
        catch (failure: Throwable) { failed++; summary.append("$name: FAIL $failure\n"); publish(-2, name, failure.toString()) }
    }
    private fun publish(code: Int, name: String, detail: String) = instrumentation.sendStatus(code, Bundle().apply {
        putString("id", "SucruneTools"); putString("class", ToolsChecks::class.java.name)
        putString("test", name); putInt("current", current); putInt("numtests", TOTAL)
        putString("stream", "\n$name: $detail\n")
    })
    companion object { private const val TOTAL = 10 }
}
