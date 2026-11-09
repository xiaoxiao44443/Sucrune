package com.sucrune.probe.tests

import android.app.Activity
import android.app.Instrumentation
import android.os.Bundle
import android.os.SystemClock
import com.sucrune.probe.RuntimeClient
import org.json.JSONObject
import java.net.InetSocketAddress
import java.net.ServerSocket
import java.net.Socket
import java.util.UUID

/** Run from the test APK with -e probe resident and the verified Linux Node rootfs assets. */
internal fun residentExecutionChecks(instrumentation: Instrumentation) {
    val client = RuntimeClient.get(instrumentation.targetContext)
    val projects = mutableSetOf<String>()
    val executions = mutableListOf<String>()
    val outcome = Bundle()
    fun project(): String = client.createEnvironment("resident-" + UUID.randomUUID().toString().take(8))
        .getString("id").also { projects.add(it) }
    fun progress(message: String) = instrumentation.sendStatus(1, Bundle().apply { putString("stream", "\n$message\n") })
    fun waitForOutput(id: String, marker: String): JSONObject {
        val deadline = SystemClock.elapsedRealtime() + 20_000
        while (true) {
            val record = client.getExecution(id)
            check(record.getString("state") == "running") { record.toString() }
            if (record.getString("stdout").contains(marker)) return record
            check(SystemClock.elapsedRealtime() < deadline) { "No $marker in $record" }
            SystemClock.sleep(25)
        }
    }
    fun checkStopped(id: String, state: String) {
        val record = client.waitFor(id, 25_000)
        check(record.getString("state") == state) { record.toString() }
        val result = record.getJSONObject("result")
        for (field in listOf("binder_death_confirmed", "output_drained", "stdin_feeder_completed", "broker_cleanup_confirmed")) {
            check(result.getBoolean(field)) { "$field missing in $record" }
        }
    }
    try {
        val main = project()
        val other = project()
        val assets = instrumentation.context.assets
        val files = JSONObject(assets.open("linux-rootfs/manifest.json").bufferedReader().use { it.readText() })
            .getJSONArray("files")
        for (index in 0 until files.length()) {
            val entry = files.getJSONObject(index)
            val path = entry.getString("path")
            if (path != "/usr/bin/node" && !path.startsWith("/lib/") && !path.startsWith("/usr/lib/aarch64-linux-gnu/")) continue
            client.makeDirectory(main, path.substringBeforeLast('/'))
            assets.open("linux-rootfs/" + entry.getString("asset")).use {
                client.importFile(main, path, it, entry.getLong("bytes"), entry.getString("sha256"),
                    executable = entry.getInt("mode") and 73 != 0)
            }
        }
        val env = listOf("LD_LIBRARY_PATH=/lib/aarch64-linux-gnu:/usr/lib/aarch64-linux-gnu", "SUCRUNE_MEMORY_POLICY=linux-jit")
        val server = """
            const server = require('http').createServer((req,res) => res.end('resident-ok'));
            server.listen(0,'127.0.0.1',() => console.log('PORT ' + server.address().port));
        """.trimIndent()
        val service = client.executePath(main, "/usr/bin/node", listOf("-e", server),
            env + "SUCRUNE_NETWORK_POLICY=loopback", resident = true).also { executions.add(it) }
        val ready = waitForOutput(service, "PORT ")
        val request = ready.getJSONObject("request")
        check(request.getBoolean("resident") && request.getLong("timeout_ms") == 0L)
        val port = ready.getString("stdout").trim().removePrefix("PORT ").toInt()
        val address = InetSocketAddress("127.0.0.1", port)
        fun requestPage() {
            Socket().use { socket ->
                socket.connect(address, 5_000)
                socket.soTimeout = 5_000
                socket.getOutputStream().write("GET / HTTP/1.0\r\nHost: localhost\r\nConnection: close\r\n\r\n".toByteArray(Charsets.US_ASCII))
                val page = socket.getInputStream().bufferedReader(Charsets.US_ASCII).readText()
                check(page.substringBefore("\r\n").contains(" 200 ") && page.substringAfter("\r\n\r\n") == "resident-ok") { page }
            }
        }
        requestPage()
        val firstResponseAt = SystemClock.elapsedRealtime()
        progress("A declared guest HTTP server answered on loopback")

        val resourceWork = """
            const fs = require('fs');
            const fds = Array.from({length:128}, () => fs.openSync('/usr/bin/node', 'r'));
            for (const fd of fds) fs.closeSync(fd);
            let uid = 0;
            for (let i=0; i<1000100; ++i) uid = process.getuid();
            if (!uid) throw Error('unexpected identity');
            console.log('resource-ok');
        """.trimIndent()
        val resources = client.executePath(main, "/usr/bin/node", listOf("-e", resourceWork), env).also { executions.add(it) }
        val record = client.waitFor(resources, 120_000)
        check(record.getString("state") == "exited" && record.getInt("exit_code") == 0 &&
            record.getString("stdout").trim() == "resource-ok") { record.toString() }
        check(record.getJSONObject("request").getLong("timeout_ms") == 1_800_000L)
        val native = record.getJSONObject("result").getJSONObject("native")
        val fds = native.getInt("fd_limit")
        val peak = native.getInt("fd_peak")
        val calls = native.getLong("syscalls")
        check(fds >= 1024 && peak >= 128 && calls > 1_000_000L) { native.toString() }
        progress("Same-project command finished with fd_limit=$fds, fd_peak=$peak, translated_syscalls=$calls")

        val short = client.executePath(main, "/usr/bin/node", listOf("-e", "setInterval(()=>{},60000)"),
            env, timeoutMs = 2_000L).also { executions.add(it) }
        checkStopped(short, "timed_out")
        val quietRemaining = firstResponseAt + 31_000 - SystemClock.elapsedRealtime()
        if (quietRemaining > 0) SystemClock.sleep(quietRemaining)
        requestPage()
        val serviceInterval = SystemClock.elapsedRealtime() - firstResponseAt
        val independent = client.executeProgram(other, "musl-smoke", listOf("sleep", "30")).also { executions.add(it) }
        waitForOutput(independent, "musl:sleep=start")
        val ordinary = client.executeProgram(main, "musl-smoke", listOf("sleep", "30")).also { executions.add(it) }
        waitForOutput(ordinary, "musl:sleep=start")
        check(client.deleteProject(main).getBoolean("deleted"))
        projects.remove(main)
        checkStopped(service, "cancelled")
        checkStopped(ordinary, "cancelled")
        val remaining = client.listEnvironments()
        check((0 until remaining.length()).none { remaining.getJSONObject(it).getString("id") == main })
        ServerSocket().use { released -> released.reuseAddress = true; released.bind(address) }
        check(client.getExecution(independent).getString("state") == "running")
        check(client.cancel(independent))
        checkStopped(independent, "cancelled")
        progress("Short command timed out, listener stayed reachable, deletion released the port and stopped only the deleted project's work")
        outcome.putString("stream", "PASS resident Linux lifecycle; HTTP interval=${serviceInterval}ms fd_limit=$fds fd_peak=$peak syscalls=$calls\n")
    } catch (failure: Throwable) {
        outcome.putString("stream", "FAIL resident Linux lifecycle: $failure\n")
        outcome.putInt("failed", 1)
    } finally {
        fun cleanupFailure(cleanup: Throwable) {
            outcome.putString("stream", outcome.getString("stream", "") + "FAIL test workspace cleanup: $cleanup\n")
            outcome.putInt("failed", 1)
        }
        for (id in executions) try {
            if (client.cancel(id)) client.waitFor(id, 25_000)
        } catch (cleanup: Throwable) { cleanupFailure(cleanup) }
        for (id in projects) try {
            client.deleteEnvironment(id)
        } catch (cleanup: Throwable) { cleanupFailure(cleanup) }
    }
    val failed = outcome.getInt("failed", 0)
    outcome.putInt("passed", if (failed == 0) 1 else 0)
    outcome.putInt("failed", failed)
    instrumentation.finish(if (failed == 0) Activity.RESULT_OK else Activity.RESULT_CANCELED, outcome)
}
