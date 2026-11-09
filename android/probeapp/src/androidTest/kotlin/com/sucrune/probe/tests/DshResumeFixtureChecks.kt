package com.sucrune.probe.tests

import android.os.SystemClock
import com.sucrune.probe.RuntimeClient
import com.sucrune.probe.RuntimeExceptionWithCode
import org.json.JSONObject
import java.util.UUID

/** Two original SDK processes recover a real JSONL header and session cwd.
 * Only metadata RPCs are sent. The supplied launcher tracks each execution,
 * uses Linux JIT and has no network or credential environment. */
internal fun checkDshSessionResume(client: RuntimeClient, project: String,
    startInteractive: (String, List<String>, Long, String, List<String>) -> String): String {
    val suffix = UUID.randomUUID().toString().replace("-", "")
    val root = "/workspace/dsh-restore-$suffix"
    val original = "$root/first"
    val selected = "$original/selected"
    val next = "$root/second"
    val home = "$root/home/.dsh"
    val session = "restore-$suffix"
    val env = listOf("HOME=$root/home", "DSH_HOME=$home", "TMPDIR=$root/tmp", "NARB_NATIVE_CACHE_DIR=$root/cache",
        "DSH_TELEMETRY_DISABLED=1", "PATH=/usr/bin:/bin", "SHELL=/bin/bash")
    listOf(selected, next, home, "$root/tmp", "$root/cache").forEach { client.makeDirectory(project, it) }
    var previousPid = -1
    fun launch(cwd: String, restore: Boolean) {
        val id = startInteractive(project, listOf("/opt/dsh/node_modules/@deepseek-ai/dsh/lib/bin.js", "--profile",
            "sdk-minimal"), 75_000L, cwd, env)
        val deadline = SystemClock.elapsedRealtime() + 70_000
        var cursor = 0
        var number = 0
        val identity = JSONObject().put("sessionId", session)
        fun request(method: String, params: JSONObject): JSONObject {
            val packet = JSONObject().put("jsonrpc", "2.0").put("id", ++number).put("method", method).put("params", params)
            val bytes = (packet.toString() + "\n").toByteArray(Charsets.UTF_8)
            check(client.writeInput(id, bytes) == bytes.size)
            while (SystemClock.elapsedRealtime() < deadline) {
                val record = client.getExecution(id)
                check(!record.optBoolean("truncated")) { "Offline restore RPC output exceeded its bound" }
                val stdout = record.getString("stdout")
                while (true) {
                    val end = stdout.indexOf('\n', cursor)
                    if (end < 0) break
                    val frame = JSONObject(stdout.substring(cursor, end))
                    cursor = end + 1
                    check(frame.getString("jsonrpc") == "2.0")
                    if (!frame.has("id")) {
                        check(frame.getString("method") in setOf("session.event", "session.status"))
                        val note = frame.getJSONObject("params")
                        check(note.getString("sessionId") == session)
                        if (frame.getString("method") == "session.event") {
                            check(note.getJSONObject("event").getString("type") !in setOf("turn/start", "assistant/message", "tool/call"))
                        }
                        continue
                    }
                    check(!frame.has("method") && frame.getInt("id") == number)
                    if (frame.has("error")) {
                        val error = frame.getJSONObject("error")
                        val message = error.optString("message")
                        val category = listOf("ftruncate", "truncate", "flock", "ENOENT", "permission", "generation",
                            "unavailable", "corrupt", "lock", "not found").firstOrNull { message.contains(it, true) } ?: "other"
                        throw IllegalStateException("Offline $method error code=${error.optInt("code")} category=$category")
                    }
                    return frame.getJSONObject("result")
                }
                check(record.getString("state") == "running") { "Offline SDK exited before $method reply" }
                SystemClock.sleep(20)
            }
            error("Offline $method reached deadline")
        }
        try {
            val info = request("initialize", JSONObject().put("cwd", cwd).put("provider", "deepseek-official")
                .put("model", "deepseek-flash")).getJSONObject("serverInfo")
            check(info.getString("name") == "deepseek-harness-sdk-runtime" && info.getString("version") == "0.0.1")
            fun select(path: String) {
                check(request("session/working-directory/set", JSONObject().put("sessionId", session)
                    .put("path", path)).getString("cwd") == path)
            }
            if (restore) check(request("session/resume", identity).length() == 0)
            else {
                check(request("session/working-directory/get", identity).getString("cwd") == original)
                // DSH commits working-directory/change. Its informational inject uses
                // send(..., wakeup=false), so the idle model loop stays asleep.
                repeat(6) { select(selected); select(original) }
                select(selected)
            }
            check(request("session/working-directory/get", identity).getString("cwd") == selected)
            if (restore) select(next)
            check(request("shutdown", JSONObject()).length() == 0)
            val record = client.waitFor(id, (deadline - SystemClock.elapsedRealtime()).coerceAtLeast(0))
            check(record.getString("state") == "exited" && record.getInt("exit_code") == 0)
            val result = record.getJSONObject("result")
            check(result.getBoolean("binder_death_confirmed") && result.getBoolean("output_drained") &&
                result.getBoolean("broker_cleanup_confirmed") && result.getBoolean("stdin_feeder_completed"))
            val pid = result.getJSONObject("native").getInt("runner_pid")
            check(pid > 0 && pid != previousPid)
            previousPid = pid
        } finally {
            try { client.closeInput(id) } catch (e: RuntimeExceptionWithCode) {
                if (e.code != "not_found") throw e
            } finally {
                if (client.getExecution(id).getString("state") == "running") {
                    client.cancel(id)
                    check(client.waitFor(id, 10_000L).getString("state") != "running")
                }
            }
        }
    }
    launch(original, restore = false)
    val directory = "$home/sessions/--workspace-dsh-restore-$suffix-first--/$session"
    val entries = client.listFiles(project, directory).getJSONArray("entries")
    val file = (0 until entries.length()).map { entries.getJSONObject(it) }.single {
        it.optString("kind") == "file" && it.optString("name").matches(Regex("session(?:\\.v[1-9][0-9]*)?\\.jsonl"))
    }.getString("name")
    val path = "$directory/$file"
    val before = client.readFile(project, path)
    check(before.size > 4096 && before.last() == 10.toByte() && before.toString(Charsets.UTF_8).let {
        it.contains(session) && it.contains("working-directory/change") && it.contains(selected)
    })
    launch(next, restore = true)
    val after = client.readFile(project, path)
    check(after.size > before.size && before.indices.all { before[it] == after[it] } && after.last() == 10.toByte())
    val appended = String(after, before.size, after.size - before.size, Charsets.UTF_8)
    check(appended.lineSequence().filter { it.isNotEmpty() }.map(::JSONObject).any {
        it.optString("type") == "working-directory/change" && it.optJSONObject("data")?.optString("cwd") == next
    })
    return "Two original SDK runners restored the selected cwd and appended to a ${before.size}-byte JSONL without changing its prefix"
}
