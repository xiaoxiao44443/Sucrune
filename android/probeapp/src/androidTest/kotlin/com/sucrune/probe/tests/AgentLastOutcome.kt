package com.sucrune.probe.tests

import android.app.Activity
import android.app.Instrumentation
import android.content.Context
import android.os.Bundle
import com.sucrune.probe.RuntimeClient
import org.json.JSONArray
import org.json.JSONObject
import java.io.File
import java.nio.file.Files

/** Retrospective diagnostics for this specific fixture, even if the host's instrumentation stream
 * was interrupted. No path, frame, exception, model text, tool argument or arbitrary string value
 * is allowed into the result. This probe never opens a credential source or launches a guest. */
internal fun agentLastOutcome(instrumentation: Instrumentation, context: Context) {
    val result = Bundle()
    try {
        val client = RuntimeClient.get(context)
        val recent = File(context.filesDir, "sucrune/executions").listFiles().orEmpty()
            .filter { it.name.matches(Regex("exec_[0-9a-f]{32}")) && !Files.isSymbolicLink(it.toPath()) && it.isDirectory }
            .sortedByDescending { it.lastModified() }.take(80)
        val samples = JSONArray()
        val terminalChecks = JSONArray()
        for (dir in recent) {
            val r = client.getExecution(dir.name)
            val request = r.optJSONObject("request") ?: continue
            if (terminalChecks.length() < 2 && request.optString("path") == "/usr/bin/node" &&
                request.optString("cwd") == "/workspace/terminal-check" && !request.has("secret_env_names")) {
                val lines = r.optString("stdout").lineSequence().filter { it.startsWith("SUC_BASH ") }
                    .map { it.removePrefix("SUC_BASH ") }.take(16)
                val phases = listOf("setup","registered","first","second","dispose","pass","error_proc","error_module",
                    "error_addon","error_assert","error_other")
                terminalChecks.put(JSONArray(lines.map { if (it in phases) it else "other" }.toList()))
            }
            if (request.optString("path") != "/usr/bin/node" ||
                !request.optString("cwd").matches(Regex("/workspace/dsh-agent-[0-9a-f]{32}/work")) ||
                request.optJSONArray("argv")?.optString(0) != "/opt/dsh/node_modules/@deepseek-ai/dsh/lib/bin.js" ||
                request.optJSONArray("secret_env_names")?.optString(0) != "DEEPSEEK_API_KEY") continue
            val out = JSONObject()
            fun known(s: String, values: String): String = values.split(' ').firstOrNull { it == s } ?: "other"
            val stdout = r.optString("stdout")
            val stderr = r.optString("stderr")
            out.put("state", known(r.optString("state"), "running exited lost timed_out cancelled"))
            out.put("truncated", r.optBoolean("truncated"))
            val rows = JSONArray()
            for (line in stdout.lineSequence().filter { it.isNotBlank() }.take(180)) {
                val f = try { JSONObject(line) } catch (_: Exception) { rows.put("invalid_frame"); continue }
                val p = f.optJSONObject("params")
                val event = p?.optJSONObject("event")
                val data = event?.optJSONObject("data")
                val type = event?.optString("type")
                val flags = when {
                    f.has("error") -> "rpc_error"
                    f.has("result") -> "rpc_result"
                    f.optString("method") == "session.status" -> "status_" + known(p?.optString("status").orEmpty(), "running idle")
                    type == "turn/end" -> {
                        val reason = data?.optJSONObject("reason")
                        val err = reason?.optJSONObject("error")
                        out.put("provider_code", known(err?.optString("code").orEmpty(),
                            "AUTH QUOTA RATE_LIMIT SERVER TRANSPORT MISSING_CREDENTIAL INVALID_CREDENTIAL INVALID_REQUEST EMPTY_RESPONSE UNKNOWN"))
                        val http = err?.optInt("status", -1) ?: -1
                        if (http in 400..599) out.put("provider_http_status", http)
                        "end_" + known(reason?.optString("kind").orEmpty(), "completed aborted blocked error max-tokens interrupted forked")
                    }
                    type == "tool/call" -> "call_" + known(data?.optString("name").orEmpty(), "write read bash")
                    type == "tool/result" -> if (data?.optJSONObject("message")?.optBoolean("isError") == true) "tool_failed" else "tool_result"
                    else -> known(type.orEmpty(), "turn/start user/message assistant/message session/header")
                }
                rows.put(flags)
            }
            out.put("frames", rows)
            val markers = JSONArray()
            for (m in listOf("EACCES", "ENOSYS", "ENOTSUP", "ENOENT", "ECONNRESET", "ENOTFOUND", "ECONNREFUSED",
                    "ERR_DLOPEN_FAILED", "MODULE_NOT_FOUND", "startup failed", "fatal uncaught exception", "FATAL ERROR",
                    "unable to verify", "certificate", "fetch failed", "getaddrinfo", "did not activate"))
                if (stderr.contains(m, ignoreCase = true) || stdout.contains(m, ignoreCase = true)) markers.put(m)
            out.put("known_markers", markers)
            val operations = JSONArray()
            for (op in listOf("link", "unlink", "lstat", "stat", "statfs", "fchmod", "chmod", "mkdir", "rename",
                    "open", "fsync", "fdatasync", "ftruncate", "readlink", "realpath", "getaddrinfo", "getifaddrs",
                    "uv_interface_addresses", "uv_os_get_passwd", "uv_get_available_parallelism", "uv_os_uname",
                    "uv_resident_set_memory", "uv_getrusage", "uv_get_free_memory", "setsockopt", "sendmsg", "connect")) {
                val mentions = listOf("implemented, $op", "\"syscall\":\"$op\"", "syscall: '$op'", "at $op (", "syscall $op",
                    "uv_$op")
                if (mentions.any { stdout.contains(it) || stderr.contains(it) }) operations.put(op)
            }
            out.put("known_operations", operations)
            val native = r.optJSONObject("result")?.optJSONObject("native")
            val last = native?.optInt("last_unsupported_syscall", -1) ?: -1
            if (last in 0..1024) out.put("native_last_unsupported", last)
            samples.put(out)
            if (samples.length() == 3) break
        }
        result.putString("agent_fixture_outcomes", samples.toString())
        result.putString("offline_terminal_phases", terminalChecks.toString())
        instrumentation.finish(Activity.RESULT_OK, result)
    } catch (_: Exception) {
        result.putString("agent_fixture_outcome_error", "record_unavailable")
        instrumentation.finish(Activity.RESULT_CANCELED, result)
    }
}
