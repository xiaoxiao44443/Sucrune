package com.sucrune.probe.tests

import android.app.Activity
import android.app.Instrumentation
import android.content.Context
import android.content.pm.ApplicationInfo
import android.os.Bundle
import android.os.Process
import android.os.SystemClock
import android.util.AtomicFile
import com.sucrune.probe.RuntimeClient
import org.json.JSONObject
import java.io.File
import java.util.UUID

/** Requires a real external app force-stop/restart between prepare and verify. */
internal class RuntimeRecoveryChecks(private val instrumentation: Instrumentation,
                                     private val context: Context, private val arguments: Bundle) {
    private val receiptFile = AtomicFile(File(context.filesDir, "runtime-recovery.json"))

    fun run() {
        var passed = false
        var detail = ""
        val phase = arguments.getString("phase") ?: ""
        try {
            val expected = when (val value = arguments.getString("expect_debuggable")) {
                null -> null
                "true" -> true
                "false" -> false
                else -> error("expect_debuggable must be true or false: $value")
            }
            val actual = context.applicationInfo.flags and ApplicationInfo.FLAG_DEBUGGABLE != 0
            expected?.let { check(it == actual) { "Target APK debuggable=$actual, expected $it" } }
            check(Process.myUid() == context.applicationInfo.uid && Process.myUid() != 0)
            detail = when (phase) {
                "prepare" -> prepare()
                "verify" -> verify()
                else -> error("runtime_recovery requires -e phase prepare or -e phase verify")
            }
            passed = true
        } catch (failure: Throwable) { detail = failure.toString() }
        instrumentation.sendStatus(if (passed) 0 else -2, Bundle().apply {
            putString("id", "SucruneRuntimeRecovery"); putString("test", "recovery_$phase")
            putString("class", RuntimeRecoveryChecks::class.java.name)
            putInt("current", 1); putInt("numtests", 1)
            putString("stream", "\nrecovery_$phase: ${if (passed) "PASS" else "FAIL"} $detail\n")
        })
        instrumentation.finish(if (passed) Activity.RESULT_OK else Activity.RESULT_CANCELED, Bundle().apply {
            putInt("passed", if (passed) 1 else 0); putInt("failed", if (passed) 0 else 1)
            putInt("expected_tests", 1); putString("probe", "runtime_recovery"); putString("phase", phase)
            putString("stream", "\n$detail\n")
        })
    }

    private fun prepare(): String {
        check(!receiptFile.baseFile.exists()) { "A recovery receipt already exists; verify that attempt first" }
        val client = RuntimeClient.get(context)
        val token = UUID.randomUUID().toString()
        val name = "recovery-🍬-${token.take(8)}"
        val env = client.createEnvironment(name).getString("id")
        var execution: String? = null
        var committed = false
        try {
            val path = "persisted-🍬.txt"
            val content = "Sucrune persisted 🍬\n$token\n"
            client.writeFile(env, path, content.toByteArray(Charsets.UTF_8))
            execution = client.execute(env, "echo ready; sleep 30", "/", 60_000)
            val deadline = SystemClock.elapsedRealtime() + 10_000
            var live: JSONObject
            while (true) {
                live = client.getExecution(execution)
                check(live.getString("state") == "running") { "Execution ended before prepare checkpoint: $live" }
                if (live.getString("stdout").contains("ready\n")) break
                check(SystemClock.elapsedRealtime() < deadline) { "Guest never reached recovery checkpoint: $live" }
                SystemClock.sleep(25)
            }
            val worker = live.getJSONObject("runtime").getJSONObject("worker")
            check(worker.getInt("uid") != Process.myUid() && worker.getInt("uid") != 0)
            check(worker.getInt("pid") != Process.myPid())
            val receipt = JSONObject().put("schema_version", 1).put("env_id", env)
                .put("execution_id", execution).put("manager_pid", Process.myPid())
                .put("worker_pid", worker.getInt("pid")).put("worker_uid", worker.getInt("uid"))
                .put("environment_name", name).put("path", path).put("content", content)
            val stream = receiptFile.startWrite()
            try {
                stream.write(receipt.toString().toByteArray(Charsets.UTF_8))
                receiptFile.finishWrite(stream)
            } catch (failure: Throwable) { receiptFile.failWrite(stream); throw failure }
            committed = true
            check(client.getExecution(execution).getString("state") == "running")
            return "Prepared real running execution; externally force-stop the app before verify. $receipt"
        } finally {
            // A successful prepare intentionally leaves the live execution for
            // the external stop. It never fakes a manager restart in this JVM.
            if (!committed) {
                execution?.let {
                    client.cancel(it)
                    client.waitFor(it, 10_000)
                }
                client.deleteEnvironment(env)
            }
        }
    }

    private fun verify(): String {
        val receipt = JSONObject(String(receiptFile.readFully(), Charsets.UTF_8))
        check(receipt.getInt("schema_version") == 1)
        val oldPid = receipt.getInt("manager_pid")
        check(oldPid != Process.myPid()) { "Manager PID is unchanged; external restart was not established" }
        val client = RuntimeClient.get(context)
        val envId = receipt.getString("env_id")
        val executionId = receipt.getString("execution_id")
        val record = client.getExecution(executionId)
        check(record.getString("env_id") == envId && record.getString("execution_id") == executionId)
        check(record.getString("state") == "lost") { "Previous running process must recover as lost: $record" }
        check(!record.has("exit_code")) { "A lost process must not invent an exit code" }
        val result = record.getJSONObject("result")
        check(result.getString("reason") == "manager_restarted")
        check(!result.getBoolean("process_resumed"))
        val request = record.getJSONObject("request")
        check(request.getString("script") == "echo ready; sleep 30")
        check(request.getString("cwd") == "/" && request.getLong("timeout_ms") == 60_000L)
        check(client.getEnvironment(envId).getString("name") == receipt.getString("environment_name"))
        check(client.readFile(envId, receipt.getString("path")).toString(Charsets.UTF_8) == receipt.getString("content"))
        val rerun = client.execute(envId, "cat 'persisted-🍬.txt'", "/", 20_000)
        val completed = client.waitFor(rerun, 25_000)
        check(completed.getString("state") == "exited" && completed.getInt("exit_code") == 0) { completed.toString() }
        check(completed.getString("stdout") == receipt.getString("content"))
        check(completed.getJSONObject("result").getBoolean("binder_death_confirmed"))
        check(completed.getJSONObject("result").getBoolean("broker_cleanup_confirmed"))
        client.deleteEnvironment(envId)
        receiptFile.delete()
        return "Manager PID $oldPid -> ${Process.myPid()}; old execution is lost/manager_restarted, Unicode file persisted, project executes again. Test environment and receipt removed."
    }
}
