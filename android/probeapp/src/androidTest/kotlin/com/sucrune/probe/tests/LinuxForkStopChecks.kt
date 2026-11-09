package com.sucrune.probe.tests

import android.content.res.AssetManager
import android.os.SystemClock
import com.sucrune.probe.RuntimeClient
import org.json.JSONObject

internal fun linuxForkStopCase(
    assets: AssetManager, client: RuntimeClient, envId: String,
    start: (String, List<String>) -> String, barriers: (JSONObject) -> Unit
): Pair<String, () -> String> = "linux_fork_cancel_session_lease" to {
    val name = "linux-fork-stop-lease"
    val path = "/$name"
    val metadata = assets.open("linux-fixtures/$name.json").bufferedReader().use { JSONObject(it.readText()) }
    assets.open("linux-fixtures/$name.elf").use {
        client.importFile(envId, path, it, metadata.getLong("bytes"), metadata.getString("sha256"), executable = true)
    }
    val id = start(path, emptyList())
    var childPid: Int? = null
    val limit = SystemClock.elapsedRealtime() + 12_000
    while (SystemClock.elapsedRealtime() < limit) {
        val execution = client.getExecution(id)
        check(execution.getString("state") == "running") { execution.toString() }
        val lines = execution.optString("stdout").lineSequence().toList()
        if ("PARENT_CLOSED_LEASE" in lines) {
            childPid = lines.singleOrNull { it.startsWith("SESSION_LEASE_PID=") }?.substringAfter('=')?.toIntOrNull()
            if (childPid != null && childPid > 0) break
        }
        SystemClock.sleep(25)
    }
    check(childPid != null && childPid > 0) { "Both lease markers were required before cancelling" }
    check(client.cancel(id))
    val stopped = client.waitFor(id, 15_000)
    check(stopped.getString("state") == "cancelled") { stopped.toString() }
    barriers(stopped)
    val native = stopped.getJSONObject("result").getJSONObject("native")
    check(native.getString("stage") == "runner_stopped" && native.getBoolean("stop_requested") &&
        native.getBoolean("runner_waited") && native.getInt("runner_signal") == 9 &&
        native.getBoolean("descendant_wait_complete") && native.getInt("descendants_reaped") == 1 &&
        native.getInt("last_reaped_descendant_pid") == childPid && native.getInt("runner_pid") != childPid) { native.toString() }
    val fresh = client.waitFor(start(path, listOf("verify-lease")), 15_000)
    check(fresh.getString("state") == "exited" && fresh.getInt("exit_code") == 0 &&
        fresh.getString("stdout") == "LEASE_REACQUIRED\n" && fresh.getString("stderr").isEmpty()) { fresh.toString() }
    barriers(fresh)
    "Wrapper reaped the recorded session leader, reached ECHILD, and the next execution reacquired its file lock"
}
