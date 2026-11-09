package com.sucrune.probe.tests

import android.content.res.AssetManager
import com.sucrune.probe.RuntimeClient
import org.json.JSONObject

internal fun linuxProcessCases(
    client: RuntimeClient,
    assets: AssetManager,
    envId: String,
    probeVfork: Boolean,
    execute: (String) -> JSONObject
): List<Pair<String, () -> String>> {
    fun importAndRun(name: String): JSONObject {
        val metadata = JSONObject(assets.open("linux-fixtures/$name.json").bufferedReader().use { it.readText() })
        val path = "/$name"
        assets.open("linux-fixtures/$name.elf").use { source ->
            client.importFile(envId, path, source, metadata.getLong("bytes"), metadata.getString("sha256"), executable = true)
        }
        return execute(path)
    }
    fun run(name: String, expected: String) {
        val record = importAndRun(name)
        val native = record.getJSONObject("result").getJSONObject("native")
        check(record.getString("stdout") == expected && record.getString("stderr").isEmpty()) { record.toString() }
        check(native.getInt("processes_created") == 1 && native.getInt("processes_waited") == 1 &&
            native.getInt("processes_cleanup_reaped") == 0 && native.getInt("processes_killed") == 0 &&
            native.getInt("processes_live") == 0 && native.getInt("exit_code") == 0 && native.getBoolean("runner_waited")) { record.toString() }
    }
    return listOfNotNull(
        if (probeVfork) "linux_guest_fork_vfork_semantics" to {
            val record = importAndRun("linux-vfork-semantics")
            val native = record.getJSONObject("result").getJSONObject("native")
            check(record.getString("stderr").isEmpty() && native.getInt("processes_live") == 0)
            check(record.getString("stdout") == "vfork-hello\nvfork-shared-exit-exec-ok\n" &&
                native.getInt("processes_created") == 3 && native.getInt("processes_waited") == 3) { record.toString() }
            "A sibling serviced a syscall during vfork. Shared writes, clear-TID on exit/exec, set_tid_address replacement, wait4 rusage and fork→vfork passed."
        } else null,
        "linux_guest_fork_continuation_and_wait" to {
            run("linux-fork-continuation", "fork-child\nfork-cow-tls-fpsimd-wait-ok\n")
            "ARM64 child resumed with inherited TLS, x18, FPSIMD and private memory. The parent collected exit 41."
        },
        "linux_guest_fork_unlinked_file_and_cwd" to {
            client.makeDirectory(envId, "/fork-cwd")
            run("linux-fork-broker", "fork-broker-ofd-ok\n")
            "The child changed its working directory and extended the unlinked file. Its parent retained / and read ABC from the shared open file description."
        },
        "linux_guest_fork_stop_continue_wait" to {
            run("linux-fork-wait-states", "fork-stop-continue-wait-ok\n")
            "The child stopped itself with SIGSTOP, its authorized parent continued it, waited each state once and collected exit 41"
        },
        "linux_guest_fork_exec_debian_hello" to {
            run("linux-fork-exec", "exec-original-glibc-ok\nfork-exec-wait-ok\n")
            "A missing executable returned ENOENT to the child. Its next exec loaded Debian GNU Hello and the glibc interpreter. The parent collected status zero."
        },
        "linux_guest_pselect6_mask_and_readiness" to {
            run("linux-pselect-smoke", "pselect-ready-timeout-mask-child-ok\n")
            "pselect6 counted read/write readiness separately, detected closed descriptors, slept with no FDs and restored its signal mask after a real child exit."
        }
    )
}
