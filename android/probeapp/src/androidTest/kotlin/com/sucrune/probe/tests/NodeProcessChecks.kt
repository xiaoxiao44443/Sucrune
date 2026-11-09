package com.sucrune.probe.tests

import org.json.JSONObject

internal fun nodeProcessCases(runNode: (String) -> JSONObject): List<Pair<String, () -> String>> = listOf(
    "linux_node_spawn_debian_hello_with_pipes" to {
        val script = """
            const {spawn} = require('node:child_process');
            const child = spawn('/usr/bin/hello', ['--greeting=hello-from-real-child'], {
              stdio: ['pipe', 'pipe', 'pipe'], cwd: '/', env: {LC_ALL: 'C'}
            });
            child.stdin.end();
            let stdout = '', stderr = '', spawned = 0, exited = false;
            child.stdout.setEncoding('utf8').on('data', data => { stdout += data; });
            child.stderr.setEncoding('utf8').on('data', data => { stderr += data; });
            child.once('error', error => { console.error(error); process.exitCode = 71; });
            child.once('spawn', () => { spawned = child.pid; });
            child.once('exit', (code, signal) => { exited = code === 0 && signal === null; });
            child.once('close', (code, signal) => {
              if (!exited || spawned <= 0 || spawned === process.pid || code !== 0 || signal !== null ||
                  stdout !== 'hello-from-real-child\n' || stderr !== '') {
                console.error(JSON.stringify({spawned, exited, code, signal, stdout, stderr}));
                process.exitCode = 72;
              } else console.log('node-spawn-debian-hello-ok');
            });
        """.trimIndent()
        val record = runNode(script)
        val native = record.getJSONObject("result").getJSONObject("native")
        check(record.getString("stdout") == "node-spawn-debian-hello-ok\n" && record.getString("stderr").isEmpty() &&
            native.getInt("exit_code") == 0 && native.getBoolean("runner_waited")) { record.toString() }
        "Official Node observed spawn, exit and close from Debian GNU Hello and received its exact stdout over the guest pipe."
    }
)
