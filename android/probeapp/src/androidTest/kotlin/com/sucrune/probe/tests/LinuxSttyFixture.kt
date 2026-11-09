package com.sucrune.probe.tests

import android.content.res.AssetManager
import com.sucrune.probe.RuntimeClient
import org.json.JSONObject

internal fun importLinuxSttyFixture(assets: AssetManager, client: RuntimeClient, project: String): Int {
    val wanted = setOf("/usr/bin/stty", "/usr/share/doc/coreutils/copyright", "/usr/share/common-licenses/GPL-3")
    val manifest = assets.open("linux-stty/manifest.json").bufferedReader().use { JSONObject(it.readText()) }
    check(manifest.getString("name") == "debian-bookworm-arm64-stty" && manifest.getString("version") == "9.1-1")
    val files = manifest.getJSONArray("files")
    val imported = mutableSetOf<String>()
    for (i in 0 until files.length()) {
        val item = files.getJSONObject(i)
        val path = item.getString("path")
        check(path in wanted && item.getString("asset") == "files$path" && imported.add(path))
        val executable = path == "/usr/bin/stty"
        check(item.getInt("mode") == if (executable) 493 else 420)
        client.makeDirectory(project, path.substringBeforeLast('/'))
        assets.open("linux-stty/files$path").use { stream ->
            val size = item.getLong("bytes")
            val result = client.importFile(project, path, stream, size, item.getString("sha256"), executable)
            check(result.getLong("size") == size)
        }
    }
    check(imported == wanted)
    return imported.size
}

/** Stock node-pty forks the real Bash, which runs the imported GNU utility
 * twice. The Bash program verifies both random input lines, and its parent
 * independently checks that only the second line was echoed by the terminal. */
internal fun checkOriginalSttyEcho(execute: (List<String>) -> JSONObject): String {
    val script = """
        'use strict';
        const assert = require('node:assert/strict');
        const { randomBytes } = require('node:crypto');
        const pty = require('/opt/dsh/node_modules/node-pty');
        const hidden = 'HIDDEN_' + randomBytes(12).toString('hex');
        const visible = 'VISIBLE_' + randomBytes(12).toString('hex');
        const bash = [
          '/usr/bin/stty -echo || exit 11',
          "printf 'STTY_DISABLED\\n'",
          'IFS= read -r input && [[ "${'$'}input" == "${'$'}1" ]] || exit 12',
          '/usr/bin/stty echo || exit 13',
          "printf 'STTY_ENABLED\\n'",
          'IFS= read -r input && [[ "${'$'}input" == "${'$'}2" ]] || exit 14',
          "printf 'STTY_VERIFIED\\n'"
        ].join('; ');
        const terminal = pty.spawn('/bin/bash', ['--noprofile', '--norc', '-c', bash, 'stty-test', hidden, visible], {
          cwd: '/', cols: 80, rows: 24, name: 'xterm-256color',
          env: { PATH: '/usr/bin:/bin', SHELL: '/bin/bash', LC_ALL: 'C', HOME: '/',
            LD_LIBRARY_PATH: '/lib/aarch64-linux-gnu:/usr/lib/aarch64-linux-gnu' }
        });
        let output = '', phase = 0;
        const timer = setTimeout(() => { process.exitCode = 1; terminal.kill('SIGKILL'); }, 12000);
        terminal.onData(data => {
          output += data;
          if (output.length > 8192) throw Error('stty capture limit');
          const lines = output.replace(/\r\n/g, '\n').split('\n');
          if (phase === 0 && lines.includes('STTY_DISABLED')) {
            phase = 1;
            terminal.write(hidden + '\r');
          }
          if (phase === 1 && lines.includes('STTY_ENABLED')) {
            phase = 2;
            terminal.write(visible + '\r');
          }
        });
        terminal.onExit(({exitCode, signal}) => {
          clearTimeout(timer);
          assert.equal(exitCode, 0);
          assert.ok(!signal);
          assert.equal(phase, 2);
          const lines = output.replace(/\r\n/g, '\n').split('\n');
          assert.ok(!output.includes(hidden));
          assert.ok(lines.includes(visible));
          assert.ok(lines.includes('STTY_VERIFIED'));
          console.log('ORIGINAL_STTY_ECHO_OFF_ON');
        });
    """.trimIndent()
    val result = execute(listOf("-e", script))
    check(result.getString("state") == "exited" && result.getInt("exit_code") == 0 &&
        result.getString("stdout") == "ORIGINAL_STTY_ECHO_OFF_ON\n" && result.getString("stderr").isEmpty()) {
        "Original Debian stty failed the PTY echo challenge"
    }
    return "ORIGINAL_STTY_ECHO_OFF_ON"
}
