package com.sucrune.probe.tests

import org.json.JSONObject

/** Sample the kernel's actual session and foreground group while the child
 * reads the PTY, then again in the interactive shell after stty has exited. */
internal fun checkOriginalPtyJobControl(execute: (List<String>) -> JSONObject): String {
    val script = """
        'use strict';
        const assert = require('node:assert/strict');
        const pty = require('/opt/dsh/node_modules/node-pty');
        const prompt = 'JC_READY> ';
        const terminal = pty.spawn('/bin/bash', ['--noprofile', '--norc', '-i'], {
          name: 'dumb', cols: 93, rows: 31, cwd: '/',
          env: { TERM: 'dumb', PS1: prompt, HISTFILE: '/dev/null', LC_ALL: 'C',
                 HOME: '/', PATH: '/bin:/usr/bin', LD_LIBRARY_PATH: '/lib/aarch64-linux-gnu:/usr/lib/aarch64-linux-gnu' }
        });
        const fields = 'read -r pid comm state ppid pgid sid tty fg rest < /proc/self/stat';
        const child = fields + '; printf "\\nJC_CHILD %d %d %d %d %d %d\\n" "${'$'}BASHPID" "${'$'}pid" "${'$'}pgid" "${'$'}sid" "${'$'}tty" "${'$'}fg"; ' +
          'IFS= read -r word && [[ "${'$'}word" == JC_CONTINUE ]] || exit 19';
        let output = '', phase = 0;
        const watchdog = setTimeout(() => {
          console.error('job-control timeout phase=' + phase); process.exitCode = 1; terminal.kill('SIGKILL');
        }, 15000);
        terminal.onData(chunk => {
          output += chunk;
          if (output.length > 16384) throw Error('job-control capture limit');
          const text = output.replace(/\r\n/g, '\n');
          if (phase === 0 && text.includes(prompt)) {
            phase = 1; output = '';
            terminal.write("[[ ${'$'}- == *m* ]] || exit 17; /bin/bash --noprofile --norc -c '" + child + "' || exit 18\r");
          } else if (phase === 1) {
            const m = text.match(/^JC_CHILD (\d+) (\d+) (\d+) (\d+) (-?\d+) (\d+)\n/m);
            if (!m) return;
            const [pid, statPid, group, session, tty, foreground] = m.slice(1).map(Number);
            assert.ok(pid > 0 && pid !== terminal.pid);
            assert.equal(statPid, pid); assert.equal(group, pid); assert.equal(foreground, group);
            assert.equal(session, terminal.pid); assert.notEqual(tty, 0);
            phase = 2; output = ''; terminal.write('JC_CONTINUE\r');
          } else if (phase === 2 && text.includes(prompt)) {
            phase = 3; output = '';
            terminal.write('/usr/bin/stty size || exit 20; ' + fields +
              '; printf "\\nJC_PARENT %d %d %d %d %d\\n" "${'$'}BASHPID" "${'$'}pid" "${'$'}pgid" "${'$'}sid" "${'$'}fg"\r');
          } else if (phase === 3) {
            const m = text.match(/^JC_PARENT (\d+) (\d+) (\d+) (\d+) (\d+)\n/m);
            if (!m || !text.includes(prompt)) return;
            assert.match(text, /(?:^|\n)31 93\n/);
            for (const value of m.slice(1)) assert.equal(Number(value), terminal.pid);
            phase = 4; output = '';
            terminal.write('printf "\\nJC_NEXT=%d\\n" "${'$'}((6*7))"; exit 7\r');
          }
        });
        terminal.onExit(({exitCode, signal}) => {
          clearTimeout(watchdog);
          assert.equal(phase, 4); assert.equal(exitCode, 7); assert.ok(!signal);
          assert.match(output.replace(/\r\n/g, '\n'), /^JC_NEXT=42$/m);
          console.log('ORIGINAL_PTY_BASH_JOB_CONTROL');
        });
    """.trimIndent()
    val record = execute(listOf("-e", script))
    check(record.getString("state") == "exited" && record.getInt("exit_code") == 0 &&
        record.getString("stdout") == "ORIGINAL_PTY_BASH_JOB_CONTROL\n" && record.getString("stderr").isEmpty()) {
        "Original Bash job control failed: " + record.getString("state") + ", " + record.opt("exit_code") +
            ", " + record.optString("stderr").take(1024)
    }
    return "Original Bash handed the PTY to its child, ran GNU stty, regained the foreground and accepted a new command"
}
