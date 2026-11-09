package com.sucrune.probe.tests

import android.content.res.AssetManager
import com.sucrune.probe.RuntimeClient
import org.json.JSONObject

/** Use includeAddon=false in projects that already have the complete original DSH SDK. */
internal fun importNodePtyFixture(
    assets: AssetManager, client: RuntimeClient, envId: String, includeAddon: Boolean = true
): Int {
    val manifest = assets.open("linux-node-pty/manifest.json").bufferedReader().use { JSONObject(it.readText()) }
    check(manifest.getString("name") == "linux-arm64-node-pty" && manifest.getString("version") == "1.2.0-beta.15")
    val files = manifest.getJSONArray("files")
    var imported = 0
    for (i in 0 until files.length()) {
        val item = files.getJSONObject(i)
        val file = item.getString("path")
        if (file != "/lib/aarch64-linux-gnu/libutil.so.1") {
            check(file.startsWith("/opt/dsh/node_modules/node-pty/"))
            if (!includeAddon) continue
        }
        check(file.drop(1).split('/').none { it.isEmpty() || it == "." || it == ".." })
        check(item.getString("asset") == "files$file" && item.getInt("mode") == 420)
        client.makeDirectory(envId, file.substringBeforeLast('/'))
        assets.open("linux-node-pty/files$file").use { stream ->
            val bytes = item.getLong("bytes")
            check(client.importFile(envId, file, stream, bytes, item.getString("sha256")).getLong("size") == bytes)
        }
        imported++
    }
    check(imported == if (includeAddon) 9 else 1)
    return imported
}

internal fun nodePtyWorkflowCases(execute: (List<String>) -> JSONObject): List<Pair<String, () -> String>> {
    fun checkNode(script: String, expected: String): String {
        val record = execute(listOf("-e", script.trimIndent()))
        check(record.getString("state") == "exited" && record.getInt("exit_code") == 0) { record.toString() }
        check(record.getString("stdout") == "$expected\n" && record.getString("stderr").isEmpty()) { record.toString() }
        return expected
    }
    return listOf(
        "linux_node_pty_load" to {
            checkNode("""
                'use strict';
                const assert = require('node:assert/strict');
                const base = '/opt/dsh/node_modules/node-pty';
                assert.equal(process.platform, 'linux');
                assert.equal(process.arch, 'arm64');
                assert.equal(process.version, 'v24.22.2');
                assert.equal(require(base + '/package.json').version, '1.2.0-beta.15');
                const addon = require(base + '/prebuilds/linux-arm64/pty.node');
                assert.equal(require(base).native, addon);
                assert.throws(() => addon.open(), /Usage: pty\.open/);
                console.log('ORIGINAL_PTY_LOADED');
            """, "ORIGINAL_PTY_LOADED")
        },
        "linux_node_pty_open" to {
            checkNode("""
                'use strict';
                const assert = require('node:assert/strict');
                const fs = require('node:fs'), tty = require('node:tty');
                const addon = require('/opt/dsh/node_modules/node-pty').native;
                const pause = () => new Promise(resolve => setTimeout(resolve, 5));
                async function readLine(fd) {
                  const buf = Buffer.alloc(128), end = performance.now() + 4000;
                  let value = '';
                  while (performance.now() < end && value.length < 512) {
                    try { value += buf.toString('utf8', 0, fs.readSync(fd, buf, 0, buf.length, null)); }
                    catch (e) { if (e.code !== 'EAGAIN' && e.code !== 'EINTR') throw e; }
                    if (value.includes('\n')) return value.replace(/\r\n/g, '\n');
                    await pause();
                  }
                  throw Error('PTY line deadline or size exceeded');
                }
                async function main() {
                  const pair = addon.open(80, 24);
                  let writer;
                  try {
                    assert.match(pair.pty, /^\/dev\/pts\/\d+$/);
                    assert.notEqual(pair.master, pair.slave);
                    for (const fd of [pair.master, pair.slave]) {
                      assert.ok(tty.isatty(fd) && fs.fstatSync(fd).isCharacterDevice());
                    }
                    assert.equal(fs.writeSync(pair.slave, 'FROM_SLAVE\n'), 11);
                    assert.equal(await readLine(pair.master), 'FROM_SLAVE\n');
                    assert.equal(fs.writeSync(pair.master, 'FROM_MASTER\n'), 12);
                    assert.equal(await readLine(pair.slave), 'FROM_MASTER\n');
                    addon.resize(pair.master, 103, 39, 0, 0);
                    writer = new tty.WriteStream(pair.master);
                    assert.deepEqual(writer.getWindowSize(), [103, 39]);
                  } finally {
                    fs.closeSync(pair.slave);
                    if (writer) writer.destroy();
                    else fs.closeSync(pair.master);
                  }
                  console.log('ORIGINAL_PTY_PAIR_OK');
                }
                main().catch(e => { console.error(e); process.exitCode = 1; });
            """, "ORIGINAL_PTY_PAIR_OK")
        },
        "linux_node_pty_bash" to {
            checkNode("""
                'use strict';
                const assert = require('node:assert/strict');
                const pty = require('/opt/dsh/node_modules/node-pty');
                const term = pty.spawn('/bin/bash', ['--noprofile', '--norc', '-i'], {
                  name: 'xterm-256color', cols: 80, rows: 24, cwd: '/',
                  env: { PATH: '/bin:/usr/bin', HOME: '/', LANG: 'C', LC_ALL: 'C',
                         LD_LIBRARY_PATH: '/lib/aarch64-linux-gnu:/usr/lib/aarch64-linux-gnu', PS1: 'SUCRUNE_PTY_READY> ', HISTFILE: '/dev/null' }
                });
                assert.ok(Number.isInteger(term.pid) && term.pid > 0 && term.pid !== process.pid);
                let out = '', sentFirst = false, sentSecond = false;
                const timer = setTimeout(() => { console.error('Bash PTY dialogue timed out'); process.exitCode = 1; term.kill('SIGKILL'); }, 9000);
                term.onData(data => {
                  out += data;
                  if (out.length > 32768) throw Error('Unexpected PTY output volume');
                  if (!sentFirst && out.includes('SUCRUNE_PTY_READY> ')) {
                    sentFirst = true;
                    term.write('n=41; [[ -t 0 && -t 1 && -t 2 ]] && printf "\\nPTY_%s=%d\\n" FIRST "${'$'}((6*7))"\r');
                  }
                  if (!sentSecond && /(?:^|\n)PTY_FIRST=42\r?\n/.test(out)) {
                    sentSecond = true;
                    term.resize(103, 39);
                    term.write('printf "\\nPTY_%s=%d:%d\\n" SECOND "${'$'}((n+1))" "${'$'}BASHPID"; exit 7\r');
                  }
                });
                term.onExit(({exitCode, signal}) => {
                  clearTimeout(timer);
                  assert.equal(exitCode, 7, out);
                  assert.ok(!signal, String(signal));
                  assert.ok(sentFirst, out);
                  assert.ok(sentSecond);
                  assert.ok(out.replace(/\r\n/g, '\n').split('\n').includes('PTY_SECOND=42:' + term.pid), out);
                  console.log('ORIGINAL_PTY_BASH_TWO_ROUNDS');
                });
            """, "ORIGINAL_PTY_BASH_TWO_ROUNDS")
        }
    )
}
