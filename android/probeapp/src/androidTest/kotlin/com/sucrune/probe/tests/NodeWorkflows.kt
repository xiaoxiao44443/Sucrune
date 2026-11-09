package com.sucrune.probe.tests

import com.sucrune.probe.RuntimeClient
import org.json.JSONObject

/** Real guest Node programs. The caller owns execution cleanup and deletes envId. */
internal fun nodeWorkflowCases(client: RuntimeClient, envId: String,
                              execute: (List<String>) -> JSONObject): List<Pair<String, () -> String>> {
    val root = "/node-workflows"
    fun write(directory: String, name: String, source: String): String {
        val directoryPath = "$root/$directory"
        client.makeDirectory(envId, directoryPath)
        val path = "$directoryPath/$name"
        client.writeFile(envId, path, source.trimIndent().toByteArray(Charsets.UTF_8))
        return path
    }
    fun checked(record: JSONObject): JSONObject {
        check(record.getString("state") == "exited" && record.getInt("exit_code") == 0) { record.toString() }
        check(record.getJSONObject("result").getJSONObject("native").getString("memory_policy") == "linux-jit") { record.toString() }
        check(record.getString("stderr").isEmpty()) { record.toString() }
        return record
    }
    fun output(record: JSONObject): JSONObject = JSONObject(checked(record).getString("stdout").trim())
    fun run(directory: String, source: String): JSONObject =
        output(execute(listOf(write(directory, "main.cjs", source))))

    return listOf(
        "linux_node_fs_workflow" to {
            val result = run("fs", """
                'use strict';
                const assert = require('node:assert/strict');
                const fs = require('node:fs');
                const fsp = require('node:fs/promises');
                const path = require('node:path');
                const text = 'Sucrune 文件🙂\n';
                const source = path.join(__dirname, 'sync.tmp');
                const renamed = path.join(__dirname, 'sync.txt');
                fs.writeFileSync(source, text, 'utf8');
                assert.equal(fs.readFileSync(source, 'utf8'), text);
                fs.renameSync(source, renamed);
                const syncStat = fs.statSync(renamed);
                assert.ok(syncStat.isFile());
                assert.equal(syncStat.size, Buffer.byteLength(text));
                assert.throws(() => fs.statSync(source), { code: 'ENOENT' });
                fs.accessSync(renamed, fs.constants.R_OK | fs.constants.W_OK);
                assert.throws(() => fs.accessSync(renamed, fs.constants.X_OK), { code: 'EACCES' });
                assert.throws(() => fs.accessSync(source), { code: 'ENOENT' });
                assert.equal(fs.readlinkSync('/proc/self/exe'), '/usr/bin/node');
                assert.equal(process.execPath, '/usr/bin/node');
                assert.throws(() => fs.readlinkSync(renamed), { code: 'EINVAL' });
                assert.throws(() => fs.readlinkSync(source), { code: 'ENOENT' });
                // The original DSH history writer publishes a completed temporary
                // file with link(tmp, final) and removes tmp afterwards.
                const tmp = path.join(__dirname, 'history.tmp'), finalName = path.join(__dirname, 'history.jsonl');
                const other = path.join(__dirname, 'another.tmp'), denied = path.join(__dirname, 'denied.link');
                fs.writeFileSync(tmp, 'first\n', {flag:'wx'});
                fs.writeFileSync(other, 'second\n', {flag:'wx'});
                fs.linkSync(tmp, finalName);
                const original = fs.statSync(tmp, {bigint:true}), published = fs.statSync(finalName, {bigint:true});
                assert.equal(original.dev, published.dev); assert.equal(original.ino, published.ino);
                assert.equal(original.nlink, 2n); assert.equal(published.nlink, 2n);
                const edit = fs.openSync(tmp, 'r+'), readOnly = fs.openSync(finalName, 'r');
                try {
                  const prefix = Buffer.alloc(5);
                  assert.equal(fs.readSync(edit, prefix, 0, 5, null), 5);
                  assert.equal(prefix.toString(), 'first');
                  fs.ftruncateSync(edit, 2);
                  assert.equal(fs.fstatSync(readOnly).size, 2);
                  assert.equal(fs.readFileSync(finalName, 'utf8'), 'fi');
                  fs.ftruncateSync(edit, 7);
                  assert.deepEqual(fs.readFileSync(finalName), Buffer.from([102, 105, 0, 0, 0, 0, 0]));
                  assert.equal(fs.writeSync(edit, Buffer.from('X')), 1);
                  assert.deepEqual(fs.readFileSync(finalName), Buffer.from([102, 105, 0, 0, 0, 88, 0]));
                  assert.throws(() => fs.ftruncateSync(readOnly, 0), e => e.code === 'EBADF' || e.code === 'EINVAL');
                  assert.throws(() => fs.ftruncateSync(edit, 256 * 1024 * 1024 + 1), {code: 'EFBIG'});
                  assert.equal(fs.fstatSync(readOnly).size, 7);
                  // This Node API converts a negative length to zero before calling Linux.
                  fs.ftruncateSync(edit, -1);
                  assert.equal(fs.writeSync(edit, Buffer.alloc(0)), 0);
                  assert.equal(fs.fstatSync(readOnly).size, 0);
                  assert.equal(fs.writeSync(edit, Buffer.from('first\n'), 0, 6, 0), 6);
                } finally { fs.closeSync(readOnly); fs.closeSync(edit); }
                assert.throws(() => fs.linkSync(other, finalName), {code:'EEXIST'});
                assert.equal(fs.readFileSync(finalName, 'utf8'), 'first\n');
                assert.throws(() => fs.linkSync(__dirname, denied), {code:'EPERM'});
                assert.throws(() => fs.linkSync('/../outside', denied), {code:'EPERM'});
                assert.throws(() => fs.linkSync(tmp, '/../outside'), {code:'EPERM'});
                assert.throws(() => fs.statSync(denied), {code:'ENOENT'});
                fs.unlinkSync(tmp);
                assert.equal(fs.statSync(finalName, {bigint:true}).nlink, 1n);
                assert.equal(fs.readFileSync(finalName, 'utf8'), 'first\n');
                fs.unlinkSync(other);
                const removeTree = path.join(__dirname, 'remove-tree');
                fs.mkdirSync(path.join(removeTree, 'one', 'two'), {recursive:true});
                fs.writeFileSync(path.join(removeTree, 'one', 'two', 'item'), 'nested');
                fs.writeFileSync(path.join(removeTree, 'sibling'), 'sibling');
                fs.linkSync(finalName, path.join(removeTree, 'one', 'history-link'));
                assert.equal(fs.statSync(finalName, {bigint:true}).nlink, 2n);
                fs.rmSync(removeTree, {recursive:true});
                assert.throws(() => fs.statSync(removeTree), {code:'ENOENT'});
                assert.equal(fs.statSync(finalName, {bigint:true}).nlink, 1n);
                assert.equal(fs.readFileSync(finalName, 'utf8'), 'first\n');
                const modeFd = fs.openSync(renamed, 'r+');
                try {
                  fs.fchmodSync(modeFd, 0o640);
                  assert.equal(fs.fstatSync(modeFd).mode & 0o777, 0o640);
                  assert.throws(() => fs.fchmodSync(modeFd, 0o4640), { code: 'EINVAL' });
                  assert.equal(fs.fstatSync(modeFd).mode & 0o777, 0o640);
                } finally { fs.closeSync(modeFd); }
                const directory = path.join(__dirname, 'listing');
                fs.mkdirSync(directory);
                const names = Array.from({length: 180}, (_, i) => 'entry-' + String(i).padStart(3, '0') + '.txt');
                for (const name of names) fs.writeFileSync(path.join(directory, name), name);
                fs.mkdirSync(path.join(directory, '空目录🙂'));
                const expectedNames = [...names, '空目录🙂'].sort();
                assert.deepEqual(fs.readdirSync(directory).sort(), expectedNames);
                const typed = fs.readdirSync(directory, {withFileTypes: true});
                assert.equal(typed.filter(entry => entry.isFile()).length, 180);
                assert.equal(typed.filter(entry => entry.isDirectory()).length, 1);
                assert.deepEqual(fs.readdirSync(path.join(directory, '空目录🙂')), []);
                assert.throws(() => fs.readdirSync(source), {code: 'ENOENT'});
                assert.throws(() => fs.readdirSync(renamed), {code: 'ENOTDIR'});
                (async () => {
                  const pending = path.join(__dirname, 'async.tmp');
                  const final = path.join(__dirname, 'async.txt');
                  await fsp.writeFile(pending, text + 'async\n', 'utf8');
                  assert.equal(await fsp.readFile(pending, 'utf8'), text + 'async\n');
                  await fsp.rename(pending, final);
                  const asyncStat = await fsp.stat(final);
                  assert.ok(asyncStat.isFile());
                  assert.equal(asyncStat.size, Buffer.byteLength(text + 'async\n'));
                  await assert.rejects(fsp.stat(pending), { code: 'ENOENT' });
                  await fsp.access(final, fs.constants.R_OK | fs.constants.W_OK);
                  await assert.rejects(fsp.access(pending), { code: 'ENOENT' });
                  const executable = await fsp.readlink('/proc/self/exe');
                  assert.equal(executable, '/usr/bin/node');
                  assert.deepEqual((await fsp.readdir(directory)).sort(), expectedNames);
                  const streamed = [];
                  for await (const entry of await fsp.opendir(directory)) streamed.push(entry.name);
                  assert.deepEqual(streamed.sort(), expectedNames);
                  await assert.rejects(fsp.readdir(source), {code: 'ENOENT'});
                  await assert.rejects(fsp.readdir(renamed), {code: 'ENOTDIR'});
                  const journal = path.join(__dirname, 'large-history.jsonl');
                  const rows = Array.from({length: 12}, (_, row) =>
                    JSON.stringify({row, payload: 'π🙂'.repeat(1024 + row * 3)}) + '\n');
                  const expected = Buffer.from(rows.join(''));
                  assert.ok(expected.length > 65536 && Buffer.byteLength(rows[0]) > 4096);
                  fs.writeFileSync(journal, rows[0], {flag: 'wx'});
                  for (const row of rows.slice(1, 6)) await fsp.appendFile(journal, row);
                  const appender = await fsp.open(journal, 'a');
                  try {
                    for (const row of rows.slice(6)) await appender.writeFile(row);
                    await appender.sync();
                  } finally { await appender.close(); }
                  assert.equal((await fsp.stat(journal)).size, expected.length);
                  assert.ok(fs.readFileSync(journal).equals(expected), 'sync file contents');
                  assert.ok((await fsp.readFile(journal)).equals(expected), 'promises Buffer contents');
                  assert.ok((await fsp.readFile(journal, 'utf8')) === rows.join(''), 'promises UTF-8 contents');
                  const reader = await fsp.open(journal, 'r');
                  try {
                    const offset = 4089, length = 16387, buffer = Buffer.alloc(length);
                    const positioned = await reader.read(buffer, 0, length, offset);
                    assert.equal(positioned.bytesRead, length, 'regular-file positioned read');
                    assert.ok(buffer.equals(expected.subarray(offset, offset + length)), 'positioned content');
                    const tail = await reader.read(buffer, 0, length, expected.length - 17);
                    assert.equal(tail.bytesRead, 17, 'short read at EOF');
                    assert.ok(buffer.subarray(0, 17).equals(expected.subarray(-17)), 'EOF content');
                    assert.ok((await reader.readFile()).equals(expected), 'positioned reads preserve the file offset');
                  } finally { await reader.close(); }
                  console.log(JSON.stringify({syncBytes: syncStat.size, asyncBytes: asyncStat.size, renamed: true, access: true, executable, directoryEntries: streamed.length, journalBytes: expected.length}));
                })().catch(error => { console.error(error.stack); process.exitCode = 1; });
            """)
            val text = "Sucrune 文件🙂\n"
            check(client.readFile(envId, "/node-workflows/fs/history.jsonl").toString(Charsets.UTF_8) == "first\n")
            check(result.getInt("syncBytes") == text.toByteArray(Charsets.UTF_8).size &&
                result.getInt("asyncBytes") == (text + "async\n").toByteArray(Charsets.UTF_8).size && result.getBoolean("renamed") &&
                result.getBoolean("access") && result.getString("executable") == "/usr/bin/node" &&
                result.getInt("directoryEntries") == 181) { result.toString() }
            check(client.readFile(envId, "$root/fs/sync.txt").toString(Charsets.UTF_8) == text)
            check(client.readFile(envId, "$root/fs/async.txt").toString(Charsets.UTF_8) == text + "async\n")
            val expectedJournal = buildString {
                for (row in 0 until 12) {
                    append("{\"row\":").append(row).append(",\"payload\":\"")
                    append("π🙂".repeat(1024 + row * 3)).append("\"}\n")
                }
            }.toByteArray(Charsets.UTF_8)
            check(result.getInt("journalBytes") == expectedJournal.size &&
                client.readFile(envId, "$root/fs/large-history.jsonl").contentEquals(expectedJournal)) {
                "Guest and manager disagreed on the complete JSONL history"
            }
            "Node verified append, sync, promises and positioned reads across a ${expectedJournal.size}-byte JSONL file, hard-link truncation and a 181-entry directory. The manager independently checked the saved bytes"
        },
        "linux_node_esm_argv_unicode" to {
            write("esm", "模块.mjs", """
                export const text = '模块中文🙂';
                export const multiply = (left, right) => left * right;
            """)
            val main = write("esm", "main.mjs", """
                import assert from 'node:assert/strict';
                import {fileURLToPath} from 'node:url';
                import {multiply, text} from './模块.mjs';
                const again = await import('./模块.mjs');
                assert.equal(again.multiply, multiply);
                assert.equal(multiply(6, 7), 42);
                assert.equal(text, '模块中文🙂');
                assert.equal(fileURLToPath(import.meta.url), process.argv[1]);
                assert.deepEqual(process.argv.slice(2), ['参数 中文🙂', 'with spaces', '']);
                console.log(JSON.stringify({value: multiply(6, 7), text, argv: process.argv.slice(2)}));
            """)
            val result = output(execute(listOf(main, "参数 中文🙂", "with spaces", "")))
            check(result.getInt("value") == 42 && result.getString("text") == "模块中文🙂") { result.toString() }
            val argv = result.getJSONArray("argv")
            check(argv.length() == 3 && argv.getString(0) == "参数 中文🙂" && argv.getString(1) == "with spaces" && argv.getString(2).isEmpty()) { result.toString() }
            "Static and dynamic ESM imports loaded a Unicode filename, preserved module identity, and passed UTF-8, spaced and empty argv"
        },
        "linux_node_timers_promises" to {
            val result = run("timers", """
                'use strict';
                const assert = require('node:assert/strict');
                const {setTimeout: delay, setImmediate: immediate, setInterval: interval} = require('node:timers/promises');
                (async () => {
                  const steps = [];
                  await Promise.resolve().then(() => steps.push('microtask'));
                  const before = process.hrtime.bigint();
                  assert.equal(await delay(20, 'timeout'), 'timeout');
                  assert.ok(process.hrtime.bigint() - before >= 10000000n);
                  steps.push('timeout');
                  assert.equal(await immediate('immediate'), 'immediate');
                  steps.push('immediate');
                  await new Promise(resolve => setTimeout(() => { steps.push('callback'); resolve(); }, 2));
                  let ticks = 0;
                  for await (const value of interval(2, 'tick')) {
                    assert.equal(value, 'tick');
                    if (++ticks === 3) break;
                  }
                  assert.deepEqual(steps, ['microtask', 'timeout', 'immediate', 'callback']);
                  console.log(JSON.stringify({steps, ticks}));
                })().catch(error => { console.error(error.stack); process.exitCode = 1; });
            """)
            val steps = result.getJSONArray("steps")
            check(steps.length() == 4 && steps.getString(0) == "microtask" && steps.getString(1) == "timeout" &&
                steps.getString(2) == "immediate" && steps.getString(3) == "callback" && result.getInt("ticks") == 3) { result.toString() }
            "Promise microtasks, delayed and immediate promises, callback timer and three async interval ticks completed; interval cleanup allowed natural exit"
        },
        "linux_node_crypto_workflow" to {
            val result = run("crypto", """
                'use strict';
                const assert = require('node:assert/strict');
                const {randomBytes, createHash} = require('node:crypto');
                (async () => {
                  const first = randomBytes(32);
                  const second = await new Promise((resolve, reject) => randomBytes(64, (error, bytes) => error ? reject(error) : resolve(bytes)));
                  assert.equal(first.length, 32);
                  assert.equal(second.length, 64);
                  assert.ok(first.some(value => value !== 0));
                  assert.ok(second.some(value => value !== 0));
                  assert.equal(first.equals(second.subarray(0, 32)), false);
                  const hash = createHash('sha256').update('a').update('bc').digest('hex');
                  assert.equal(hash, 'ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad');
                  console.log(JSON.stringify({syncBytes: first.length, asyncBytes: second.length, hash,
                    fingerprint: createHash('sha256').update(first).update(second).digest('hex')}));
                })().catch(error => { console.error(error.stack); process.exitCode = 1; });
            """)
            check(result.getInt("syncBytes") == 32 && result.getInt("asyncBytes") == 64 &&
                result.getString("hash") == "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad" &&
                result.getString("fingerprint").matches(Regex("[0-9a-f]{64}"))) { result.toString() }
            "OpenSSL-backed sync/async randomBytes and streaming SHA-256 matched the known abc digest"
        },
        "linux_node_worker_shared_atomics" to {
            write("workers", "worker.cjs", """
                'use strict';
                const assert = require('node:assert/strict');
                const {isMainThread, parentPort, workerData, threadId} = require('node:worker_threads');
                assert.equal(isMainThread, false);
                assert.ok(threadId > 0);
                globalThis.__sucruneWorkerOnly = 'independent isolate';
                const words = new Int32Array(workerData.shared);
                parentPort.once('message', message => {
                  assert.deepEqual(message, {command: 'start', text: '线程🙂'});
                  for (let index = 0; index < 4096; index++) Atomics.add(words, 1, 1);
                  Atomics.store(words, 0, 1);
                  Atomics.notify(words, 0, 1);
                  parentPort.postMessage({text: message.text, count: 4096, threadId, isolated: globalThis.__sucruneWorkerOnly});
                  parentPort.close();
                });
            """)
            val result = run("workers", """
                'use strict';
                const assert = require('node:assert/strict');
                const path = require('node:path');
                const {Worker, isMainThread, threadId} = require('node:worker_threads');
                assert.equal(isMainThread, true);
                assert.equal(threadId, 0);
                (async () => {
                  const shared = new SharedArrayBuffer(8);
                  const words = new Int32Array(shared);
                  const worker = new Worker(path.join(__dirname, 'worker.cjs'), {workerData: {shared}});
                  const message = new Promise((resolve, reject) => { worker.once('message', resolve); worker.once('error', reject); });
                  const exit = new Promise((resolve, reject) => { worker.once('exit', resolve); worker.once('error', reject); });
                  const settled = Promise.all([message, exit]);
                  try {
                    worker.postMessage({command: 'start', text: '线程🙂'});
                    // Progress while the parent JS thread is blocked requires a real worker.
                    if (Atomics.load(words, 0) === 0) assert.notEqual(Atomics.wait(words, 0, 0, 15000), 'timed-out');
                    assert.equal(Atomics.load(words, 0), 1);
                    assert.equal(Atomics.add(words, 1, 7), 4096);
                    const [reply, exitCode] = await settled;
                    assert.equal(exitCode, 0);
                    assert.equal(reply.text, '线程🙂');
                    assert.equal(reply.count, 4096);
                    assert.ok(reply.threadId > 0);
                    assert.equal(reply.isolated, 'independent isolate');
                    assert.equal(globalThis.__sucruneWorkerOnly, undefined);
                    assert.equal(Atomics.load(words, 1), 4103);
                    console.log(JSON.stringify({worker: true, independent: true, atomic: Atomics.load(words, 1), message: reply.text}));
                  } finally { await worker.terminate(); }
                })().catch(error => { console.error(error.stack); process.exitCode = 1; });
            """)
            check(result.getBoolean("worker") && result.getBoolean("independent") && result.getInt("atomic") == 4103 &&
                result.getString("message") == "线程🙂") { result.toString() }
            "A separate worker JS file exchanged Unicode messages, advanced shared Atomics while parent JS blocked, preserved isolate globals and exited normally"
        },
        "linux_node_jit_optimization" to {
            val main = write("jit", "main.cjs", """
                'use strict';
                const assert = require('node:assert/strict');
                function sucruneJitSum(left, right) { return (left + right) | 0; }
                %PrepareFunctionForOptimization(sucruneJitSum);
                let warmup = 0;
                for (let index = 0; index < 32; index++) warmup += sucruneJitSum(index, 7);
                %OptimizeFunctionOnNextCall(sucruneJitSum);
                const value = sucruneJitSum(20, 22);
                assert.equal(value, 42);
                assert.equal(warmup, 720);
                // Compilation completion is checked in the V8 trace, not inferred from this result.
                console.log('SUCRUNE_JIT_RESULT ' + JSON.stringify({value, warmup}));
            """)
            val record = checked(execute(listOf("--trace-opt", "--allow-natives-syntax", "--no-concurrent-recompilation", main)))
            val lines = record.getString("stdout").lineSequence().toList()
            val compiled = lines.filter { it.contains("sucruneJitSum") &&
                (it.contains("completed compiling") || it.contains("completed optimizing")) && it.contains("TURBOFAN") }
            check(compiled.isNotEmpty()) { "V8 did not report completed TurboFan compilation of sucruneJitSum: $record" }
            val resultLines = lines.filter { it.startsWith("SUCRUNE_JIT_RESULT ") }
            check(resultLines.size == 1) { record.toString() }
            val result = JSONObject(resultLines.single().removePrefix("SUCRUNE_JIT_RESULT "))
            check(result.getInt("value") == 42 && result.getInt("warmup") == 720) { record.toString() }
            "V8 completed TurboFan compilation of sucruneJitSum and the optimized call returned 42: ${compiled.first()}"
        }
    )
}
