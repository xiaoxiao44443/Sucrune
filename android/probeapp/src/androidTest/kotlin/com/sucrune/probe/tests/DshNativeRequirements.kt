package com.sucrune.probe.tests

import com.sucrune.probe.RuntimeClient
import org.json.JSONObject
import java.util.UUID

/**
 * Two opt-in prerequisites using original Linux Node and the published system
 * addon. Caller prepares the SHA-verified SDK closure in an idle test project,
 * owns execution identity/barrier checks and final cleanup, and supplies no
 * credentials. These cases do not call a model or start an Agent. Raw runtime
 * errno remains in the execution result on failure; no missing syscall passes.
 */
internal fun dshNativeRequirementCases(
    client: RuntimeClient,
    environment: () -> String,
    execute: (String, List<String>, Long, String, List<String>) -> JSONObject
): List<Pair<String, () -> String>> {
    val directory = "/workspace/dsh-native-requirements-${UUID.randomUUID().toString().replace("-", "")}"
    val publicEnv = listOf("HOME=$directory/home", "TMPDIR=$directory/tmp", "DSH_TELEMETRY_DISABLED=1")
    fun run(source: String): Pair<String, JSONObject> {
        val project = environment()
        listOf(directory, "$directory/home", "$directory/tmp").forEach { client.makeDirectory(project, it) }
        val script = "$directory/check-${UUID.randomUUID()}.mjs"
        client.writeFile(project, script, source.toByteArray(Charsets.UTF_8))
        val record = execute(project, listOf(script), 45_000L, directory, publicEnv)
        check(record.getString("state") == "exited" && record.getInt("exit_code") == 0 && !record.getBoolean("truncated")) {
            "Original Linux Node native requirement failed; retain its bounded stderr/native errno record"
        }
        val result = record.getJSONObject("result")
        check(result.getBoolean("run_sent") && result.getBoolean("binder_death_confirmed") &&
            result.getBoolean("output_drained") && result.getBoolean("broker_cleanup_confirmed") && result.getBoolean("stdin_feeder_completed"))
        val native = result.getJSONObject("native")
        check(native.getString("kind") == "linux" && native.getString("status") == "exited" && native.getBoolean("runner_waited"))
        return project to JSONObject(record.getString("stdout").trim())
    }
    return listOf(
        "linux_dsh_native_process_report" to {
            val (_, report) = run("""
                import assert from 'node:assert/strict';
                const report = process.report.getReport();
                assert.equal(report.header.platform, 'linux');
                assert.equal(report.header.arch, 'arm64');
                assert.equal(report.header.nodejsVersion, process.version);
                assert.equal(report.header.processId, process.pid);
                assert.equal(typeof report.header.glibcVersionRuntime, 'string');
                assert.match(report.header.glibcVersionRuntime, /^[0-9]+\.[0-9]+/);
                // Never serialize the whole report: it includes environment values.
                console.log(JSON.stringify({ok:true, platform:report.header.platform,
                  arch:report.header.arch, node:report.header.nodejsVersion,
                  glibc:report.header.glibcVersionRuntime, pid:report.header.processId}));
            """.trimIndent())
            check(report.getBoolean("ok") && report.getString("platform") == "linux" && report.getString("arch") == "arm64")
            check(report.getString("node") == "v24.22.2" && report.getString("glibc").matches(Regex("[0-9]+\\.[0-9]+.*")))
            "Original Node process.report completed and identified GNU libc ${report.getString("glibc")}; no report environment or credentials were emitted"
        },
        "linux_dsh_native_flock_conflict_release" to {
            val (project, report) = run("""
                import assert from 'node:assert/strict';
                import {open} from 'node:fs/promises';
                import {createRequire} from 'node:module';
                import {pathToFileURL} from 'node:url';
                const require = createRequire('/opt/dsh/node_modules/@deepseek-ai/dsh/package.json');
                const {tryLockExclusive} = await import(pathToFileURL(require.resolve('@deepseek-ai/node-addon-system/flock')).href);
                const path = 'session.lock';
                let first, second, contender;
                let conflict;
                try {
                  first = await open(path, 'w+');
                  second = await open(path, 'r+');
                  const [a,b] = await Promise.all([first.stat({bigint:true}),second.stat({bigint:true})]);
                  assert.equal(a.ino,b.ino); assert.equal(a.dev,b.dev);
                  await tryLockExclusive(first.fd);
                  // Re-locking the same open description succeeds.
                  await tryLockExclusive(first.fd);
                  try { await tryLockExclusive(second.fd); }
                  catch(error) { conflict=error; }
                  assert.ok(conflict, 'independent open must conflict with the first lock');
                  assert.ok(['EAGAIN','EWOULDBLOCK'].includes(conflict.code));
                  assert.equal(conflict.syscall,'flock'); assert.equal(conflict.errno,11);
                  await first.close(); first=undefined;
                  await tryLockExclusive(second.fd);
                  await second.writeFile('SUCRUNE_FLOCK_OK\n');
                  await second.sync();
                  await second.close(); second=undefined;
                  contender=await open(path,'r+');
                  await tryLockExclusive(contender.fd);
                  await contender.close(); contender=undefined;
                  console.log(JSON.stringify({ok:true, mode:'original-system-node',
                    conflict_code:conflict.code, conflict_errno:conflict.errno,
                    same_description_relock:true, independent_open_conflict:true,
                    first_close_released:true, second_close_released:true}));
                } finally {
                  await Promise.allSettled([first?.close(),second?.close(),contender?.close()]);
                }
            """.trimIndent())
            check(report.getBoolean("ok") && report.getString("mode") == "original-system-node")
            check(report.getString("conflict_code") in setOf("EAGAIN", "EWOULDBLOCK") && report.getInt("conflict_errno") == 11)
            listOf("same_description_relock", "independent_open_conflict", "first_close_released", "second_close_released").forEach { check(report.getBoolean(it)) }
            check(client.readFile(project, "$directory/session.lock").toString(Charsets.UTF_8) == "SUCRUNE_FLOCK_OK\n")
            "Original published system.node performed real asynchronous flock: same-description re-lock, independent-open EAGAIN/EWOULDBLOCK and lock release on both closes passed"
        }
    )
}
