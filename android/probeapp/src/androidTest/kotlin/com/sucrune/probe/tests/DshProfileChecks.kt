package com.sucrune.probe.tests

import android.content.res.AssetManager
import android.os.Process
import android.os.SystemClock
import android.util.JsonReader
import android.util.JsonToken
import com.sucrune.probe.RuntimeClient
import com.sucrune.probe.RuntimeExceptionWithCode
import org.json.JSONObject
import java.io.StringReader

/**
 * Four dependent checks of the original sdk-minimal profile, not Web/Agent work.
 * createEnvironment is called only inside prepare; its caller owns final cleanup.
 * execute must run /usr/bin/node with linux-jit, the base C.UTF-8/LD_LIBRARY_PATH
 * environment and finite empty stdin. It owns identity, timeout, execution
 * tracking and all four death/drain barriers; argv here excludes Node argv[0].
 * startInteractive tracks the new execution while this helper keeps its writer
 * open until initialize and shutdown replies have arrived in that order.
 */
internal fun dshProfileCases(
    client: RuntimeClient,
    assets: AssetManager,
    createEnvironment: () -> String,
    execute: (String, List<String>, Long, String, List<String>) -> JSONObject,
    startInteractive: (String, List<String>, Long, String, List<String>) -> String,
    nativeRequirements: Boolean = false,
    bundleInstalled: (String) -> Unit = {}
): List<Pair<String, () -> String>> {
    val assetRoot = "dsh-sdk-minimal"
    val bundlePath = "/tmp/dsh-sdk-minimal.bundle.gz"
    val installerPath = "/tmp/guest-install-bundle.cjs"
    val entrypoint = "/opt/dsh/node_modules/@deepseek-ai/dsh/lib/bin.js"
    val profilePath = "/workspace/dsh-test-home/.dsh/profiles/sdk-minimal"
    val profileEnvironment = listOf(
        "HOME=/workspace/dsh-test-home",
        "DSH_HOME=/workspace/dsh-test-home/.dsh",
        "TMPDIR=/workspace/dsh-tmp",
        "NARB_NATIVE_CACHE_DIR=/workspace/dsh-native-cache",
        "DSH_TELEMETRY_DISABLED=1"
    )
    var envId: String? = null
    var receipt: JSONObject? = null
    var prepared = false
    var installed = false
    var prepareFailure = "prepare has not run"
    var installFailure = "install has not run"

    fun requirePrepared(): String {
        check(prepared) {
            "SKIPPED-AS-FAIL: preparation prerequisite failed ($prepareFailure); Linux/DSH runtime compatibility was not evaluated"
        }
        return checkNotNull(envId)
    }
    fun checkCompleted(record: JSONObject) {
        check(record.getString("state") == "exited" && record.getInt("exit_code") == 0) { "execution did not exit zero" }
        check(!record.getBoolean("truncated")) { "execution output was truncated" }
        val native = record.getJSONObject("result").getJSONObject("native")
        check(native.getString("kind") == "linux" && native.getString("status") == "exited" &&
            native.getString("memory_policy") == "linux-jit") { "Linux native startup/execution failed" }
        // Normal diagnostics are allowed. Reject concrete loader/module/native
        // failure markers even when a launcher incorrectly exits with zero.
        val diagnostics = record.getString("stderr") + "\n" + record.getString("stdout")
        listOf("MODULE_NOT_FOUND", "ERR_MODULE_NOT_FOUND", "ERR_DLOPEN_FAILED",
            "Cannot find module", "Cannot find package", "No native build was found",
            "Could not locate the bindings file", "Failed to load native binding",
            "error while loading shared libraries", "Error loading shared library",
            "cannot open shared object file", "FATAL ERROR:", "UnhandledPromiseRejection",
            "Segmentation fault", "dsh: fatal load failure:", "dsh: fatal uncaught exception:",
            "dsh: startup failed:", "dsh: disabling profile plugin").forEach { marker ->
            check(!diagnostics.contains(marker, ignoreCase = true)) { "startup/module/native failure marker: $marker" }
        }
        check(!Regex("dsh: warning: [0-9]+ entr(?:y|ies) did not activate", RegexOption.IGNORE_CASE).containsMatchIn(diagnostics)) {
            "Original profile reported inactive entries; reduced startup is not accepted as complete profile activation"
        }
    }

    return listOf(
        "linux_dsh_profile_prepare" to {
            try {
                val linux = JSONObject(assets.open("linux-rootfs/manifest.json").bufferedReader().use { it.readText() })
                val files = linux.getJSONArray("files")
                check(linux.getBoolean("includes_node") && files.length() == 28) { "Expected the original 28-file Node/glibc/locale rootfs" }
                val bundle = JSONObject(assets.open("$assetRoot/bundle.json").bufferedReader().use { it.readText() })
                check(bundle.getInt("schema_version") == 1 && bundle.getString("format") == "sucrune-file-bundle-v1" &&
                    bundle.getString("compression") == "gzip" && bundle.getString("asset") == "rootfs.bundle.gz")
                check(bundle.getInt("magic_bytes") == 17 && bundle.getInt("index_bytes") in 1..16_777_216)
                check(bundle.getLong("bytes") in 1L..268_435_456L)
                check(bundle.getInt("file_count") == 24_424 && bundle.getInt("package_count") == 212)
                listOf("sha256", "index_sha256", "source_manifest_sha256").forEach {
                    check(bundle.getString(it).matches(Regex("[0-9a-f]{64}"))) { "Invalid bundle receipt hash: $it" }
                }
                val payload = bundle.getLong("decompressed_bytes") - 17L - 4L - bundle.getLong("index_bytes")
                check(payload == 367_519_382L) { "Unexpected complete SDK profile payload size" }
                val installer = assets.open("$assetRoot/guest-install-bundle.cjs").use { it.readBytes() }
                check(installer.isNotEmpty() && installer.size <= 1_048_576)
                val project = createEnvironment().also { envId = it }
                val started = SystemClock.elapsedRealtime()
                val directories = HashSet<String>()
                val paths = HashSet<String>()
                for (index in 0 until files.length()) {
                    val file = files.getJSONObject(index)
                    val path = file.getString("path")
                    check(path.startsWith('/') && paths.add(path)) { "Invalid/duplicate Linux rootfs path" }
                    val directory = path.substringBeforeLast('/').ifEmpty { "/" }
                    if (directories.add(directory)) client.makeDirectory(project, directory)
                    assets.open("linux-rootfs/" + file.getString("asset")).use { input ->
                        val imported = client.importFile(project, path, input, file.getLong("bytes"), file.getString("sha256"),
                            executable = file.getInt("mode") and 73 != 0)
                        check(imported.getLong("size") == file.getLong("bytes") &&
                            imported.getString("sha256").equals(file.getString("sha256"), ignoreCase = true))
                    }
                }
                check(paths.containsAll(listOf("/usr/bin/node", "/lib/ld-linux-aarch64.so.1", "/lib/aarch64-linux-gnu/libc.so.6")))
                listOf("/tmp", "/opt", "/workspace/dsh-test-work", "/workspace/dsh-test-home/.dsh",
                    "/workspace/dsh-tmp", "/workspace/dsh-native-cache").forEach { client.makeDirectory(project, it) }
                // The target /opt/dsh is intentionally absent for atomic bundle publication.
                check(client.listFiles(project, "/opt").getJSONArray("entries").length() == 0)
                // AAPT expands .gz assets and drops the extension. Package the
                // exact verified gzip bytes under .bin so SHA/CRC stay meaningful.
                assets.open("$assetRoot/rootfs.bundle.bin").use { input ->
                    val imported = client.importFile(project, bundlePath, input, bundle.getLong("bytes"), bundle.getString("sha256"))
                    check(imported.getLong("size") == bundle.getLong("bytes") && imported.getString("sha256") == bundle.getString("sha256"))
                }
                check(client.writeFile(project, installerPath, installer).getLong("size") == installer.size.toLong())
                check(client.readFile(project, installerPath).contentEquals(installer))
                receipt = bundle
                prepared = true
                "Prepared a fresh project with 28 verified Linux files, one ${bundle.getLong("bytes")}-byte verified SDK bundle and installer in ${SystemClock.elapsedRealtime() - started}ms; no DSH profile has run"
            } catch (failure: Throwable) {
                prepareFailure = failure.toString()
                throw IllegalStateException("Profile preparation failed; downstream runtime claims are unavailable: $failure", failure)
            }
        },
        "linux_dsh_profile_install_bundle" to {
            val project = requirePrepared()
            val bundle = checkNotNull(receipt)
            var record: JSONObject? = null
            try {
                record = execute(project, listOf(installerPath, bundlePath, "--sha256", bundle.getString("sha256")),
                    300_000L, "/", profileEnvironment)
                checkCompleted(record)
                val report = JSONObject(record.getString("stdout").trim())
                check(report.getBoolean("ok") && report.getString("format") == bundle.getString("format") &&
                    report.getString("guest_prefix") == "/opt/dsh")
                check(report.getInt("file_count") == bundle.getInt("file_count") &&
                    report.getInt("package_count") == bundle.getInt("package_count"))
                check(report.getLong("total_bytes") == bundle.getLong("decompressed_bytes") - 21L - bundle.getLong("index_bytes"))
                check(report.getLong("compressed_bytes") == bundle.getLong("bytes") &&
                    report.getString("compressed_sha256") == bundle.getString("sha256"))
                check(report.getString("manifest_sha256") == bundle.getString("index_sha256") &&
                    report.getString("source_manifest_sha256") == bundle.getString("source_manifest_sha256"))
                installed = true
                bundleInstalled(project)
                "Original Linux Node installed ${report.getInt("file_count")} files/${report.getLong("total_bytes")} bytes with complete gzip/SHA validation and atomic publication; index=${report.getString("manifest_sha256")}"
            } catch (failure: Throwable) {
                installFailure = failure.toString()
                throw IllegalStateException("Profile bundle installation failed: $failure; full execution record=${record ?: "callback did not return a record"}", failure)
            }
        },
        "linux_dsh_sdk_minimal_eof" to {
            val project = requirePrepared()
            check(installed) {
                "SKIPPED-AS-FAIL: bundle installation prerequisite failed ($installFailure); sdk-minimal startup compatibility was not evaluated"
            }
            var record: JSONObject? = null
            try {
                record = execute(project, listOf(entrypoint, "sdk-minimal"), 120_000L,
                    "/workspace/dsh-test-work", profileEnvironment)
                checkCompleted(record)
                val packageJson = JSONObject(client.readFile(project, "$profilePath/package.json").toString(Charsets.UTF_8))
                check(packageJson.getString("name") == "dsh-profile-sdk-minimal" && packageJson.getBoolean("private"))
                val bundles = packageJson.getJSONObject("dsh").getJSONObject("profile").getJSONArray("bundles")
                check(bundles.length() == 1 && bundles.getString(0) == "@deepseek-ai/dsh-sdk-minimal")
                val cordis = client.readFile(project, "$profilePath/cordis.yml")
                val patch = client.readFile(project, "$profilePath/cordis.patch.yml")
                val workspace = client.readFile(project, "$profilePath/pnpm-workspace.yaml")
                check(cordis.isNotEmpty()) { "Original launcher did not publish a nonempty profile root" }
                "Official unmodified sdk-minimal reached appReady and exited zero after finite empty stdin; isolated profile package/bundles verified, cordis=${cordis.size}B, patch=${patch.size}B, pnpm-workspace=${workspace.size}B; no prompt/model/tool/Web/npm execution claimed"
            } catch (failure: Throwable) {
                throw IllegalStateException("Official sdk-minimal startup/artifact validation failed: $failure; full execution record=${record ?: "callback did not return a record"}", failure)
            }
        },
        "linux_dsh_sdk_initialize_shutdown" to {
            val project = requirePrepared()
            check(installed) {
                "SKIPPED-AS-FAIL: bundle installation prerequisite failed ($installFailure); SDK protocol compatibility was not evaluated"
            }
            // The same test-owned HOME contains only this run's generated
            // profile configuration. No user credentials or external HOME are
            // inherited; initialize resolves metadata, never prompt/query.
            val started = SystemClock.elapsedRealtime()
            val workDeadline = started + 110_000L
            val cleanupDeadline = started + 120_000L
            var executionId: String? = null
            var record: JSONObject? = null
            var primaryFailure: Throwable? = null
            val replies = HashMap<Int, JSONObject>()
            var consumed = ""
            var notifications = 0
            var shutdownSent = false

            fun observe(snapshot: JSONObject) {
                record = snapshot
                check(!snapshot.getBoolean("truncated")) { "SDK output was truncated" }
                val stdout = snapshot.getString("stdout")
                val stderr = snapshot.getString("stderr")
                check(stdout.toByteArray(Charsets.UTF_8).size + stderr.toByteArray(Charsets.UTF_8).size < 65_536) {
                    "SDK output exceeded the bounded protocol capture"
                }
                // Compare only complete previously consumed lines: a partial
                // UTF-8 character at the live capture tail may be replaced on
                // the next snapshot, while complete lines must stay immutable.
                check(stdout.startsWith(consumed)) { "SDK output prefix changed" }
                var offset = consumed.length
                while (true) {
                    val newline = stdout.indexOf('\n', offset)
                    if (newline < 0) break
                    val line = stdout.substring(offset, newline)
                    check(line.isNotBlank()) { "Unexpected empty SDK stdout frame" }
                    val frame = strictSdkObject(line)
                    check(frame.opt("jsonrpc") == "2.0" && !frame.has("error")) { "SDK protocol error or invalid version: $frame" }
                    if (frame.has("id")) {
                        val value = frame.get("id")
                        check(value is Int || value is Long) { "SDK response id must be an integer: $frame" }
                        val number = (value as Number).toLong()
                        check(number == 1L || number == 2L) { "Unexpected SDK response id: $frame" }
                        val id = number.toInt()
                        check(!frame.has("method") && frame.has("result") && !replies.containsKey(id)) { "Invalid or duplicate SDK response: $frame" }
                        check(id != 2 || shutdownSent) { "Shutdown response arrived before its request" }
                        val result = frame.getJSONObject("result")
                        if (id == 1) {
                            val server = result.getJSONObject("serverInfo")
                            check(server.opt("name") == "deepseek-harness-sdk-runtime" && server.opt("version") == "0.0.1") {
                                "Unexpected original SDK server identity: $result"
                            }
                        } else check(result.length() == 0) { "Original SDK shutdown must return an empty object: $result" }
                        replies[id] = frame
                    } else {
                        // Lifecycle notifications may interleave replies, but
                        // an error, server request or non-JSON stdout is never
                        // discarded as a diagnostic to manufacture a pass.
                        check(frame.opt("method") is String && frame.getString("method").isNotEmpty() && !frame.has("result")) {
                            "Malformed SDK notification: $frame"
                        }
                        check(!frame.has("params") || frame.get("params") is JSONObject) { "Invalid SDK notification params: $frame" }
                        notifications++
                    }
                    offset = newline + 1
                }
                consumed = stdout.substring(0, offset)
                if (snapshot.getString("state") != "running") {
                    check(stdout.length == offset) { "SDK exited with an incomplete JSON line" }
                }
            }

            fun awaitReply(id: Int): JSONObject {
                while (true) {
                    val snapshot = client.getExecution(checkNotNull(executionId))
                    observe(snapshot)
                    if (replies.containsKey(id)) return snapshot
                    check(snapshot.getString("state") == "running") { "SDK exited before reply $id" }
                    check(SystemClock.elapsedRealtime() < workDeadline) { "SDK reply $id exceeded the total handshake deadline" }
                    SystemClock.sleep(25)
                }
            }

            try {
                val id = startInteractive(project, listOf(entrypoint, "sdk-minimal"), 110_000L,
                    "/workspace/dsh-test-work", profileEnvironment).also { executionId = it }
                val initialize = (JSONObject().put("jsonrpc", "2.0").put("id", 1).put("method", "initialize")
                    .put("params", JSONObject().put("cwd", "/workspace/dsh-test-work")
                        .put("provider", "deepseek-official").put("model", "deepseek-flash")).toString() + "\n").toByteArray(Charsets.UTF_8)
                check(client.writeInput(id, initialize) == initialize.size) { "Initialize was not accepted as one complete input block" }
                val initialized = awaitReply(1)
                check(initialized.getString("state") == "running") { "SDK exited instead of awaiting the next request" }
                val live = initialized.getJSONObject("runtime")
                check(!live.getBoolean("input_closed") && !live.getBoolean("input_ended") && !live.getBoolean("stdin_feeder_completed")) {
                    "Interactive stdin closed before shutdown was requested"
                }
                val shutdown = (JSONObject().put("jsonrpc", "2.0").put("id", 2).put("method", "shutdown")
                    .put("params", JSONObject()).toString() + "\n").toByteArray(Charsets.UTF_8)
                check(client.writeInput(id, shutdown) == shutdown.size) { "Shutdown was not accepted as one complete input block" }
                shutdownSent = true
                awaitReply(2)
                while (true) {
                    val snapshot = client.getExecution(id)
                    observe(snapshot)
                    if (snapshot.getString("state") != "running") break
                    check(SystemClock.elapsedRealtime() < workDeadline) { "SDK failed to exit after its shutdown response" }
                    SystemClock.sleep(25)
                }
                val completed = checkNotNull(record)
                checkCompleted(completed)
                checkSdkBarriers(completed, requireRun = true)
                val result = completed.getJSONObject("result")
                val native = result.getJSONObject("native")
                val worker = result.getJSONObject("worker")
                check(worker.getString("identity") == "isolated_runtime" && worker.getInt("uid") != Process.myUid() && worker.getInt("uid") != 0)
                check(!worker.getBoolean("debuggable") && worker.getString("abi") == "arm64-v8a")
                val runner = native.getInt("runner_pid")
                check(runner > 0 && runner != worker.getInt("pid") && runner != Process.myPid() && worker.getInt("pid") != Process.myPid())
                check(native.getInt("pid") == runner && native.getInt("uid") == worker.getInt("uid") && native.getInt("runner_parent_pid") == worker.getInt("pid"))
                check(native.getBoolean("runner_waited") && native.getInt("runner_exit_code") == 0 && native.getBoolean("on_alt_stack"))
                if (native.getString("cleanup_mode") == "process_exit_group") {
                    check(native.getBoolean("report_on_host_tls") && !native.getBoolean("thread_joined") && !native.getBoolean("handler_restored"))
                } else {
                    check(native.getBoolean("host_tls_restored") && native.getBoolean("thread_joined") && native.getBoolean("handler_restored"))
                    check(native.getInt("fds_live") == 0 && native.getInt("resources_live") == 0)
                }
                val inputBytes = initialize.size + shutdown.size
                check(result.getInt("stdin_bytes_accepted") == inputBytes && result.getInt("stdin_bytes_written") == inputBytes)
                check(result.getBoolean("input_closed") && result.getBoolean("input_ended"))
                check(replies.size == 2)
                "Original SDK initialize returned deepseek-harness-sdk-runtime/0.0.1 while stdin stayed open; only then shutdown returned {}, process exited zero, and all four cleanup barriers completed; $inputBytes input bytes, $notifications protocol notifications; no prompt/model/tool request"
            } catch (failure: Throwable) {
                val wrapped = IllegalStateException("Official SDK interactive handshake failed: $failure; full execution record=${record ?: "no snapshot available"}", failure)
                primaryFailure = wrapped
                throw wrapped
            } finally {
                executionId?.let { id ->
                    var cleanupFailure: Throwable? = null
                    try { client.closeInput(id) }
                    catch (failure: RuntimeExceptionWithCode) {
                        if (failure.code != "not_found") cleanupFailure = failure
                    } catch (failure: Throwable) { cleanupFailure = failure }
                    try {
                        if (client.getExecution(id).getString("state") == "running") {
                            client.cancel(id)
                            val remaining = (cleanupDeadline - SystemClock.elapsedRealtime()).coerceAtLeast(0L)
                            val ended = client.waitFor(id, remaining)
                            check(ended.getString("state") != "running") { "SDK cleanup did not reach terminal state" }
                            checkSdkBarriers(ended, requireRun = false)
                        }
                    } catch (failure: Throwable) {
                        if (cleanupFailure == null) cleanupFailure = failure else cleanupFailure.addSuppressed(failure)
                    }
                    cleanupFailure?.let { failure ->
                        if (primaryFailure == null) throw failure else primaryFailure.addSuppressed(failure)
                    }
                }
            }
        }
    ) + if (nativeRequirements) dshNativeRequirementCases(client, environment = {
        val project = requirePrepared()
        check(installed) { "Native prerequisites require the installed SDK closure" }
        project
    }, execute = execute) else emptyList()
}

/** Android JSONObject accepts non-JSON extensions; validate the wire grammar
 * with a strict reader first, including unique keys and bounded nesting. */
private fun strictSdkObject(line: String): JSONObject {
    JsonReader(StringReader(line)).use { reader ->
        reader.isLenient = false
        fun value(depth: Int) {
            check(depth <= 32) { "SDK JSON frame nesting exceeds the limit" }
            when (reader.peek()) {
                JsonToken.BEGIN_OBJECT -> {
                    reader.beginObject()
                    val keys = HashSet<String>()
                    while (reader.hasNext()) {
                        check(keys.add(reader.nextName())) { "Duplicate SDK JSON object key" }
                        value(depth + 1)
                    }
                    reader.endObject()
                }
                JsonToken.BEGIN_ARRAY -> {
                    reader.beginArray()
                    while (reader.hasNext()) value(depth + 1)
                    reader.endArray()
                }
                JsonToken.STRING -> reader.nextString()
                JsonToken.NUMBER -> check(reader.nextString().matches(Regex("-?(?:0|[1-9][0-9]*)(?:\\.[0-9]+)?(?:[eE][+-]?[0-9]+)?"))) { "Malformed SDK JSON number" }
                JsonToken.BOOLEAN -> reader.nextBoolean()
                JsonToken.NULL -> reader.nextNull()
                else -> error("Invalid SDK JSON value")
            }
        }
        check(reader.peek() == JsonToken.BEGIN_OBJECT) { "SDK stdout frame must be a JSON object" }
        value(0)
        check(reader.peek() == JsonToken.END_DOCUMENT) { "Trailing data after SDK JSON object" }
    }
    return JSONObject(line)
}

private fun checkSdkBarriers(record: JSONObject, requireRun: Boolean) {
    val result = record.getJSONObject("result")
    check(result.getBoolean("binder_death_confirmed") || (!requireRun && result.getBoolean("worker_never_started")))
    if (requireRun) check(result.getBoolean("run_sent"))
    check(result.getBoolean("output_drained") && result.getBoolean("broker_cleanup_confirmed") && result.getBoolean("stdin_feeder_completed"))
}
