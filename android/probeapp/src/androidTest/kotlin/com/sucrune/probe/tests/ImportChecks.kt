package com.sucrune.probe.tests

import android.app.Activity
import android.app.Instrumentation
import android.content.Context
import android.content.pm.ApplicationInfo
import android.os.Build
import android.os.Bundle
import android.os.Process
import android.os.SystemClock
import android.system.Os
import android.system.OsConstants
import com.sucrune.probe.NativeProbe
import com.sucrune.probe.RuntimeClient
import com.sucrune.probe.RuntimeExceptionWithCode
import org.json.JSONObject
import java.io.ByteArrayInputStream
import java.io.File
import java.io.IOException
import java.io.InputStream
import java.nio.file.Files
import java.security.MessageDigest
import java.util.UUID

/** Real Android manager-identity streaming import and POSIX boundary checks. */
internal class ImportChecks(private val instrumentation: Instrumentation,
                            private val context: Context, private val arguments: Bundle) {
    private lateinit var client: RuntimeClient
    private val environments = ArrayList<String>()
    private val executions = ArrayList<String>()
    private val ownedPrivatePaths = ArrayList<File>()
    private val summary = StringBuilder()
    private var passed = 0
    private var failed = 0
    private var current = 0
    private val dataRoot get() = File(context.filesDir, "sucrune")
    private val imports get() = File(dataRoot, "imports")

    fun run() {
        try {
            check(Build.VERSION.SDK_INT >= 29)
            val debug = context.applicationInfo.flags and ApplicationInfo.FLAG_DEBUGGABLE != 0
            arguments.getString("expect_debuggable")?.let { check(it == debug.toString()) }
            check(Process.myUid() == context.applicationInfo.uid && Process.myUid() != 0)
            client = RuntimeClient.get(context)
            val suffix = UUID.randomUUID().toString().take(8)
            val a = create("import-$suffix-A")
            val b = create("import-$suffix-B")
            val aw = workspace(a)
            val bw = workspace(b)
            case("import_large_stream") { large(a, b, aw) }
            case("import_executable_modes") { modes(a, aw) }
            case("import_stream_failures_preserve_artifact") { streamFailures(a, aw) }
            case("import_core_rechecks_integrity") { coreIntegrity(a, aw) }
            case("import_active_rejection_and_reuse") { busy(a, aw) }
            case("import_staging_symlink_rejected") { sourceLink(a, aw) }
            case("import_destination_symlinks_rejected") { targetLinks(a, b, aw, bw) }
        } catch (failure: Throwable) {
            failed++; summary.append("Runner failed: $failure\n")
        } finally {
            if (::client.isInitialized) {
                executions.forEach { id ->
                    try {
                        if (client.getExecution(id).getString("state") == "running") {
                            client.cancel(id)
                            check(client.waitFor(id, 10_000).getString("state") != "running")
                        }
                    } catch (failure: Throwable) { failed++; summary.append("Cleanup execution $id: $failure\n") }
                }
                // Exact, test-created files or links only. deleteIfExists never follows links.
                ownedPrivatePaths.forEach { file ->
                    try { Files.deleteIfExists(file.toPath()) }
                    catch (failure: Throwable) { failed++; summary.append("Cleanup private import entry: $failure\n") }
                }
                environments.forEach { id ->
                    try { client.deleteEnvironment(id) }
                    catch (failure: Throwable) { failed++; summary.append("Cleanup environment $id: $failure\n") }
                }
            }
            instrumentation.finish(if (passed == TOTAL && failed == 0) Activity.RESULT_OK else Activity.RESULT_CANCELED,
                Bundle().apply {
                    putInt("passed", passed); putInt("failed", failed); putInt("expected_tests", TOTAL)
                    putString("probe", "import"); putString("stream", "\n$summary\nPassed: $passed; failed: $failed\n")
                })
        }
    }

    private fun create(name: String) = client.createEnvironment(name).getString("id").also { environments.add(it) }
    private fun core(request: JSONObject): JSONObject = JSONObject(NativeProbe.coreCall(dataRoot.absolutePath, request.toString()))
    private fun workspace(env: String): File {
        val reply = core(JSONObject().put("op", "env.paths").put("env_id", env))
        check(reply.getBoolean("ok")) { reply.toString() }
        return File(reply.getJSONObject("result").getString("workspace")).also { check(it.isDirectory) }
    }
    private fun write(env: String, path: String, text: String) = client.writeFile(env, path, text.toByteArray(Charsets.UTF_8))
    private fun read(env: String, path: String) = client.readFile(env, path).toString(Charsets.UTF_8)
    private fun digest(data: ByteArray) = digest(ByteArrayInputStream(data))
    private fun digest(input: InputStream): String {
        val hash = MessageDigest.getInstance("SHA-256")
        val buffer = ByteArray(65_536)
        while (true) {
            val count = input.read(buffer)
            if (count < 0) break
            if (count != 0) hash.update(buffer, 0, count)
        }
        return hash.digest().joinToString("") { "%02x".format(it.toInt() and 255) }
    }
    private fun stagingNames(): Set<String> = imports.list()?.toSet() ?: error("Cannot list private imports")
    private fun noScratch(before: Set<String>, workspace: File) {
        check((stagingNames() - before).isEmpty()) { "Import staging entries were leaked" }
        check(workspace.listFiles()?.none { it.name.startsWith(".pending-import-") } == true) {
            "Import publication temporary was leaked"
        }
    }
    private fun mode(file: File, expected: Int) {
        val stat = Os.lstat(file.absolutePath)
        check(OsConstants.S_ISREG(stat.st_mode))
        check((stat.st_mode and 0xfff) == expected) { "Expected mode ${expected.toString(8)}, got ${(stat.st_mode and 0xfff).toString(8)}" }
    }
    private fun expectCode(code: String, body: () -> Unit) {
        try { body() }
        catch (failure: RuntimeExceptionWithCode) { check(failure.code == code) { failure.toString() }; return }
        error("Expected $code")
    }
    private fun importText(env: String, path: String, text: String, executable: Boolean = false): JSONObject {
        val data = text.toByteArray(Charsets.UTF_8)
        return ByteArrayInputStream(data).use { client.importFile(env, path, it, data.size.toLong(), digest(data), executable) }
    }

    private fun large(a: String, b: String, aw: File): String {
        val length = 2_097_169L
        val expected = PatternInput(length).use { digest(it) }
        val before = stagingNames()
        PatternInput(length).use { source ->
            val result = client.importFile(a, "大文件🙂.bin", source, length, expected)
            check(!source.closed) { "Import unexpectedly closed caller-owned input" }
            check(result.getLong("size") == length && result.getString("sha256") == expected)
            check(result.getString("path") == "/大文件🙂.bin" && !result.getBoolean("executable"))
        }
        val actual = File(aw, "大文件🙂.bin")
        check(actual.length() == length)
        check(actual.inputStream().use { digest(it) } == expected)
        mode(actual, 0x180)
        expectCode("too_large") { client.readFile(a, "大文件🙂.bin") }
        expectCode("not_found") { client.readFile(b, "大文件🙂.bin") }
        noScratch(before, aw)
        return "2097169 streamed bytes and SHA-256 match; default mode 0600, caller stream ownership, 1 MiB read limit and project separation verified"
    }

    private fun modes(a: String, aw: File): String {
        val before = stagingNames()
        val file = File(aw, "mode.bin")
        importText(a, "mode.bin", "default")
        mode(file, 0x180)
        val enabled = importText(a, "mode.bin", "executable", executable = true)
        check(enabled.getBoolean("executable")); mode(file, 0x1c0)
        // Neither an old target's public bits nor its executable bit may survive default replacement.
        Os.chmod(file.absolutePath, 0x1ff)
        val reset = importText(a, "mode.bin", "default-again")
        check(!reset.getBoolean("executable")); mode(file, 0x180)
        check(read(a, "mode.bin") == "default-again")
        importText(a, "empty.bin", "")
        check(File(aw, "empty.bin").length() == 0L)
        noScratch(before, aw)
        return "Real Android stat confirms explicit 0700, default/replacement 0600 and no special/public mode bits; empty stream imports correctly"
    }

    private fun streamFailures(a: String, aw: File): String {
        write(a, "preserved.txt", "original")
        val data = "replacement".toByteArray()
        val expected = digest(data)
        val before = stagingNames()
        ByteArrayInputStream(data).use { source ->
            expectCode("integrity_mismatch") { client.importFile(a, "preserved.txt", source, data.size.toLong(), "0".repeat(64)) }
        }
        for (size in listOf(data.size - 1L, data.size + 1L)) {
            ByteArrayInputStream(data).use { source ->
                expectCode("integrity_mismatch") { client.importFile(a, "preserved.txt", source, size, expected) }
            }
        }
        val broken = object : InputStream() {
            private var position = 0
            override fun read(): Int { if (position++ < 3) return 65; throw IOException("controlled import read failure") }
            override fun read(buffer: ByteArray, offset: Int, length: Int): Int {
                if (position != 0) throw IOException("controlled import read failure")
                val count = minOf(length, 3)
                buffer.fill(65, offset, offset + count); position += count; return count
            }
        }
        var rejected = false
        try { client.importFile(a, "preserved.txt", broken, 10, expected) }
        catch (failure: IOException) { check(failure.message == "controlled import read failure"); rejected = true }
        finally { broken.close() }
        check(rejected && read(a, "preserved.txt") == "original")
        noScratch(before, aw)
        return "Wrong digest, short/long stream and reader failure preserve existing artifact and remove private/publication temporaries"
    }

    private fun makeStage(data: ByteArray): Pair<String, File> {
        val id = UUID.randomUUID().toString()
        val file = File(imports, "$id.bin")
        check(file.createNewFile())
        ownedPrivatePaths.add(file)
        file.outputStream().use { it.write(data); it.fd.sync() }
        return id to file
    }
    private fun rawImport(env: String, path: String, id: String, size: Long, hash: String): JSONObject = core(
        JSONObject().put("op", "file.import").put("env_id", env).put("path", path)
            .put("import_id", id).put("size", size).put("sha256", hash))
    private fun coreRejected(reply: JSONObject, code: String) {
        check(!reply.getBoolean("ok") && reply.getJSONObject("error").getString("code") == code) { reply.toString() }
    }

    private fun coreIntegrity(a: String, aw: File): String {
        write(a, "core-preserved.txt", "original")
        val data = "replacement".toByteArray()
        val before = stagingNames()
        for (badSize in listOf(false, true)) {
            val (id, file) = makeStage(data)
            try {
                coreRejected(rawImport(a, "core-preserved.txt", id,
                    data.size.toLong() + if (badSize) 1 else 0,
                    if (badSize) digest(data) else "0".repeat(64)), "integrity_mismatch")
                check(!Files.exists(file.toPath())) { "Go did not consume rejected regular staging source" }
                check(read(a, "core-preserved.txt") == "original")
            } finally { Files.deleteIfExists(file.toPath()) }
        }
        val (id, file) = makeStage(data)
        try {
            coreRejected(rawImport(a, "../escape", id, data.size.toLong(), digest(data)), "unsafe_path")
            check(!Files.exists(file.toPath()))
        } finally { Files.deleteIfExists(file.toPath()) }
        noScratch(before, aw)
        return "Go independently rejects staged size/hash mismatch and traversal, consumes owned regular slots and preserves old destination"
    }

    private fun busy(a: String, aw: File): String {
        write(a, "busy.txt", "original")
        val id = client.execute(a, "echo ready; sleep 30", timeoutMs = 60_000).also { executions.add(it) }
        val until = SystemClock.elapsedRealtime() + 8_000
        while (true) {
            val current = client.getExecution(id)
            check(current.getString("state") == "running") { current.toString() }
            if (current.getString("stdout").contains("ready\n")) break
            check(SystemClock.elapsedRealtime() < until)
            SystemClock.sleep(25)
        }
        val before = stagingNames()
        expectCode("conflict") { importText(a, "busy.txt", "rejected") }
        val data = "rejected".toByteArray()
        val (stagingId, file) = makeStage(data)
        try {
            coreRejected(rawImport(a, "busy.txt", stagingId, data.size.toLong(), digest(data)), "conflict")
            check(!Files.exists(file.toPath()))
        } finally { Files.deleteIfExists(file.toPath()) }
        check(read(a, "busy.txt") == "original")
        noScratch(before, aw)
        check(client.cancel(id))
        val result = client.waitFor(id, 10_000)
        check(result.getString("state") == "cancelled")
        val barriers = result.getJSONObject("result")
        check(barriers.getBoolean("binder_death_confirmed") && barriers.getBoolean("output_drained") &&
            barriers.getBoolean("broker_cleanup_confirmed") && barriers.getBoolean("stdin_feeder_completed"))
        importText(a, "busy.txt", "after-cancel")
        check(read(a, "busy.txt") == "after-cancel")
        noScratch(before, aw)
        return "Both manager and Go reject active-project imports; cancellation satisfies four cleanup barriers before successful reuse"
    }

    private fun sourceLink(a: String, aw: File): String {
        write(a, "source-sentinel.txt", "sentinel")
        write(a, "source-destination.txt", "original")
        val id = UUID.randomUUID().toString()
        val link = File(imports, "$id.bin")
        val before = stagingNames()
        Os.symlink(File(aw, "source-sentinel.txt").absolutePath, link.absolutePath)
        ownedPrivatePaths.add(link)
        try {
            check(OsConstants.S_ISLNK(Os.lstat(link.absolutePath).st_mode))
            coreRejected(rawImport(a, "source-destination.txt", id, 8, digest("sentinel".toByteArray())), "unsafe_path")
            check(read(a, "source-sentinel.txt") == "sentinel" && read(a, "source-destination.txt") == "original")
            check(OsConstants.S_ISLNK(Os.lstat(link.absolutePath).st_mode))
        } finally { Files.deleteIfExists(link.toPath()) }
        noScratch(before, aw)
        return "Real Android symlink in an owned UUID staging slot is rejected without following, deleting or changing its target"
    }

    private fun targetLinks(a: String, b: String, aw: File, bw: File): String {
        write(b, "target-sentinel.txt", "other-project")
        val link = File(aw, "target-link")
        val parent = File(aw, "parent-link")
        val before = stagingNames()
        Os.symlink(File(bw, "target-sentinel.txt").absolutePath, link.absolutePath)
        ownedPrivatePaths.add(link)
        try {
            Os.symlink(bw.absolutePath, parent.absolutePath)
            ownedPrivatePaths.add(parent)
            try {
                expectCode("unsafe_path") { importText(a, "target-link", "overwrite") }
                expectCode("unsafe_path") { importText(a, "parent-link/target-sentinel.txt", "overwrite") }
                check(read(b, "target-sentinel.txt") == "other-project")
                check(OsConstants.S_ISLNK(Os.lstat(link.absolutePath).st_mode))
                check(OsConstants.S_ISLNK(Os.lstat(parent.absolutePath).st_mode))
            } finally { Files.deleteIfExists(parent.toPath()) }
        } finally { Files.deleteIfExists(link.toPath()) }
        noScratch(before, aw)
        return "Real destination and ancestor symlinks cannot redirect imports into another project; target content and links stay intact"
    }

    private class PatternInput(private val length: Long) : InputStream() {
        private var position = 0L
        var closed = false
            private set
        override fun read(): Int = if (position >= length) -1 else value(position++).toInt() and 0xff
        override fun read(buffer: ByteArray, offset: Int, count: Int): Int {
            if (count == 0) return 0
            if (position >= length) return -1
            val available = minOf(count.toLong(), length - position, 32_771L).toInt()
            for (i in 0 until available) buffer[offset + i] = value(position++)
            return available
        }
        override fun close() { closed = true }
        private fun value(index: Long): Byte = ((index * 131 + (index ushr 8)) and 0xff).toByte()
    }
    private fun case(name: String, body: () -> String) {
        current++; publish(1, name, "Starting $name")
        try { val detail = body(); passed++; summary.append("$name: PASS $detail\n"); publish(0, name, detail) }
        catch (failure: Throwable) { failed++; summary.append("$name: FAIL $failure\n"); publish(-2, name, failure.toString()) }
    }
    private fun publish(code: Int, name: String, detail: String) = instrumentation.sendStatus(code, Bundle().apply {
        putString("id", "SucruneImport"); putString("class", ImportChecks::class.java.name)
        putString("test", name); putInt("current", current); putInt("numtests", TOTAL)
        putString("stream", "\n$name: $detail\n")
    })
    companion object { private const val TOTAL = 7 }
}
