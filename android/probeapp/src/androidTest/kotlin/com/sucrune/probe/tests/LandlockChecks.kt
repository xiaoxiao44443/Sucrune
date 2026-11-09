package com.sucrune.probe.tests

import android.app.Activity
import android.app.Instrumentation
import android.os.Bundle
import com.sucrune.probe.RuntimeClient
import com.sucrune.probe.TrustedExecutable
import org.json.JSONObject
import java.security.MessageDigest
import java.util.UUID

/** Exercise the Linux UAPI through a real isolated worker, including an exec after fork. */
internal fun landlockChecks(instrumentation: Instrumentation) {
    val client = RuntimeClient.get(instrumentation.targetContext)
    val result = Bundle()
    var envId: String? = null
    try {
        val project = client.createEnvironment("landlock-" + UUID.randomUUID().toString().take(8)).getString("id")
        envId = project
        val assets = instrumentation.context.assets
        val binary = assets.open("linux-fixtures/linux-landlock.elf").use { it.readBytes() }
        val manifest = assets.open("linux-fixtures/linux-landlock.json").bufferedReader().use { JSONObject(it.readText()) }
        val hash = manifest.getString("sha256")
        fun install(path: String, bytes: ByteArray, checksum: String) {
            client.importFile(project, path, bytes.inputStream(), bytes.size.toLong(), checksum.lowercase(), executable = true)
        }
        client.makeDirectory(project, "/workspace/subdir")
        client.makeDirectory(project, "/protected")
        install("/workspace/probe", binary, hash)
        install("/protected/probe", binary, hash)
        val sentinel = "unchanged".toByteArray()
        client.writeFile(project, "/protected/sentinel", sentinel)
        fun run(path: String, args: List<String>, expected: String, trusted: TrustedExecutable? = null) {
            val id = client.executePath(project, path, args, cwd = "/workspace", timeoutMs = 30_000, trustedExecutable = trusted)
            val record = client.waitFor(id, 45_000)
            check(record.optString("state") == "exited" && record.optInt("exit_code", -1) == 0 &&
                record.optString("stdout").trim() == expected) { record.toString() }
        }
        run("/workspace/probe", emptyList(), "landlock-fs-fork-exec-ok")
        check(client.readFile(project, "/protected/sentinel").contentEquals(sentinel))
        val path = "/workspace/trusted"
        val replacement = "#!/does-not-exist\n".toByteArray()
        val checksum = MessageDigest.getInstance("SHA-256").digest(replacement).joinToString("") { "%02x".format(it) }
        install(path, replacement, checksum)
        run(path, listOf("identity"), "sealed-image-ok", TrustedExecutable(path, binary))
        result.putString("stream", "PASS Landlock ABI, nested restrictions, descriptors, fork/exec and sealed executable\n")
    } catch (error: Throwable) {
        result.putInt("failed", 1)
        result.putString("stream", "FAIL Landlock: $error\n")
    } finally {
        envId?.let { id ->
            try { client.deleteProject(id) }
            catch (error: Throwable) {
                result.putInt("failed", 1)
                result.putString("stream", result.getString("stream", "") + "FAIL cleanup $id: $error\n")
            }
        }
    }
    instrumentation.finish(if (result.getInt("failed") == 0) Activity.RESULT_OK else Activity.RESULT_CANCELED, result)
}
