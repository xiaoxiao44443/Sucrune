package com.sucrune.probe.tests

import android.app.Activity
import android.app.Instrumentation
import android.os.Bundle
import android.os.ParcelFileDescriptor
import android.system.ErrnoException
import android.system.Os
import android.system.OsConstants
import com.sucrune.probe.GuestDirectory
import com.sucrune.probe.GuestDirectoryBind
import com.sucrune.probe.RuntimeClient
import com.sucrune.probe.RuntimeExceptionWithCode
import org.json.JSONObject
import java.io.Closeable
import java.nio.file.Files
import java.nio.file.Path
import java.util.UUID
import java.util.zip.ZipInputStream

private const val profile = "/home/sugar/.dsh"
private const val repairParent = "deepseek-harness/default-workspace/repair"
private const val repair = "/workspace/$repairParent/.dsh"
private const val busybox = "/bin/busybox"

/** A read-only provider above the nested recovery bind. Opening a real file must route to the bind. */
private class RepairWorkspace(private val root: Path) : GuestDirectory, Closeable {
    private val dirs = listOf("", "deepseek-harness", "deepseek-harness/default-workspace", repairParent, "$repairParent/.dsh")
    fun prepare() {
        for (name in dirs.drop(1)) Files.createDirectory(root.resolve(name))
    }
    private fun directory(path: String): Path {
        if (path !in dirs) throw ErrnoException("directory", OsConstants.ENOENT)
        return root.resolve(path)
    }
    override fun stat(path: String): LongArray {
        val st = Os.lstat(directory(path).toString())
        return longArrayOf(st.st_mode.toLong(), st.st_size, st.st_mtime * 1000, st.st_dev, st.st_ino)
    }
    override fun list(path: String): Array<String> {
        stat(path)
        return dirs.filter { it.isNotEmpty() && it.substringBeforeLast('/', "") == path }
            .map { it.substringAfterLast('/') }.toTypedArray()
    }
    override fun open(path: String, flags: Int, mode: Int): ParcelFileDescriptor {
        val target = directory(path)
        if (flags and (OsConstants.O_ACCMODE or OsConstants.O_CREAT or OsConstants.O_TRUNC) != 0)
            throw ErrnoException("open", OsConstants.EROFS)
        val fd = Os.open(target.toString(), flags or OsConstants.O_CLOEXEC or OsConstants.O_NOFOLLOW, 0)
        return try { ParcelFileDescriptor.dup(fd) } finally { Os.close(fd) }
    }
    override fun mkdir(path: String): Unit = throw ErrnoException("mkdir", OsConstants.EROFS)
    override fun remove(path: String, directory: Boolean): Unit = throw ErrnoException("remove", OsConstants.EROFS)
    override fun rename(source: String, target: String, flags: Int): Unit = throw ErrnoException("rename", OsConstants.EROFS)
    override fun close() {
        for (name in dirs.asReversed()) Files.deleteIfExists(root.resolve(name))
    }
}

internal fun sharedDirectoryChecks(instrumentation: Instrumentation) {
    val client = RuntimeClient.get(instrumentation.targetContext)
    val projects = mutableListOf<String>()
    val result = Bundle()
    var live: String? = null
    var stage = "fixture"
    fun fail(message: String) {
        result.putInt("failed", 1)
        result.putString("stream", result.getString("stream", "") + "FAIL shared_directory $stage: $message\n")
    }
    fun project(name: String): String =
        client.createEnvironment("bind-$name-${UUID.randomUUID().toString().take(8)}").getString("id").also(projects::add)

    try {
        val host = project("host")
        val first = project("a")
        val second = project("b")
        val recovery = project("recovery")
        client.makeDirectory(host, profile)
        client.writeFile(host, "$profile/state", "initial\n".toByteArray())
        client.writeFile(host, "/home/sugar/host-only", "host".toByteArray())
        for (id in listOf(first, second, recovery)) {
            client.makeDirectory(id, "/workspace")
            client.makeDirectory(id, "/bin")
            client.makeDirectory(id, profile)
        }
        ZipInputStream(instrumentation.context.assets.open("linux-toolbox/profile.bin").buffered()).use { zip ->
            check(zip.nextEntry?.name == "manifest.json")
            val files = JSONObject(zip.readBytes().decodeToString()).getJSONArray("files")
            val entry = (0 until files.length()).map(files::getJSONObject).single { it.getString("path") == busybox }
            while (true) {
                val member = checkNotNull(zip.nextEntry) { "Missing static BusyBox fixture" }
                if (member.name == "root$busybox") break
            }
            val bytes = zip.readBytes()
            for (id in listOf(first, second, recovery)) {
                client.importFile(id, busybox, bytes.inputStream(), entry.getLong("bytes"), entry.getString("sha256"), executable = true)
            }
        }
        val bind = GuestDirectoryBind(host, profile, profile)
        fun run(id: String, script: String, scope: String? = null, grant: GuestDirectoryBind? = bind,
                provider: GuestDirectory? = null, cwd: String = "/") {
            val exec = client.executePath(id, busybox, listOf("sh", "-ec", script),
                env = listOfNotNull(scope?.let { "SUCRUNE_WRITE_SCOPE=$it" }), cwd = cwd, timeoutMs = 30_000,
                workspaceDirectory = provider, directoryBind = grant)
            val rec = client.waitFor(exec, 45_000)
            check(rec.getString("state") == "exited" && rec.optInt("exit_code", -1) == 0) {
                "${rec.optString("state")}/${rec.optInt("exit_code", -1)}: ${rec.optString("stderr").take(500)} ${rec.optString("error").take(500)}"
            }
        }
        stage = "atomic-save-and-isolation"
        run(first, """
            read -r value < $profile/state
            [ "${'$'}value" = initial ]
            [ ! -e /home/sugar/host-only ]
            echo local-a > /workspace/only-a
            echo next > $profile/state.tmp
            $busybox mv $profile/state.tmp $profile/state
            $busybox ln -s state $profile/current
        """.trimIndent())
        run(second, """
            [ ! -e /workspace/only-a ]
            [ ! -e /home/sugar/host-only ]
            read -r value < $profile/current
            [ "${'$'}value" = next ]
            echo from-b > $profile/from-b
            echo local-b > /workspace/only-b
        """.trimIndent())
        run(first, "[ -f $profile/from-b ]; [ ! -e /workspace/only-b ]")
        check(client.readFile(host, "$profile/state").decodeToString() == "next\n")
        check(client.readFile(host, "$profile/from-b").decodeToString() == "from-b\n")
        run(first, "[ ! -e $profile/state ]; [ -f /workspace/only-a ]", grant = null)

        stage = "immutable-write-scopes"
        for (scope in listOf("read-only", "workspace-write")) {
            run(second, """
                read -r value < $profile/state
                [ "${'$'}value" = next ]
                if (echo overwrite > $profile/state); then exit 41; fi
                if $busybox rm $profile/state; then exit 42; fi
            """.trimIndent(), scope)
        }
        run(second, "if (echo x > /workspace/denied); then exit 43; fi", "read-only")
        run(second, "echo ok > /workspace/allowed", "workspace-write")
        check(client.readFile(host, "$profile/state").decodeToString() == "next\n")

        stage = "nested-recovery"
        val repairBind = GuestDirectoryBind(host, profile, repair)
        client.makeDirectory(recovery, "/tmp/recovery-home/.dsh")
        RepairWorkspace(Files.createTempDirectory(instrumentation.targetContext.cacheDir.toPath(), "sugar-repair-test-")).use { provider ->
            provider.prepare()
            run(recovery, """
            cd /workspace/deepseek-harness/default-workspace
            read -r value < repair/.dsh/state
            [ "${'$'}value" = next ]
            [ ! -e /tmp/recovery-home/.dsh/state ]
            echo scratch > /tmp/recovery-home/.dsh/state
            echo repaired > repair/.dsh/new
            $busybox mv repair/.dsh/new repair/.dsh/state
            """.trimIndent(), "workspace-write", repairBind, provider, cwd = "/workspace")
            run(recovery, "cd /workspace/deepseek-harness/default-workspace; if (echo no > repair/.dsh/state); then exit 44; fi",
                "read-only", repairBind, provider, cwd = "/workspace")
        }
        check(client.readFile(host, "$profile/state").decodeToString() == "repaired\n")
        check(client.readFile(recovery, "/tmp/recovery-home/.dsh/state").decodeToString() == "scratch\n")

        stage = "source-lifetime"
        check(runCatching { client.executePath(first, busybox, directoryBind = GuestDirectoryBind(first, profile, profile)) }
            .exceptionOrNull() is IllegalArgumentException)
        val exec = client.executePath(first, busybox, listOf("sleep", "120"), resident = true, directoryBind = bind)
        live = exec
        val conflict = runCatching { client.deleteProject(host) }.exceptionOrNull()
        check(conflict is RuntimeExceptionWithCode && conflict.code == "conflict") { "Source deletion was not rejected as busy: $conflict" }
        client.cancel(exec)
        client.waitFor(exec, 30_000)
        live = null
        result.putString("stream", "PASS shared directory: atomic updates, two isolated projects, immutable scopes, nested recovery and source lifetime\n")
    } catch (error: Throwable) {
        fail(error.toString())
    } finally {
        stage = "cleanup"
        live?.let { id -> runCatching { client.cancel(id); client.waitFor(id, 30_000) }.onFailure { fail(it.toString()) } }
        for (id in projects.asReversed()) {
            runCatching { client.deleteProject(id, purgeExecutionHistory = true) }.onFailure { fail(it.toString()) }
        }
    }
    instrumentation.finish(if (result.getInt("failed") == 0) Activity.RESULT_OK else Activity.RESULT_CANCELED, result)
}
