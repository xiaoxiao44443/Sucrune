package com.sucrune.probe.tests

import android.content.res.AssetManager
import com.sucrune.probe.RuntimeClient
import org.json.JSONObject
import java.security.MessageDigest
import java.util.zip.GZIPInputStream
import java.util.zip.ZipInputStream

internal fun linuxDistroProcessCases(execute: ToolboxExec): List<Pair<String, () -> String>> {
    val pipelines = listOf("bash", "ash").map { shell ->
        "linux_${shell}_nested_pipeline" to {
            val script = """set -eo pipefail; value=$(printf '%s\n' a b | tail -1 | tr b B); printf '<%s>\n' "${'$'}value" """
            val record = execute("/bin/$shell", listOf("-c", script), "/workspace", emptyList(), 30_000)
            check(record.optInt("exit_code", -1) == 0 && record.getString("stdout").trim() == "<B>") {
                "$shell nested pipeline: ${record.optString("stderr")} ${record.optString("stdout")}"
            }
            "$shell forked and waited for the children of a command-substitution pipeline."
        }
    }
    return pipelines + ("linux_tar_vfork_gzip" to {
        val script = "set -e; printf 'compressed in guest' > orig; tar -czf result.tgz orig; rm orig; tar -xzf result.tgz; cat orig"
        val record = execute("/bin/bash", listOf("-c", script), "/workspace", emptyList(), 30_000)
        check(record.optInt("exit_code", -1) == 0 && record.getString("stdout") == "compressed in guest") {
            "tar/gzip: ${record.optString("stderr")} ${record.optString("stdout")}"
        }
        "BusyBox tar ran gzip helpers and round-tripped the original bytes."
    })
}

internal fun alpineRootfsCase(assets: AssetManager, client: RuntimeClient, project: String, execute: ToolboxExec): String {
    client.makeDirectory(project, "/.sucrune-bootstrap")
    val bootstrap = "/.sucrune-bootstrap/busybox"
    val archive = "/.sucrune-rootfs.tar"
    // Stream only the static extraction tool from the existing Debian test bundle.
    ZipInputStream(assets.open("linux-toolbox/profile.bin").buffered()).use { zip ->
        while (true) {
            val entry = checkNotNull(zip.nextEntry) { "Missing static BusyBox fixture" }
            if (entry.name == "root/bin/busybox") break
        }
        client.importFile(project, bootstrap, zip, 1846504L,
            "61781806ad3650b0b9d2b3fc6971e2bffdca967af1a95375abd0578bafff14fb", executable = true)
    }
    GZIPInputStream(assets.open("linux-distro/rootfs.bin")).use {
        client.importFile(project, archive, it, 8806400L,
            "046decd25c65c6511229d2aca49bc0c27a02a5949d834eba2dbdcae449ff4295", executable = false)
    }
    fun run(path: String, vararg args: String): String {
        val record = try {
            execute(path, args.toList(), "/", listOf("PATH=/sbin:/usr/sbin:/bin:/usr/bin", "LD_LIBRARY_PATH=/lib:/usr/lib"), 120_000)
        } catch (failure: Exception) {
            throw IllegalStateException("$path ${args.take(2)}: ${failure.message}", failure)
        }
        check(record.optInt("exit_code", -1) == 0) { "$path ${args.firstOrNull()} exit=${record.optInt("exit_code", -1)}: ${record.optString("stderr").takeLast(2400)}" }
        return record.getString("stdout").trim()
    }
    fun expect(expected: String, path: String, vararg args: String) {
        val actual = run(path, *args)
        check(actual == expected) { "$path ${args.toList()} expected '$expected', got '$actual'" }
    }
    run(bootstrap, "tar", "-xof", archive)
    val inventory = assets.open("linux-distro/inventory.json").bufferedReader().use { JSONObject(it.readText()) }
    val checksums = "/.sucrune-bootstrap/files.sha256"
    assets.open("linux-distro/files.sha256").use { client.writeFile(project, checksums, it.readBytes()) }
    val hashes = run("/bin/busybox", "sha256sum", "-c", checksums)
    val files = inventory.getInt("regular_files")
    check(hashes.lines().count { it.endsWith(": OK") } == files) { "Incomplete archive checksum verification" }
    val directories = inventory.getJSONArray("directories")
    (0 until directories.length()).map(directories::getString).chunked(32).forEach { paths ->
        run("/bin/sh", "-c", """for dir do test -d "${'$'}dir" && ! test -L "${'$'}dir" || exit 1; done""", "sh", *paths.toTypedArray())
    }
    val targets = inventory.getJSONObject("links")
    targets.keys().asSequence().toList().chunked(32).forEach { paths ->
        val listing = run("/bin/busybox", "ls", "-ld", *paths.toTypedArray()).lines()
        for (path in paths) {
            check(listing.any { it.startsWith("l") && it.endsWith(" $path -> ${targets.getString(path)}") }) { "Incorrect symlink: $path" }
        }
    }
    expect("3.22.2", "/bin/cat", "/etc/alpine-release")
    expect("/bin/busybox", "/usr/bin/readlink", "/bin/sh")
    expect("../run", "/usr/bin/readlink", "/var/run")
    expect("/run", "/bin/sh", "-c", "cd /var/run && pwd -P")
    val script = """
        #!/bin/sh
        read -r version </etc/alpine-release || exit 72
        nested=$(read -r v </etc/alpine-release && printf '%s' "${'$'}v") || exit 73
        test "${'$'}version" = "${'$'}nested" || exit 74
        printf '%s/%s' "${'$'}version" "${'$'}1"
    """.trimIndent().toByteArray()
    val digest = MessageDigest.getInstance("SHA-256").digest(script).joinToString("") { "%02x".format(it) }
    val entry = "/.sucrune-bootstrap/check-release"
    client.importFile(project, entry, script.inputStream(), script.size.toLong(), digest, executable = true)
    expect("3.22.2/rootfs", entry, "rootfs")
    val installed = run("/sbin/apk", "info", "-e", "alpine-baselayout")
    check(installed.contains("alpine-baselayout")) { "apk info returned '$installed'" }
    val links = run("/usr/bin/find", "/", "-path", "/proc", "-prune", "-o", "-type", "l", "-print")
    check(links.lines().size == 335) { "Expected all 335 distribution symlinks, found ${links.lines().size}" }
    check(directories.length() + targets.length() + files == 520)
    return "Verified $files regular file hashes, ${directories.length()} directories and all 335 symlink targets; Alpine 3.22.2 sh, BusyBox and apk executed."
}
