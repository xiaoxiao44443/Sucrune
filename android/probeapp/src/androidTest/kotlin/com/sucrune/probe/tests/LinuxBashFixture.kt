package com.sucrune.probe.tests

import android.content.res.AssetManager
import com.sucrune.probe.RuntimeClient
import org.json.JSONObject

/** Add the original Debian Bash and terminfo files to a project with the glibc base fixture. */
internal fun importLinuxBashFixture(assets: AssetManager, client: RuntimeClient, envId: String): Int {
    val manifest = assets.open("linux-bash/manifest.json").bufferedReader().use { JSONObject(it.readText()) }
    check(manifest.getString("name") == "debian-bookworm-arm64-bash")
    check(manifest.getString("bash_version") == "5.2.15(1)-release")
    val files = manifest.getJSONArray("files")
    val importedPaths = mutableSetOf<String>()
    for (index in 0 until files.length()) {
        val file = files.getJSONObject(index)
        val path = file.getString("path")
        check(path.startsWith("/") && path.drop(1).split('/').none { it.isEmpty() || it == "." || it == ".." })
        check(file.getString("asset") == "files$path" && importedPaths.add(path))
        val size = file.getLong("bytes")
        val executable = path == "/bin/bash"
        check(file.getInt("mode") == if (executable) 493 else 420)
        client.makeDirectory(envId, path.substringBeforeLast('/'))
        assets.open("linux-bash/files$path").use { stream ->
            val imported = client.importFile(envId, path, stream, size, file.getString("sha256"), executable = executable)
            check(imported.getLong("size") == size) { "Incomplete Bash fixture import at $path" }
        }
    }
    check("/bin/bash" in importedPaths && "/lib/aarch64-linux-gnu/libtinfo.so.6" in importedPaths)
    return importedPaths.size
}
