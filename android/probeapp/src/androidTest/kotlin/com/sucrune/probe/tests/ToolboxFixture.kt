package com.sucrune.probe.tests

import android.content.res.AssetManager
import com.sucrune.probe.RuntimeClient
import org.json.JSONObject
import java.util.zip.ZipInputStream

internal typealias ToolboxExec = (String, List<String>, String, List<String>, Long) -> JSONObject

/** Only the instrumentation APK supplies this userland. All files enter via the public client. */
internal fun importToolboxFixture(assets: AssetManager, client: RuntimeClient, project: String,
                                 execute: ToolboxExec, assetRoot: String = "linux-toolbox"): String {
    val directories = hashSetOf<String>()
    fun directory(path: String) {
        if (directories.add(path)) client.makeDirectory(project, path)
    }
    listOf("/tmp", "/etc", "/home/agent", "/workspace").forEach(::directory)
    ZipInputStream(assets.open("$assetRoot/profile.bin").buffered()).use { zip ->
        check(zip.nextEntry?.name == "manifest.json")
        val manifest = JSONObject(zip.readBytes().toString(Charsets.UTF_8))
        check(manifest.getInt("schema_version") == 1)
        val files = manifest.getJSONArray("files")
        for (i in 0 until files.length()) {
            val file = files.getJSONObject(i)
            val path = file.getString("path")
            check(zip.nextEntry?.name == "root$path") { "Missing toolbox fixture entry $path" }
            directory(path.substringBeforeLast('/'))
            client.importFile(project, path, zip, file.getLong("bytes"), file.getString("sha256"),
                executable = file.getInt("mode") and 73 != 0)
        }
        check(zip.nextEntry == null)
        val aliases = manifest.getJSONArray("aliases")
        if (aliases.length() == 0) return "$assetRoot: ${files.length()} verified distribution files installed"
        for (i in 0 until aliases.length()) directory(aliases.getJSONObject(i).getString("path").substringBeforeLast('/'))
        // The test Node is already present in this project. Exercise guest linkat, so
        // ordinary guest shells can discover each multicall executable through PATH.
        val links = "/tmp/toolbox-test-aliases.json"
        client.writeFile(project, links, aliases.toString().toByteArray())
        val js = "const fs=require('node:fs'); for (const {target,path} of JSON.parse(fs.readFileSync(process.argv[1]))) " +
            "{ fs.linkSync(target,path); } fs.unlinkSync(process.argv[1]); console.log('aliases-ready')"
        val result = execute("/usr/bin/node", listOf("-e", js, links), "/", listOf("SUCRUNE_MEMORY_POLICY=linux-jit"), 120_000L)
        check(result.optInt("exit_code", -1) == 0 && result.optString("stdout").trim() == "aliases-ready") {
            "Guest command-link installation failed: ${result.optString("stderr").takeLast(1200)}"
        }
        return "${files.length()} verified distribution files and ${aliases.length()} guest command links installed"
    }
}
