package com.sucrune.probe.tests

import android.app.Activity
import android.app.Instrumentation
import android.content.Context
import android.os.Bundle
import com.sucrune.probe.RuntimeClient
import org.json.JSONArray
import org.json.JSONObject
import java.io.File
import java.nio.file.Files

/** Recovery tooling for this suite only; never clears application data/history. */
internal fun linuxDiagnostics(instrumentation: Instrumentation, context: Context, arguments: Bundle) {
    try {
        val client = RuntimeClient.get(context)
        val requested = arguments.getString("cleanup_ids")?.split(',')?.filter { it.isNotEmpty() } ?: emptyList()
        val removed = JSONArray()
        for (id in requested) {
            require(id.matches(Regex("env_[0-9a-f]{32}")))
            val env = client.getEnvironment(id)
            check(env.getString("name").matches(Regex("linux-(?:empty-|node-b-|sdk-)?[0-9a-f-]{8}"))) { "Not a Linux suite project: $env" }
            check(env.getString("state") != "running") { "Project is still reserved: $env" }
            client.deleteEnvironment(id)
            removed.put(id)
        }
        val orphanImports = arguments.getString("cleanup_import_ids")?.split(',')?.filter { it.isNotEmpty() } ?: emptyList()
        require(orphanImports.isEmpty() || requested.isNotEmpty()) { "Import cleanup requires explicit suite projects" }
        for (id in orphanImports) {
            require(id.matches(Regex("[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}")))
            val file = File(context.filesDir, "sucrune/imports/$id.bin")
            check(!Files.isSymbolicLink(file.toPath()) && file.isFile)
            Files.delete(file.toPath())
        }
        val environments = client.listEnvironments()
        for (index in 0 until environments.length()) {
            val env = environments.getJSONObject(index)
            if (env.getString("name").startsWith("linux-")) {
                val root = File(context.filesDir, "sucrune/environments/${env.getString("id")}/workspace")
                val files = root.walkTopDown().onEnter { !Files.isSymbolicLink(it.toPath()) }
                    .filter { it.isFile && !Files.isSymbolicLink(it.toPath()) }.toList()
                env.put("suite_file_count", files.size)
                env.put("recent_suite_paths", JSONArray(files.sortedByDescending { it.lastModified() }.take(4).map { it.relativeTo(root).path }))
            }
        }
        val imports = JSONArray()
        File(context.filesDir, "sucrune/imports").listFiles()?.forEach {
            imports.put(JSONObject().put("name", it.name).put("bytes", it.length()))
        }
        instrumentation.finish(Activity.RESULT_OK, Bundle().apply {
            putString("probe", "linux_diagnostics")
            putString("removed", removed.toString())
            putString("environments", environments.toString())
            putString("import_scratch", imports.toString())
            putString("stream", "Only explicitly identified suite projects were removed; execution history is retained.\n")
        })
    } catch (failure: Throwable) {
        instrumentation.finish(Activity.RESULT_CANCELED, Bundle().apply { putString("stream", failure.toString()) })
    }
}
