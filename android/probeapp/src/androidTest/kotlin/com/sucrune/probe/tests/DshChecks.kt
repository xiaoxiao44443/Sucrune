package com.sucrune.probe.tests

import android.content.res.AssetManager
import android.os.SystemClock
import com.sucrune.probe.RuntimeClient
import org.json.JSONObject

/** Official CLI closure only. These checks do not start a profile or contact a model. */
internal fun dshCliCases(client: RuntimeClient, envId: String, assets: AssetManager,
                        progress: (Int, Int) -> Unit = { _, _ -> },
                        execute: (List<String>) -> JSONObject): List<Pair<String, () -> String>> {
    val manifest = JSONObject(assets.open("dsh-rootfs-smoke/manifest.json").bufferedReader().use { it.readText() })
    val entrypoint = manifest.getString("entrypoint")
    fun checked(argv: List<String>): JSONObject {
        val record = execute(argv)
        check(record.getString("stderr").isEmpty()) { record.toString() }
        check(record.getJSONObject("result").getJSONObject("native").getString("memory_policy") == "linux-jit") { record.toString() }
        return record
    }
    return listOf(
        "linux_dsh_import_official_cli" to {
            check(manifest.getBoolean("assets_materialized") && !manifest.getBoolean("package_scripts_executed"))
            val files = manifest.getJSONArray("files")
            val started = SystemClock.elapsedRealtime()
            val directories = HashSet<String>()
            for (index in 0 until files.length()) {
                val file = files.getJSONObject(index)
                val path = file.getString("path")
                check(path.startsWith("/opt/dsh/node_modules/"))
                val directory = path.substringBeforeLast('/')
                if (directories.add(directory)) client.makeDirectory(envId, directory)
                assets.open("dsh-rootfs-smoke/" + file.getString("asset")).use {
                    val imported = client.importFile(envId, path, it, file.getLong("bytes"), file.getString("sha256"),
                        executable = file.getInt("mode") and 73 != 0)
                    check(imported.getLong("size") == file.getLong("bytes"))
                }
                if ((index + 1) % 100 == 0) progress(index + 1, files.length())
            }
            client.makeDirectory(envId, "/workspace/dsh-test-home/.dsh")
            client.makeDirectory(envId, "/workspace/dsh-native-cache")
            "Imported ${files.length()} SHA-verified original files in ${SystemClock.elapsedRealtime() - started}ms from the pinned official DSH CLI closure; full profiles are excluded"
        },
        "linux_dsh_version" to {
            val record = checked(listOf(entrypoint, "--version"))
            check(record.getString("stdout") == "0.2.2-rc.1\n") { record.toString() }
            "Official unmodified DSH CLI reports 0.2.2-rc.1 under the original GNU/Linux ARM64 Node"
        },
        "linux_dsh_help" to {
            val record = checked(listOf(entrypoint, "--help"))
            val output = record.getString("stdout")
            listOf("Usage: dsh [--profile] <name>", "Options:", "--profile <name>", "-V, --version",
                "dsh plugin --profile <name> <pnpm-args...>").forEach { check(output.contains(it)) { record.toString() } }
            "Official DSH CLI parsed --help and printed profile, version and plugin usage; no profile or model call was started"
        },
        "linux_dsh_native_addon" to {
            val script = """
                const a=require('/opt/dsh/node_modules/node-addon-require-builtin');
                const i=a.getBindingInfo();
                const p=a.requireBuiltin('path');
                if(i.backend!=='napi'||i.bindingSource!=='optional-package'||
                  i.platformPackageSuffix!=='linux-arm64-gnu'||
                  i.optionalPackageName!=='node-addon-require-builtin-linux-arm64-gnu'||
                  p.posix.join('/sucrune','native')!=='/sucrune/native'||
                  !a.isAllowedInternalId('internal/modules/cjs/loader'))
                  throw Error('native mismatch '+JSON.stringify(i));
                console.log('DSH_NATIVE_OK '+JSON.stringify(i));
            """.trimIndent()
            val record = checked(listOf("-e", script))
            val output = record.getString("stdout")
            check(output.startsWith("DSH_NATIVE_OK ")) { record.toString() }
            val binding = JSONObject(output.removePrefix("DSH_NATIVE_OK ").trim())
            check(binding.getString("backend") == "napi" && binding.getString("platformPackageSuffix") == "linux-arm64-gnu")
            "DSH's original Linux ARM64 glibc N-API addon loaded and invoked a Node builtin: $binding"
        }
    )
}
