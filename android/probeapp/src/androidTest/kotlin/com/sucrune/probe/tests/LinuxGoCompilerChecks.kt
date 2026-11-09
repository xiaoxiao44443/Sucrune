package com.sucrune.probe.tests

import com.sucrune.probe.RuntimeClient
import org.json.JSONObject

internal fun linuxGoCompilerCases(
    client: RuntimeClient, project: String, execute: ToolboxExec
): List<Pair<String, () -> String>> {
    val root = "/usr/local/go"
    val work = "/workspace/go-compile"
    val go = "$root/bin/go"
    val compiler = "$root/pkg/tool/linux_arm64/compile"
    val env = listOf("GOROOT=$root", "GOCACHE=$work/cache", "GOTMPDIR=$work/tmp",
        "GOPATH=$work/gopath", "GOMAXPROCS=1", "CGO_ENABLED=0", "GOENV=off",
        "GOTOOLCHAIN=local", "GOPROXY=off", "GOSUMDB=off", "GOFLAGS=-p=1")
    fun prepare() {
        listOf(work, "$work/cache", "$work/tmp", "$work/gopath").forEach { client.makeDirectory(project, it) }
        client.writeFile(project, "$work/go.mod", "module example.test/sucrune\n\ngo 1.26\n".toByteArray())
        val source = """
            package main
            import ("math/bits"; "os"; "strconv")
            func main() {
                if len(os.Args) != 2 { os.Exit(2) }
                result := "compiled-on-sucrune:" + strconv.Itoa(bits.OnesCount64(0xb6)) + "\n"
                if err := os.WriteFile(os.Args[1], []byte(result), 0600); err != nil { panic(err) }
            }
        """.trimIndent()
        client.writeFile(project, "$work/main.go", source.toByteArray())
    }
    fun run(path: String, args: List<String>, target: String = "linux", timeout: Long = 60_000): JSONObject {
        val record = execute(path, args, work, env + listOf("GOOS=$target", "GOARCH=arm64"), timeout)
        check(record.optString("state") == "exited" && record.optInt("exit_code", -1) == 0) {
            "$path ${args.firstOrNull()} ($target/arm64) ${record.optString("state")}/${record.optInt("exit_code", -1)}: " +
                record.optString("stdout").takeLast(1000) + " " + record.optString("stderr").takeLast(3200)
        }
        return record
    }
    fun build(target: String): String {
        prepare()
        val binary = "$work/app-$target"
        run(go, listOf("build", "-buildvcs=false", "-trimpath", "-o", binary, "main.go"), target, 300_000)
        val info = run(go, listOf("version", "-m", binary)).getString("stdout")
        check(info.contains("go1.26.10") && info.contains("GOARCH=arm64") &&
            info.contains("GOOS=$target") && info.contains("CGO_ENABLED=0")) { "Unexpected Go build metadata: $info" }
        return binary
    }
    return listOf(
        "linux_go_toolchain_version" to {
            prepare()
            val version = run(go, listOf("version")).getString("stdout").trim()
            check(version == "go version go1.26.10 linux/arm64") { version }
            version
        },
        "linux_go_compile_archive" to {
            prepare()
            val version = run(compiler, listOf("-V=full")).getString("stdout").trim()
            check(version.contains("compile version go1.26.10")) { version }
            client.writeFile(project, "$work/value.go",
                "package value\nfunc Twice(n int) int { return n*2 }\n".toByteArray())
            run(compiler, listOf("-p", "example.test/value", "-pack", "-o", "$work/value.a", "value.go"))
            val artifact = client.readFile(project, "$work/value.a")
            check(artifact.size > 128 && artifact.copyOfRange(0, 8).decodeToString() == "!<arch>\n" &&
                artifact.decodeToString().contains("__.PKGDEF"))
            "Guest $version compiled Go source into a ${artifact.size}-byte package archive"
        },
        "linux_go_compile_link_run" to {
            prepare()
            val cfg = "/usr/local/go-prebuilt/linux_arm64/importcfg"
            val source = """
                package main
                import ("runtime"; "strconv")
                func main() {
                    println("guest-compiled:" + runtime.GOARCH + ":" + strconv.Itoa(runtime.GOMAXPROCS(0)))
                }
            """.trimIndent()
            client.writeFile(project, "$work/standalone.go", source.toByteArray())
            run(compiler, listOf("-p", "main", "-pack", "-importcfg", cfg, "-o", "$work/main.a", "standalone.go"))
            val exe = "$work/standalone"
            run("$root/pkg/tool/linux_arm64/link",
                listOf("-linkmode=internal", "-importcfg", cfg, "-o", exe, "$work/main.a"), timeout = 120_000)
            val output = run(exe, emptyList()).getString("stderr").trim()
            check(output == "guest-compiled:arm64:1") { output }
            "Guest compile and link produced an executable printing '$output' with precompiled ARM64 standard-library archives"
        },
        "linux_go_build_and_run" to {
            val binary = build("linux")
            run(binary, listOf("result.txt"))
            check(client.readFile(project, "$work/result.txt").decodeToString() == "compiled-on-sucrune:5\n")
            "Linux ARM64 go build compiled and linked standard-library imports; its executable wrote the expected project file"
        },
        "linux_go_build_android" to {
            val binary = build("android")
            val inspect = """
                const fs=require('node:fs'), b=fs.readFileSync(process.argv[1]);
                if (b.readUInt32BE(0)!==0x7f454c46 || b[4]!==2 || b[5]!==1 || b.readUInt16LE(18)!==183 ||
                    b.readUInt16LE(16)!==3) throw Error('expected little-endian AArch64 PIE');
                const off=Number(b.readBigUInt64LE(32)), size=b.readUInt16LE(54), n=b.readUInt16LE(56);
                let interp;
                for(let i=0;i<n;i++){const p=off+i*size; if(b.readUInt32LE(p)===3){
                  const at=Number(b.readBigUInt64LE(p+8)), len=Number(b.readBigUInt64LE(p+32));
                  interp=b.subarray(at,at+len-1).toString();
                }}
                if(interp!=='/system/bin/linker64') throw Error('unexpected interpreter '+interp);
                console.log(interp);
            """.trimIndent()
            val result = execute("/usr/bin/node", listOf("-e", inspect, binary), work,
                listOf("SUCRUNE_MEMORY_POLICY=linux-jit"), 60_000)
            check(result.optInt("exit_code", -1) == 0 && result.optString("stdout").trim() == "/system/bin/linker64") {
                result.optString("stderr").takeLast(700)
            }
            "GOOS=android GOARCH=arm64 produced an Android PIE with verified ELF interpreter and Go build settings"
        }
    )
}
