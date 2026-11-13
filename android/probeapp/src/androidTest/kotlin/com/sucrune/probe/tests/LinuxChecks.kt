package com.sucrune.probe.tests

import android.app.Activity
import android.app.Instrumentation
import android.content.Context
import android.content.pm.ApplicationInfo
import android.os.Build
import android.os.Bundle
import android.os.Process
import android.os.SystemClock
import android.util.Log
import com.sucrune.probe.RuntimeClient
import com.sucrune.probe.RuntimeExceptionWithCode
import org.json.JSONObject
import java.security.MessageDigest
import java.nio.ByteBuffer
import java.nio.ByteOrder
import java.util.UUID
import java.util.concurrent.atomic.AtomicBoolean

/** Upstream, unmodified dynamically linked Linux files imported through the public API. */
internal class LinuxChecks(private val instrumentation: Instrumentation,
                           private val context: Context, private val arguments: Bundle) {
    private lateinit var client: RuntimeClient
    private val environments = ArrayList<String>()
    private val executions = ArrayList<String>()
    private val summary = StringBuilder()
    private var passed = 0
    private var failed = 0
    private var current = 0
    private var total = 14
    private var focused = false
    private var toolOnly = false
    private val processTitleOnly = arguments.getString("focus") == "process_title"
    private var transientCredential: CharArray? = null
    private val realAgentSuite get() = arguments.getString("real_agent") == "true"
    private val env = listOf("LC_ALL=C.UTF-8", "LANG=C.UTF-8", "LD_LIBRARY_PATH=/lib/aarch64-linux-gnu:/usr/lib/aarch64-linux-gnu")
    private val loopReady = "LINUX_RUNNER_LOOP_READY\n"
    @Volatile private var currentOperation = "initializing"
    @Volatile private var lastProgress = SystemClock.elapsedRealtime()

    fun run() {
        val running = AtomicBoolean(true)
        val suiteThread = Thread.currentThread()
        val watchdog = Thread({
            try {
                while (running.get()) {
                    Thread.sleep(30_000)
                    if (running.get() && SystemClock.elapsedRealtime() - lastProgress > 90_000) {
                        Log.w("SucruneLinuxWatch", "No suite progress: $currentOperation; ${suiteThread.state}\n" +
                            suiteThread.stackTrace.take(16).joinToString("\n"))
                    }
                }
            } catch (_: InterruptedException) { /* Suite finished. */ }
        }, "sucrune-linux-watchdog").apply { isDaemon = true; start() }
        try {
            check(Build.SUPPORTED_ABIS.first() == "arm64-v8a")
            check(context.applicationInfo.flags and ApplicationInfo.FLAG_DEBUGGABLE == 0)
            client = RuntimeClient.get(context)
            val manifest = JSONObject(instrumentation.context.assets.open("linux-rootfs/manifest.json").bufferedReader().use { it.readText() })
            val node = arguments.getString("node") == "true"
            val dsh = arguments.getString("dsh") == "true"
            val sdk = arguments.getString("sdk") == "true"
            val network = arguments.getString("network") == "true"
            val nativeRequirements = arguments.getString("native_requirements") == "true"
            val secrets = arguments.getString("secrets") == "true"
            val dns = arguments.getString("dns") == "true"
            val processes = arguments.getString("linux_processes") == "true"
            val bash = arguments.getString("bash") == "true"
            val ptyLevel = arguments.getString("node_pty")?.toInt() ?: 0
            val realAgent = arguments.getString("real_agent") == "true"
            val dshTool = realAgent || arguments.getString("dsh_tool") == "true"
            require(!dshTool || sdk)
            focused = arguments.getString("focus") == "shell"
            toolOnly = arguments.getString("focus") == "dsh_tool"
            require(!toolOnly || (dshTool && sdk && node && !realAgent))
            require(ptyLevel in 0..3 && (ptyLevel == 0 || (bash && node)))
            require(!realAgent || (!focused && sdk && dns && secrets && nativeRequirements && processes && ptyLevel == 3))
            var installedProject: String? = null
            check(!dsh || node) { "DSH checks require -e node true" }
            check(!sdk || node) { "SDK profile checks require -e node true" }
            check(!network || node) { "Network checks require -e node true" }
            check(!nativeRequirements || sdk) { "Native DSH requirements need -e sdk true" }
            check(!secrets || node) { "Secret environment checks require -e node true" }
            check(!dns || node) { "DNS and HTTPS checks require -e node true" }
            if (node) { check(manifest.getBoolean("includes_node")); total += 15 }
            if (dsh) total += 4
            if (sdk) total += 4
            if (network) total += 5
            if (nativeRequirements) total += 2
            if (secrets) total += 2
            if (dns) total += 4
            if (bash) total++
            total += ptyLevel
            if (realAgent) total += 4
            if (dshTool) total++
            if (focused) total = 1 + (if (bash) 1 else 0) + ptyLevel
            if (ptyLevel == 3) total += 2
            val a = client.createEnvironment("linux-${UUID.randomUUID().toString().take(8)}").getString("id").also { environments.add(it) }
            val processSteps = if (processes) linuxProcessCases(client, instrumentation.context.assets, a,
                arguments.getString("vfork_probe") == "true") { path ->
                completed(start(a, path))
            } else emptyList()
            total += processSteps.size
            val stopCases = if (processes) listOf(linuxForkStopCase(instrumentation.context.assets, client, a,
                start = { path, argv -> start(a, path, argv) }, barriers = ::barriers)) else emptyList()
            val spawnCases = if (processes && node) nodeProcessCases { js ->
                completed(start(a, "/usr/bin/node", listOf("-e", js), timeoutMs = 30_000, jit = true))
            } else emptyList()
            total += stopCases.size + spawnCases.size
            val procCases = if (processes && node) nodeProcWorkflowCases { argv ->
                completed(start(a, "/usr/bin/node", argv, timeoutMs = 35_000, jit = true))
            } else emptyList()
            total += procCases.size
            val tcpSpawn = if (processes && node && bash) listOf(nodeNetworkForkCase { source, policy ->
                completed(start(a, "/usr/bin/node", listOf("-e", source), timeoutMs = 35_000, jit = true, extraEnv = policy))
            }) else emptyList()
            total += tcpSpawn.size
            val outputCases = if (node && (realAgent || arguments.getString("live_stdout") == "true"))
                nodeOutputWorkflowCases(client, start = { argv, timeout, stdout, secretEnv ->
                    client.executePathInteractiveStreaming(a, "/usr/bin/node", stdout, argv,
                        env + "SUCRUNE_MEMORY_POLICY=linux-jit", "/", timeout, secretEnv).also { executions.add(it) }
                }, finishAndCheck = { id -> completed(id) })
                else emptyList()
            total += outputCases.size
            if (toolOnly) total = 3
            val distro = arguments.getString("focus") == "distro"
            val toolbox = arguments.getString("focus") == "toolbox" || distro
            val compiler = arguments.getString("focus") == "compiler"
            val execTools = toolboxExecutor(a)
            val layers = if (compiler) {
                val available = setOf("go", "go-stdlib", "jdk", "android", "native-activity")
                val optional = listOf("jdk-zero", "gradle", "gradle-maven", "gradle-sdk")
                val requested = arguments.getString("compiler_profiles")?.split(',')?.toSet() ?: available
                require(requested.all { it in available || it in optional } &&
                    ("native-activity" !in requested || "android" in requested) &&
                    ("go-stdlib" !in requested || "go" in requested) &&
                    ("jdk-zero" !in requested || "jdk" in requested) &&
                    ("gradle" !in requested || "jdk" in requested) &&
                    ("gradle-maven" !in requested || "gradle" in requested) &&
                    ("gradle-sdk" !in requested || "android" in requested)) {
                    "Unknown compiler profile or missing prerequisite: $requested"
                }
                (available + optional).filter { it in requested }
            } else emptyList()
            val toolboxSteps = if (compiler) {
                val workflows = buildList {
                    add("linux_compiler_blocking_flock" to {
                        val script = """
                            import fcntl, threading
                            from pathlib import Path
                            p = Path('/workspace/compiler.lock')
                            with p.open('w+') as owner, p.open('r') as waiter:
                                started, acquired = threading.Event(), threading.Event()
                                fcntl.flock(owner, fcntl.LOCK_EX)
                                def lock():
                                    started.set()
                                    fcntl.flock(waiter, fcntl.LOCK_SH)
                                    acquired.set()
                                thread = threading.Thread(target=lock, daemon=True)
                                thread.start()
                                assert started.wait(3) and not acquired.wait(0.15)
                                fcntl.flock(owner, fcntl.LOCK_UN)
                                assert acquired.wait(3)
                                thread.join(3)
                                assert not thread.is_alive()
                        """.trimIndent()
                        val record = execTools("/usr/bin/python3", listOf("-c", script), "/workspace", emptyList(), 15_000)
                        check(record.optInt("exit_code", -1) == 0) { record.optString("stderr").takeLast(500) }
                        "A shared lock waited for an independent exclusive owner and resumed after unlock."
                    })
                    if ("go" in layers) addAll(linuxGoCompilerCases(client, a, execTools).filter { it.first != "linux_go_compile_link_run" || "go-stdlib" in layers })
                    if ("jdk" in layers) addAll(linuxJdkCompilerCases(client, a, execTools, zero = "jdk-zero" in layers))
                    if ("android" in layers) addAll(linuxAndroidCompilerCases(client, a, execTools,
                        includeKotlin = "gradle" in layers && "jdk" in layers,
                        export = if (arguments.getString("export_apk") == "true") { bytes, marker ->
                            emitInstallableApk(instrumentation, bytes, "dev.sucrune.compiled",
                                "dev.sucrune.compiled.MainActivity", marker)
                        } else null).filter {
                        it.first != "linux_android_java_signed_apk" || "jdk" in layers
                    })
                    if ("native-activity" in layers) add(linuxNativeActivityCompilerCase(client, a, execTools))
                    if ("jdk" in layers && "gradle-sdk" in layers) add(linuxAaptDaemonCase(client, a, execTools))
                    if ("gradle" in layers) addAll(linuxGradleCompilerCases(client, a, execTools,
                        buildAndroid = "gradle-sdk" in layers && "gradle-maven" in layers,
                        diagnose = arguments.getString("compiler_trace") == "true",
                        threadDumps = arguments.getString("gradle_threads") == "true",
                        traceFaults = arguments.getString("gradle_faults") == "true",
                        resourcesFirst = arguments.getString("gradle_resources_first") == "true",
                        vmMode = arguments.getString("gradle_vm") ?: "interpreter",
                        gradleTimeout = arguments.getString("gradle_timeout_ms")?.toLong() ?: 300_000L,
                        export = if (arguments.getString("export_apk") == "true") { bytes, marker ->
                            emitInstallableApk(instrumentation, bytes, GRADLE_PROBE_PACKAGE,
                                "$GRADLE_PROBE_PACKAGE.MainActivity", marker)
                        } else null))
                }
                val requested = arguments.getString("compiler_cases")?.split(',')?.toSet()
                require(requested == null || workflows.map { it.first }.containsAll(requested)) { "Unknown compiler case" }
                workflows.filter { requested == null || it.first in requested }
            } else if (distro) {
                val cases = linuxShebangCases(client, a, execTools) + linuxDistroProcessCases(execTools) + linuxDistroSymlinkCase(execTools) +
                    linuxReadOnlyFileCase(execTools, arguments.getString("expect_direct_read") == "true") +
                    ("linux_alpine_rootfs" to {
                        val fresh = client.createEnvironment("alpine-${UUID.randomUUID().toString().take(8)}").getString("id")
                        environments.add(fresh)
                        alpineRootfsCase(instrumentation.context.assets, client, fresh, toolboxExecutor(fresh))
                    })
                val requested = arguments.getString("distro_cases")?.split(',')?.toSet()
                require(requested == null || cases.map { it.first }.containsAll(requested))
                cases.filter { requested == null || it.first in requested }
            } else if (toolbox) {
                val execCase = "linux_toolbox_exec_replace" to {
                    val script = """shopt -s execfail; exec /missing-tool 2>/dev/null; test "$?" = 127 || exit 9
                        |exec 3>exec-output; exec /usr/bin/env MARK=ok /bin/bash -c 'printf "%s\n" "${'$'}MARK" >&3'
                    """.trimMargin()
                    val result = execTools("/bin/bash", listOf("-c", script), "/workspace", emptyList(), 30_000)
                    check(result.optInt("exit_code", -1) == 0 && client.readFile(a, "/workspace/exec-output").decodeToString() == "ok\n") { result.toString() }
                    check(result.getJSONObject("result").getJSONObject("native").getInt("exec_count") == 2)
                    "Two in-place ELF replacements retained cwd, environment and open descriptor after an ENOENT preflight."
                }
                val workflows = linuxBaseToolCases(client, a, execTools) + linuxGitCurlCases(client, a, execTools,
                    traceGitHttps = arguments.getString("git_https_trace") == "true",
                    includeComparisons = arguments.containsKey("toolbox_cases")) +
                    linuxPythonCases(client, a, execTools) + execCase + linuxDistroProcessCases(execTools)
                val requested = arguments.getString("toolbox_cases")?.split(',')?.toSet()
                if (requested == null) workflows else {
                    require(workflows.map { it.first }.containsAll(requested)) { "Unknown toolbox case" }
                    workflows.filter { it.first in requested }
                }
            } else emptyList()
            if (toolbox || compiler) total = 2 + layers.size + toolboxSteps.size
            if (processTitleOnly) {
                require(node) { "Process title checks require -e node true" }
                total = 2
            }
            case("linux_import_upstream") {
                val files = manifest.getJSONArray("files")
                for (index in 0 until files.length()) {
                    val file = files.getJSONObject(index)
                    val path = file.getString("path")
                    client.makeDirectory(a, path.substringBeforeLast('/').ifEmpty { "/" })
                    instrumentation.context.assets.open("linux-rootfs/" + file.getString("asset")).use {
                        val imported = client.importFile(a, path, it, file.getLong("bytes"), file.getString("sha256"),
                            executable = file.getInt("mode") and 73 != 0)
                        check(imported.getLong("size") == file.getLong("bytes"))
                    }
                }
                "Imported ${files.length()} original ELF/library/license files with streamed size/SHA checks"
            }
            if (toolbox || compiler) {
                case("linux_toolbox_import") {
                    importLinuxBashFixture(instrumentation.context.assets, client, a)
                    installTestResolver(a)
                    importToolboxFixture(instrumentation.context.assets, client, a, execTools)
                }
                for (layer in layers) case("linux_compiler_import_$layer") {
                    val root = if (layer == "android") "linux-android-build" else "linux-$layer"
                    importToolboxFixture(instrumentation.context.assets, client, a, execTools, root)
                }
                if (failed == 0) toolboxSteps.forEach { (name, body) -> case(name, body) }
                return
            }
            case("linux_dynamic_hello") {
                val record = completed(start(a, "/usr/bin/hello"))
                check(record.getString("stdout") == "Hello, world!\n" && record.getString("stderr").isEmpty()) { record.toString() }
                "Unmodified Debian ARM64 PIE + its PT_INTERP + glibc executed in an isolated worker: ${record.getJSONObject("result").getJSONObject("native")}"
            }
            case("linux_last_instruction_trap") {
                // ET_EXEC's last instruction ends exactly at the reservation
                // boundary. seccomp observes the post-SVC PC, not the opcode.
                val bytes = ByteArray(4096)
                val image = ByteBuffer.wrap(bytes).order(ByteOrder.LITTLE_ENDIAN)
                image.put(byteArrayOf(0x7f, 69, 76, 70, 2, 1, 1))
                image.putShort(16, 2); image.putShort(18, 183); image.putInt(20, 1)
                image.putLong(24, 0x400000L + 4084); image.putLong(32, 64)
                image.putShort(52, 64); image.putShort(54, 56); image.putShort(56, 1)
                image.putInt(64, 1); image.putInt(68, 5); image.putLong(80, 0x400000)
                image.putLong(96, 4096); image.putLong(104, 4096); image.putLong(112, 4096)
                image.putInt(4084, 0xd2800540.toInt()) // mov x0,#42
                image.putInt(4088, 0xd2800bc8.toInt()) // mov x8,#94
                image.putInt(4092, 0xd4000001.toInt()) // svc #0
                val hash = MessageDigest.getInstance("SHA-256").digest(bytes).joinToString("") { "%02x".format(it.toInt() and 255) }
                client.importFile(a, "/edge-exit", bytes.inputStream(), bytes.size.toLong(), hash, executable = true)
                val record = completed(start(a, "/edge-exit"), exit = 42)
                check(record.getJSONObject("result").getJSONObject("native").getInt("syscalls") == 1)
                "Boundary SVC was translated to exit 42 with host context restored, rather than forwarded as host exit_group"
            }
            case("linux_loader_dependency_list") {
                val record = completed(start(a, "/lib/ld-linux-aarch64.so.1", listOf("--list", "/usr/bin/hello")))
                check(record.getString("stdout").contains("libc.so.6") && record.getString("stderr").isEmpty()) { record.toString() }
                "Upstream dynamic linker mapped project libraries and listed libc dependency"
            }
            case("linux_argv_and_reuse") {
                val record = completed(start(a, "/usr/bin/hello", listOf("--greeting=Sucrune中文🙂")))
                check(record.getString("stdout") == "Sucrune中文🙂\n") { record.toString() }
                val second = completed(start(a, "/usr/bin/hello", listOf("--version")))
                // The SHA-pinned hello_2.10-3_arm64.deb ELF passes an empty
                // upstream VERSION literal. Do not invent a version in runtime.
                val version = second.getString("stdout")
                check(version.startsWith("hello (GNU Hello) \n\nCopyright (C) 2022 Free Software Foundation, Inc.\n") &&
                    version.contains("License GPLv3+: GNU GPL version 3 or later") &&
                    version.contains("There is NO WARRANTY") && second.getString("stderr").isEmpty()) { second.toString() }
                "UTF-8 argv, upstream version and repeated worker/image cleanup passed"
            }
            case("linux_invalid_image_and_permissions") {
                val bad = "not an ELF".toByteArray()
                val hash = MessageDigest.getInstance("SHA-256").digest(bad).joinToString("") { "%02x".format(it.toInt() and 255) }
                client.importFile(a, "/invalid", bad.inputStream(), bad.size.toLong(), hash, executable = true)
                rejected(start(a, "/invalid"), "linux_snapshot")
                client.writeFile(a, "/not-executable", bad)
                val denied = rejected(start(a, "/not-executable"), "linux_snapshot")
                check(denied.getJSONObject("result").getJSONObject("native").getInt("error_number") == 13)
                rejected(start(a, "/missing"), "linux_snapshot")
                completed(start(a, "/usr/bin/hello"))
                "Invalid, non-executable and missing files fail explicitly; cleanup permits reuse"
            }
            case("linux_project_boundary") {
                val b = client.createEnvironment("linux-empty-${UUID.randomUUID().toString().take(8)}").getString("id").also { environments.add(it) }
                val missing = rejected(start(b, "/usr/bin/hello"), "linux_snapshot")
                check(missing.getJSONObject("result").getJSONObject("native").getInt("error_number") == 2)
                rejected(start(b, "/system/bin/sh"), "linux_snapshot")
                "Project B cannot execute project A's imported files or Android host executable paths"
            }
            case("linux_runner_timeout") {
                importLoop(a)
                val id = start(a, "/runner-loop", timeoutMs = 8_000)
                awaitLoop(id, 6_000)
                val record = client.waitFor(id, 12_000)
                check(record.getString("state") == "timed_out") { record.toString() }
                barriers(record)
                check(record.getString("stdout") == loopReady && record.getString("stderr").isEmpty()) { record.toString() }
                completed(start(a, "/edge-exit"), exit = 42)
                "A guest already executing a syscall-free loop times out; child-held output, broker and input barriers complete before project reuse"
            }
            case("linux_runner_cancel_and_closed_stdin") {
                importLoop(a)
                val input = ByteArray(1_048_576) { 0x5a }
                val id = start(a, "/runner-loop", stdin = input)
                awaitLoop(id, 10_000)
                // The fixture closes guest stdin before entering its loop. A
                // duplicate reader in either fork process would keep this
                // bounded producer blocked until cancellation or process exit.
                val feederDeadline = SystemClock.elapsedRealtime() + 3_000
                while (true) {
                    val live = client.getExecution(id)
                    check(live.getString("state") == "running") { live.toString() }
                    val runtime = live.getJSONObject("runtime")
                    if (runtime.getBoolean("stdin_feeder_completed")) {
                        check(runtime.getInt("stdin_bytes_written") < input.size) { live.toString() }
                        break
                    }
                    check(SystemClock.elapsedRealtime() < feederDeadline) { "Closed guest stdin retained a hidden reader: $live" }
                    SystemClock.sleep(25)
                }
                check(client.cancel(id))
                val record = client.waitFor(id, 12_000)
                check(record.getString("state") == "cancelled") { record.toString() }
                barriers(record)
                check(record.getString("stdout") == loopReady && record.getString("stderr").isEmpty()) { record.toString() }
                completed(start(a, "/edge-exit"), exit = 42)
                "Closing stdin finishes the 1 MiB feeder while the guest still loops; cancellation drains all four barriers and permits project reuse"
            }
            case("linux_runner_exit_without_stdin_read") {
                val input = ByteArray(1_048_576) { 0x37 }
                val record = completed(start(a, "/edge-exit", stdin = input), exit = 42)
                val result = record.getJSONObject("result")
                check(result.getJSONObject("native").getLong("stdin_bytes_read") == 0L)
                check(result.getInt("stdin_bytes_written") < input.size) { record.toString() }
                check(record.getString("stdout").isEmpty() && record.getString("stderr").isEmpty()) { record.toString() }
                completed(start(a, "/edge-exit"), exit = 42)
                "An immediate guest exit consumes no stdin; the finite feeder completes and another runner reuses the project"
            }
            case("linux_signal_delivery_and_return") {
                val fixture = JSONObject(instrumentation.context.assets.open("linux-fixtures/linux-signal-smoke.json").bufferedReader().use { it.readText() })
                instrumentation.context.assets.open("linux-fixtures/linux-signal-smoke.elf").use {
                    client.importFile(a, "/signal-smoke", it, fixture.getLong("bytes"), fixture.getString("sha256"), executable = true)
                }
                val record = completed(start(a, "/signal-smoke"))
                check(record.getString("stdout") == "LINUX_SIGNAL_OK blocked nested siginfo gpr fpsimd reset\n" && record.getString("stderr").isEmpty()) { record.toString() }
                val native = record.getJSONObject("result").getJSONObject("native")
                check(native.getInt("signal_deliveries") == 6 && native.getInt("signal_returns") == 6) { record.toString() }
                "Real Linux/musl handlers ran with deferred and nested delivery; rt_sigreturn restored edited GPR/FPSIMD and SA_RESETHAND state"
            }
            case("linux_thread_parallel_and_join") {
                val fixture = JSONObject(instrumentation.context.assets.open("linux-fixtures/linux-thread-smoke.json").bufferedReader().use { it.readText() })
                instrumentation.context.assets.open("linux-fixtures/linux-thread-smoke.elf").use {
                    client.importFile(a, "/thread-smoke", it, fixture.getLong("bytes"), fixture.getString("sha256"), executable = true)
                }
                val record = completed(start(a, "/thread-smoke"))
                check(record.getString("stdout").startsWith("LINUX_THREAD_OK parallel=8 rounds=8 joined=64 atomic=16384 mutex=16384 tls=independent cond futex waits=")) { record.toString() }
                check(record.getString("stderr").isEmpty()) { record.toString() }
                val native = record.getJSONObject("result").getJSONObject("native")
                check(native.getString("cleanup_mode") == "joined" && native.getInt("threads_created") == 64 && native.getInt("threads_joined") == 64 && native.getInt("threads_live") == 0) { record.toString() }
                "64 real Linux/musl pthreads completed eight parallel rounds with independent TLS, mutex/condition/futex synchronization and host joins"
            }
            case("linux_thread_exit_group") {
                val record = completed(start(a, "/thread-smoke", listOf("exit-group")), exit = 37)
                check(record.getString("stdout") == "LINUX_THREAD_EXIT_GROUP_READY spinning=8\n" && record.getString("stderr").isEmpty()) { record.toString() }
                val native = record.getJSONObject("result").getJSONObject("native")
                check(native.getString("cleanup_mode") == "process_exit_group" && native.getInt("threads_created") == 8 && native.getInt("threads_live_before_exit") == 8) { record.toString() }
                completed(start(a, "/edge-exit"), exit = 42)
                "exit_group ended all eight syscall-free child loops; parent waitpid and four cleanup barriers completed before project reuse"
            }
            case("linux_local_io_concurrency") {
                val fixture = JSONObject(instrumentation.context.assets.open("linux-fixtures/linux-io-smoke.json").bufferedReader().use { it.readText() })
                instrumentation.context.assets.open("linux-fixtures/linux-io-smoke.elf").use {
                    client.importFile(a, "/io-smoke", it, fixture.getLong("bytes"), fixture.getString("sha256"), executable = true)
                }
                val record = completed(start(a, "/io-smoke"))
                check(record.getString("stdout").startsWith("LINUX_IO_OK ") && record.getString("stdout").contains("records=512 retained_epoll attempts=")) { record.toString() }
                check(record.getString("stderr").isEmpty()) { record.toString() }
                "Real guest pipe/eventfd/epoll alias lifetimes, 512 atomic writev records and a waiter retained across epfd close/reuse passed"
            }
            processSteps.forEach { (name, body) -> case(name, body) }
            stopCases.forEach { (name, body) -> case(name, body) }
            spawnCases.forEach { (name, body) -> case(name, body) }
            if (bash) case("linux_gnu_bash_builtins") {
                importLinuxBashFixture(instrumentation.context.assets, client, a)
                val script = """printf '%s\n' "${'$'}BASH_VERSION"; printf '%s\n' 'sucrune bash artifact' > /bash-output; IFS= read -r data < /bash-output && printf '%s\n' "${'$'}data" """
                val record = completed(start(a, "/bin/bash", listOf("--noprofile", "--norc", "-c", script),
                    extraEnv = listOf("HOME=/", "PATH=/bin:/usr/bin")))
                check(record.getString("stdout") == "5.2.15(1)-release\nsucrune bash artifact\n" &&
                    record.getString("stderr").isEmpty()) { record.toString() }
                check(client.readFile(a, "/bash-output").decodeToString() == "sucrune bash artifact\n")
                "Original Debian GNU Bash printed its live version, redirected a builtin to a project file and read it back"
            }
            tcpSpawn.forEach { (name, body) -> case(name, body) }
            procCases.forEach { (name, body) -> case(name, body) }
            outputCases.forEach { (name, body) -> case(name, body) }
            if (node) {
                if (ptyLevel != 0) {
                    val steps = nodePtyWorkflowCases { argv -> completed(start(a, "/usr/bin/node", argv, jit = true)) }
                    steps.take(ptyLevel).forEachIndexed { index, (name, body) -> case(name) {
                        if (index == 0) importNodePtyFixture(instrumentation.context.assets, client, a)
                        body()
                    } }
                    if (ptyLevel == 3) case("linux_node_pty_stty_echo") {
                        importLinuxSttyFixture(instrumentation.context.assets, client, a)
                        checkOriginalSttyEcho { argv -> completed(start(a, "/usr/bin/node", argv, jit = true)) }
                    }
                    if (ptyLevel == 3) case("linux_node_pty_job_control") {
                        checkOriginalPtyJobControl { argv -> completed(start(a, "/usr/bin/node", argv, timeoutMs = 40_000, jit = true)) }
                    }
                }
                case("linux_node_version") {
                    val record = completed(start(a, "/usr/bin/node", listOf("--version")))
                    check(record.getString("stdout") == "v24.22.2\n") { record.toString() }
                    "Official unmodified GNU/Linux ARM64 Node 24.22.2 prints its version"
                }
                case("linux_node_javascript") {
                    val record = completed(start(a, "/usr/bin/node", listOf("-e", "console.log(JSON.stringify({value:6*7,platform:process.platform,arch:process.arch}))"), jit = true))
                    check(record.getString("stdout") == "{\"value\":42,\"platform\":\"linux\",\"arch\":\"arm64\"}\n") { record.toString() }
                    check(record.getJSONObject("result").getJSONObject("native").getString("memory_policy") == "linux-jit")
                    "Real Node/V8 JavaScript evaluated under Linux ARM64 ABI with the explicit linux-jit memory policy"
                }
                case("linux_node_process_title") {
                    val source = """
                        const assert = require('node:assert/strict');
                        const before = process.argv.slice();
                        process.title = 'npm';
                        assert.equal(process.title, 'npm');
                        assert.deepEqual(process.argv, before);
                        assert.equal(process.env.SUCRUNE_TITLE_TEST, 'preserved');
                        console.log('title-ok');
                    """.trimIndent()
                    val record = completed(start(a, "/usr/bin/node", listOf("-e", source, "arg"), jit = true,
                        extraEnv = listOf("SUCRUNE_TITLE_TEST=preserved")))
                    check(record.getString("stdout") == "title-ok\n") { record.toString() }
                    "Node's libuv process-title update preserves JavaScript argv and environment"
                }
                case("linux_node_jitless") {
                    val record = completed(start(a, "/usr/bin/node", listOf("--jitless", "-e", "console.log(6*7)")))
                    check(record.getString("stdout") == "42\n" && record.getJSONObject("result").getJSONObject("native").getString("memory_policy") == "wx") { record.toString() }
                    "Official Node also evaluates JavaScript with --jitless under the default W^X policy"
                }
                nodeWorkflowCases(client, a) { argv ->
                    completed(start(a, "/usr/bin/node", argv, jit = true))
                }.forEach { (name, body) -> case(name, body) }
                nodeInputWorkflowCases(client, a,
                    start = { argv, timeout ->
                        startInteractive(a, argv, timeout)
                    },
                    finishAndCheck = { id, expectedState ->
                        val record = client.waitFor(id, 35_000)
                        check(record.getString("state") == expectedState) { record.toString() }
                        barriers(record)
                        completed(start(a, "/edge-exit"), exit = 42)
                        record
                    }).forEach { (name, body) -> case(name, body) }
                if (dns) {
                    installTestResolver(a)
                    nodeDnsWorkflowCases(client, a) { argv ->
                        completed(start(a, "/usr/bin/node", argv, jit = true,
                            extraEnv = listOf("SUCRUNE_NETWORK_POLICY=outbound")))
                    }.forEach { (name, body) -> case(name, body) }
                }
                if (secrets) nodeSecretsWorkflowCases(client, a,
                    start = { argv, timeout, secretEnv -> startInteractive(a, argv, timeout, secretEnv = secretEnv) },
                    proveReuse = { completed(start(a, "/edge-exit"), exit = 42); Unit }
                ).forEach { (name, body) -> case(name, body) }
                if (network) nodeNetworkWorkflowCases(client, a,
                    execute = { argv, enabled ->
                        completed(start(a, "/usr/bin/node", argv, jit = true, extraEnv =
                            if (enabled) listOf("SUCRUNE_NETWORK_POLICY=loopback") else emptyList()))
                    },
                    start = { argv, timeout -> start(a, "/usr/bin/node", argv, jit = true,
                        timeoutMs = timeout, extraEnv = listOf("SUCRUNE_NETWORK_POLICY=loopback")) },
                    stopAndReuse = { id ->
                        val record = client.waitFor(id, 35_000)
                        check(record.getString("state") == "cancelled") { record.toString() }
                        barriers(record)
                        completed(start(a, "/edge-exit"), exit = 42)
                        record
                    }).forEach { (name, body) -> case(name, body) }
                case("linux_node_parallel_projects") {
                    val b = client.createEnvironment("linux-node-b-${UUID.randomUUID().toString().take(8)}")
                        .getString("id").also { environments.add(it) }
                    val files = manifest.getJSONArray("files")
                    for (index in 0 until files.length()) {
                        val file = files.getJSONObject(index)
                        val path = file.getString("path")
                        client.makeDirectory(b, path.substringBeforeLast('/').ifEmpty { "/" })
                        instrumentation.context.assets.open("linux-rootfs/" + file.getString("asset")).use {
                            client.importFile(b, path, it, file.getLong("bytes"), file.getString("sha256"),
                                executable = file.getInt("mode") and 73 != 0)
                        }
                    }
                    client.writeFile(a, "/project.txt", "PROJECT_A中文".toByteArray(Charsets.UTF_8))
                    client.writeFile(b, "/project.txt", "PROJECT_B🙂".toByteArray(Charsets.UTF_8))
                    val script = """
                        const fs=require('node:fs');
                        const text=fs.readFileSync('/project.txt','utf8');
                        console.log('READY '+text);
                        setTimeout(()=>{
                          if(fs.readFileSync('/project.txt','utf8')!==text) throw Error('project changed');
                          fs.writeFileSync('/result.txt', text+' complete');
                          console.log('DONE '+text);
                        },3000);
                    """.trimIndent()
                    val first = start(a, "/usr/bin/node", listOf("-e", script), jit = true)
                    val second = start(b, "/usr/bin/node", listOf("-e", script), jit = true)
                    val left = completed(first)
                    val right = completed(second)
                    check(left.getString("stdout") == "READY PROJECT_A中文\nDONE PROJECT_A中文\n" && left.getString("stderr").isEmpty()) { left.toString() }
                    check(right.getString("stdout") == "READY PROJECT_B🙂\nDONE PROJECT_B🙂\n" && right.getString("stderr").isEmpty()) { right.toString() }
                    check(client.readFile(a, "/result.txt").toString(Charsets.UTF_8) == "PROJECT_A中文 complete")
                    check(client.readFile(b, "/result.txt").toString(Charsets.UTF_8) == "PROJECT_B🙂 complete")
                    val l = left.getJSONObject("result").getJSONObject("native")
                    val r = right.getJSONObject("result").getJSONObject("native")
                    check(l.getInt("pid") != r.getInt("pid") && l.getInt("uid") != r.getInt("uid"))
                    val overlap = minOf(l.getLong("native_finished_at_elapsed_ms"), r.getLong("native_finished_at_elapsed_ms")) -
                        maxOf(l.getLong("native_started_at_elapsed_ms"), r.getLong("native_started_at_elapsed_ms"))
                    check(overlap > 0L) { "Node execution intervals did not overlap: $left $right" }
                    "Two original Linux Node processes overlapped by ${overlap}ms in distinct isolated UIDs/PIDs and produced independent same-path files"
                }
            }
            if (dsh) {
                dshCliCases(client, a, instrumentation.context.assets, progress = { done, count ->
                    publish(2, "linux_dsh_import_official_cli", "Imported $done/$count verified files")
                }) { argv ->
                    completed(start(a, "/usr/bin/node", argv, jit = true, extraEnv = listOf(
                        "HOME=/workspace/dsh-test-home", "DSH_HOME=/workspace/dsh-test-home/.dsh",
                        "NARB_NATIVE_CACHE_DIR=/workspace/dsh-native-cache")))
                }.forEach { (name, body) -> case(name, body) }
            }
            if (sdk) {
                dshProfileCases(client, instrumentation.context.assets,
                    createEnvironment = {
                        client.createEnvironment("linux-sdk-${UUID.randomUUID().toString().take(8)}")
                            .getString("id").also { environments.add(it) }
                    },
                    execute = { project, argv, timeout, cwd, environment ->
                        completed(start(project, "/usr/bin/node", argv, timeoutMs = timeout,
                            jit = true, cwd = cwd, extraEnv = environment), waitMs = timeout + 5_000)
                    },
                    startInteractive = { project, argv, timeout, cwd, environment ->
                        startInteractive(project, argv, timeout, cwd, environment)
                    }, nativeRequirements = nativeRequirements, bundleInstalled = { installedProject = it }).forEach { (name, body) -> case(name, body) }
            }
            if (dshTool) case("linux_dsh_persistent_bash_tool") {
                val p = checkNotNull(installedProject)
                checkDshSessionResume(client, p, ::startInteractive)
                importLinuxBashFixture(instrumentation.context.assets, client, p)
                importLinuxSttyFixture(instrumentation.context.assets, client, p)
                importNodePtyFixture(instrumentation.context.assets, client, p, includeAddon = false)
                val withToolbox = arguments.getString("toolbox") == "true"
                if (withToolbox) importToolboxFixture(instrumentation.context.assets, client, p, toolboxExecutor(p))
                client.makeDirectory(p, "/workspace/terminal-check")
                checkDshPersistentBash(captureInitOutput = toolOnly, toolbox = withToolbox, writeFixture = { name, source ->
                    client.writeFile(p, "/workspace/terminal-check/$name", source.toByteArray())
                }) { argv ->
                    val id = start(p, "/usr/bin/node", argv, timeoutMs = 100_000, jit = true,
                        cwd = "/workspace/terminal-check", extraEnv = listOf("SHELL=/bin/bash","PATH=/usr/bin:/bin","HOME=/workspace/terminal-check"))
                    val record = client.waitFor(id, 110_000)
                    barriers(record)
                    if (record.optInt("exit_code", -1) == 0) completed(id) else record
                }
            }
            if (realAgent) {
                dshAgentCases(client, environment = {
                    check(failed == 0) { "Original Agent requires clean shell, DNS, TLS, SDK and secret preflight" }
                    val p = checkNotNull(installedProject)
                    installTestResolver(p)
                    // Run the public module from this exact installed SDK before requesting any credential.
                    nodePtyWorkflowCases { argv -> completed(start(p, "/usr/bin/node", argv, jit = true)) }.last().second()
                    p
                }, startInteractive = { p, argv, timeout, cwd, environment, reader ->
                    val key = transientCredential ?: run {
                        agentDiagnostic("linux_dsh_agent_model_file_shell", DshAgentDiagnostic(DshAgentStage.CREDENTIAL_WAIT))
                        DshCredentialBridge.receive(announce = { descriptor ->
                        instrumentation.sendStatus(2, Bundle().apply {
                            putString("id", "SucruneAgentCredential"); putString("test", "linux_dsh_agent_model_file_shell")
                            putInt("current", current); putInt("numtests", total)
                            putString("credential_bridge_descriptor", descriptor.toString())
                        })
                        }, timeoutMs = 60_000).also {
                            transientCredential = it
                            agentDiagnostic("linux_dsh_agent_model_file_shell", DshAgentDiagnostic(DshAgentStage.CREDENTIAL_RECEIVED))
                        }
                    }
                    client.executePathInteractiveStreaming(p, "/usr/bin/node", reader, argv,
                        env + "SUCRUNE_MEMORY_POLICY=linux-jit" + environment + listOf("SUCRUNE_NETWORK_POLICY=outbound",
                        "DEEPSEEK_BASE_URL=https://api.deepseek.com/anthropic"), cwd, timeout,
                        mapOf("DEEPSEEK_API_KEY" to key)).also { executions.add(it) }
                }, target = DshAgentTarget("deepseek-official", "deepseek-flash"),
                    proveReuse = { p -> completed(start(p, "/usr/bin/hello")); Unit }, diagnostic = ::agentDiagnostic
                ).forEach { (name, body) -> case(name, body) }
            }
        } catch (failure: Throwable) { failed++; summary.append(if (realAgentSuite) "Agent validation runner failed\n" else "Runner failed: $failure\n") }
        finally {
            transientCredential?.fill('\u0000')
            transientCredential = null
            var removedToolProjects: Int? = null
            if (::client.isInitialized) {
                executions.forEach { id -> try {
                    if (client.getExecution(id).getString("state") == "running") { client.cancel(id); check(client.waitFor(id, 10_000).getString("state") != "running") }
                } catch (failure: Throwable) { failed++; summary.append(if (realAgentSuite) "Execution cleanup failed\n" else "Cleanup execution: $failure\n") } }
                environments.forEach { id -> try { client.deleteEnvironment(id) } catch (failure: Throwable) {
                    failed++; summary.append(if (realAgentSuite) "Environment cleanup failed\n" else "Cleanup environment: $failure\n")
                } }
                if (arguments.getString("focus") in setOf("toolbox", "compiler", "distro") || arguments.getString("toolbox") == "true") {
                    try {
                        val remaining = client.listEnvironments()
                        check((0 until remaining.length()).none { remaining.getJSONObject(it).getString("id") in environments })
                        removedToolProjects = environments.size
                    } catch (failure: Throwable) { failed++; summary.append("Tool project cleanup verification failed: $failure\n") }
                }
            }
            running.set(false)
            watchdog.interrupt()
            instrumentation.finish(if (passed == total && failed == 0) Activity.RESULT_OK else Activity.RESULT_CANCELED, Bundle().apply {
                putInt("passed", passed); putInt("failed", failed); putInt("expected_tests", total)
                removedToolProjects?.let { putInt("verified_removed_projects", it) }
                putString("probe", "linux"); putString("stream", "\n$summary\nPassed: $passed; failed: $failed\n")
            })
        }
    }
    private fun toolboxExecutor(project: String): ToolboxExec = { path, args, cwd, extra, timeout ->
        val trace = if (arguments.getString("compiler_trace") == "true") listOf("SUCRUNE_TRACE_SYSCALLS=1") else emptyList()
        val defaults = env + trace + listOf("PATH=/usr/bin:/bin", "HOME=/home/agent", "TMPDIR=/tmp", "SHELL=/bin/bash")
        val overrides = extra.map { it.substringBefore('=') }.toSet()
        val started = SystemClock.elapsedRealtime()
        val id = client.executePath(project, path, args, defaults.filterNot { it.substringBefore('=') in overrides } + extra,
            cwd = cwd, timeoutMs = timeout).also { executions.add(it) }
        val gradleDiagnostics = arguments.getString("gradle_threads") == "true" && cwd == "/workspace/gradle-probe"
        val record = if (gradleDiagnostics && args.contains("/opt/gradle/lib/gradle-gradle-cli-main-9.3.1.jar"))
            awaitGradleWithSnapshots(project, cwd, id, timeout + 10_000) else client.waitFor(id, timeout + 10_000)
        if (cwd == "/workspace/gradle-probe" && record.optString("state") != "exited") {
            throw IllegalStateException(gradleOutcome(record, SystemClock.elapsedRealtime() - started, timeout))
        }
        barriers(record)
        val native = record.getJSONObject("result").optJSONObject("native")
        check(record.optString("state") == "exited" && native?.optString("kind") == "linux") {
            "$path ${args.firstOrNull()?.take(40)}: ${record.optString("state")} ${record.optString("stderr").takeLast(800)} " +
                "stage=${native?.optString("stage")} message=${native?.optString("message")} " +
                "errno=${native?.optInt("error_number")} runner_exit=${native?.optInt("runner_exit_code", -1)} runner_signal=${native?.optInt("runner_signal")} " +
                "syscall=${native?.optInt("last_unsupported_syscall")}"
        }
        runnerIdentity(record, 0)
        record
    }

    private fun gradleOutcome(record: JSONObject, elapsed: Long, timeout: Long): String {
        val result = record.optJSONObject("result")
        val native = result?.optJSONObject("native")
        val metadata = JSONObject().put("state", record.optString("state")).put("execution_id", record.optString("execution_id"))
            .put("elapsed_ms", elapsed).put("timeout_ms", timeout)
            .put("failure_reason", result?.opt("failure") ?: JSONObject.NULL)
        for (key in listOf("binder_death_confirmed", "worker_never_started", "run_sent", "output_drained",
            "broker_cleanup_confirmed", "stdin_feeder_completed", "stdout_truncated", "stderr_truncated"))
            result?.opt(key)?.let { metadata.put(key, it) }
        for (key in listOf("stage", "message", "error_number", "runner_waited", "runner_exit_code", "runner_signal",
            "termination_signal", "fatal_signal", "fault_pc", "cleanup_mode", "thread_joined", "threads_created",
            "threads_joined", "threads_live_before_exit", "handler_restored", "fd_peak", "last_unsupported_syscall"))
            native?.opt(key)?.let { metadata.put(key, it) }
        val text = "Gradle workflow $metadata"
        fun bounded(value: String, max: Int): String =
            if (value.length <= max) value else value.take(max / 2) + "\n…\n" + value.takeLast(max / 2)
        return text + "\n" + gradleFailureSummary(record.optString("stdout"), record.optString("stderr")) +
            "\nstdout=\n" + bounded(record.optString("stdout"), 2100) +
            "\nstderr=\n" + bounded(record.optString("stderr"), 2400)
    }

    private fun awaitGradleWithSnapshots(project: String, cwd: String, id: String, timeout: Long): JSONObject {
        val deadline = SystemClock.elapsedRealtime() + timeout
        var previous = ""
        while (true) {
            val remaining = (deadline - SystemClock.elapsedRealtime()).coerceAtLeast(0)
            try {
                return client.waitFor(id, minOf(20_000L, remaining))
            } catch (wait: RuntimeExceptionWithCode) {
                if (wait.code != "wait_timeout" || remaining <= 20_000L) throw wait
            }
            val current = runCatching {
                gradleThreadSnapshots(client, project, cwd).joinToString("\n") { snapshot ->
                    val threads = snapshot.split(Regex("\n(?=[^ \\n])"))
                    threads.take(1).plus(threads.drop(1).filter { it.startsWith("main [") || it.contains("Daemon", true) ||
                        it.contains("lock", true) || it.contains("worker", true) }.take(6))
                        .joinToString("\n") { it.lineSequence().take(5).joinToString("\n") }
                }.take(2000)
            }.getOrDefault("")
            if (current.isNotBlank() && current != previous) {
                previous = current
                instrumentation.sendStatus(2, Bundle().apply {
                    putString("id", "SucruneGradleThreads"); putString("stream", "\nGradle threads\n$current\n")
                })
            }
        }
    }

    private fun installTestResolver(project: String) {
        client.makeDirectory(project, "/etc")
        client.writeFile(project, "/etc/resolv.conf", "nameserver 127.0.0.53\noptions timeout:2 attempts:2\n".toByteArray())
        client.writeFile(project, "/etc/nsswitch.conf", "hosts: files dns\n".toByteArray())
        client.writeFile(project, "/etc/hosts", "127.0.0.1 localhost\n::1 localhost\n".toByteArray())
    }
    private fun start(project: String, path: String, argv: List<String> = emptyList(),
                      timeoutMs: Long = 60_000, stdin: ByteArray = byteArrayOf(), jit: Boolean = false,
                      cwd: String = "/", extraEnv: List<String> = emptyList()) =
        client.executePath(project, path, argv, (if (jit) env + "SUCRUNE_MEMORY_POLICY=linux-jit" else env) + extraEnv,
            cwd = cwd, timeoutMs = timeoutMs, stdin = stdin).also { executions.add(it) }
    private fun startInteractive(project: String, argv: List<String>, timeoutMs: Long,
                                 cwd: String = "/", extraEnv: List<String> = emptyList(),
                                 secretEnv: Map<String, CharArray> = emptyMap()) =
        client.executePathInteractive(project, "/usr/bin/node", argv,
            env + "SUCRUNE_MEMORY_POLICY=linux-jit" + extraEnv, cwd, timeoutMs, secretEnv).also { executions.add(it) }
    private fun importLoop(project: String) {
        val bytes = ByteArray(4096)
        val image = ByteBuffer.wrap(bytes).order(ByteOrder.LITTLE_ENDIAN)
        image.put(byteArrayOf(0x7f, 69, 76, 70, 2, 1, 1))
        image.putShort(16, 2); image.putShort(18, 183); image.putInt(20, 1)
        image.putLong(24, 0x400000L + 256); image.putLong(32, 64)
        image.putShort(52, 64); image.putShort(54, 56); image.putShort(56, 1)
        image.putInt(64, 1); image.putInt(68, 5); image.putLong(80, 0x400000)
        image.putLong(96, 4096); image.putLong(104, 4096); image.putLong(112, 4096)
        image.putInt(256, 0xd2800000.toInt()) // mov x0,#0
        image.putInt(260, 0xd2800728.toInt()) // mov x8,#57 (close)
        image.putInt(264, 0xd4000001.toInt()) // svc #0
        image.putInt(268, 0xd2800020.toInt()) // mov x0,#1
        image.putInt(272, 0x10000181) // adr x1,320 (relative displacement 48)
        val message = loopReady.toByteArray(Charsets.UTF_8)
        image.putInt(276, 0xd2800002.toInt() or (message.size shl 5)) // mov x2,#length
        image.putInt(280, 0xd2800808.toInt()) // mov x8,#64 (write)
        image.putInt(284, 0xd4000001.toInt()) // svc #0
        image.putInt(288, 0x14000000) // b .; no syscall can assist termination
        message.copyInto(bytes, 320)
        val hash = MessageDigest.getInstance("SHA-256").digest(bytes).joinToString("") { "%02x".format(it.toInt() and 255) }
        client.importFile(project, "/runner-loop", bytes.inputStream(), bytes.size.toLong(), hash, executable = true)
    }
    private fun awaitLoop(id: String, timeoutMs: Long) {
        val deadline = SystemClock.elapsedRealtime() + timeoutMs
        while (true) {
            val live = client.getExecution(id)
            check(live.getString("state") == "running") { live.toString() }
            if (live.getString("stdout") == loopReady) return
            check(SystemClock.elapsedRealtime() < deadline) { "Runner did not enter the guest loop: $live" }
            SystemClock.sleep(25)
        }
    }
    private fun barriers(record: JSONObject) {
        val result = record.getJSONObject("result")
        check(result.getBoolean("binder_death_confirmed") && result.getBoolean("run_sent")) { record.toString() }
        check(result.getBoolean("output_drained") && result.getBoolean("broker_cleanup_confirmed") && result.getBoolean("stdin_feeder_completed"))
        val worker = result.getJSONObject("worker")
        check(worker.getString("identity") == "isolated_runtime" && worker.getInt("uid") != Process.myUid() && worker.getInt("uid") != 0)
        check(worker.getInt("pid") != Process.myPid())
    }
    private fun completed(id: String, exit: Int = 0, waitMs: Long = 65_000): JSONObject {
        val record = client.waitFor(id, waitMs)
        check(record.getString("state") == "exited" && record.getInt("exit_code") == exit) { record.toString() }
        barriers(record)
        runnerIdentity(record, 0)
        val native = record.getJSONObject("result").getJSONObject("native")
        check(native.getString("kind") == "linux" && native.getBoolean("on_alt_stack"))
        if (native.optString("cleanup_mode") == "process_exit_group") {
            check(!native.getBoolean("thread_joined") && !native.getBoolean("handler_restored") && native.getBoolean("report_on_host_tls"))
            check(native.getBoolean("runner_waited") && native.getInt("runner_exit_code") == 0)
        } else {
            check(native.getBoolean("host_tls_restored") && native.getBoolean("thread_joined") && native.getBoolean("handler_restored"))
            check(native.getInt("fds_live") == 0 && native.getInt("resources_live") == 0)
        }
        return record
    }
    private fun rejected(id: String, stage: String): JSONObject {
        val record = client.waitFor(id, 65_000)
        check(record.getString("state") == "lost") { record.toString() }
        barriers(record)
        runnerIdentity(record, 1)
        check(record.getJSONObject("result").getJSONObject("native").getString("stage") == stage) { record.toString() }
        return record
    }
    private fun runnerIdentity(record: JSONObject, runnerExit: Int) {
        val result = record.getJSONObject("result")
        val native = result.getJSONObject("native")
        val worker = result.getJSONObject("worker")
        val child = native.getInt("runner_pid")
        val parent = worker.getInt("pid")
        check(native.getBoolean("runner_waited") && native.getInt("runner_exit_code") == runnerExit) { record.toString() }
        check(child > 0 && child != parent && child != Process.myPid() && native.getInt("pid") == child) { record.toString() }
        check(native.getInt("runner_parent_pid") == parent && native.getInt("uid") == worker.getInt("uid")) { record.toString() }
    }
    private fun case(name: String, body: () -> String) {
        if (processTitleOnly && name != "linux_import_upstream" && name != "linux_node_process_title") return
        if (toolOnly && name !in setOf("linux_dsh_profile_prepare", "linux_dsh_profile_install_bundle", "linux_dsh_persistent_bash_tool")) return
        if (focused && name !in setOf("linux_import_upstream", "linux_gnu_bash_builtins", "linux_fork_cancel_session_lease",
                "linux_guest_pselect6_mask_and_readiness", "linux_node_spawn_debian_hello_with_pipes", "linux_node_spawn_bash_with_connected_tcp") &&
            !name.startsWith("linux_node_owned_") && !name.startsWith("linux_guest_fork_") && !name.startsWith("linux_node_pty_") && !name.startsWith("linux_node_live_stdout_")) return
        val firstExecution = executions.size
        current++; publish(1, name, "Starting $name")
        try {
            val observed = body()
            val detail = if (realAgentSuite) "Validated" else observed
            passed++; summary.append("$name: PASS $detail\n"); publish(0, name, detail)
        }
        catch (failure: Throwable) {
            // End this case's owned work before the next case reuses its project.
            // A failure while native exit is still draining must not cascade into
            // misleading environment-conflict failures in unrelated checks.
            executions.drop(firstExecution).forEach { id -> try {
                if (client.getExecution(id).getString("state") == "running") {
                    client.cancel(id)
                    check(client.waitFor(id, 10_000).getString("state") != "running")
                }
            } catch (cleanup: Throwable) { failure.addSuppressed(cleanup) } }
            val detail = if (realAgentSuite) "Validation failed; cleanup_errors=${failure.suppressed.size}" else
                failure.toString() + if (failure.suppressed.isEmpty()) "" else
                    failure.suppressed.joinToString(prefix = "; cleanup failures: ") { it.toString() }
            failed++; summary.append("$name: FAIL $detail\n"); publish(-2, name, detail)
        }
    }
    private fun agentDiagnostic(test: String, diagnostic: DshAgentDiagnostic) {
        require(test in setOf("linux_dsh_agent_prepare", "linux_dsh_agent_model_file_shell",
            "linux_dsh_agent_restart_resume", "linux_dsh_agent_cancel_active_turn"))
        currentOperation = "$test ${diagnostic.stage.name}"
        lastProgress = SystemClock.elapsedRealtime()
        instrumentation.sendStatus(2, Bundle().apply {
            putString("id", "SucruneAgentDiagnostic"); putString("test", test)
            putInt("current", current); putInt("numtests", total)
            putString("stage", diagnostic.stage.name.lowercase())
            putString("safe_reason", diagnostic.reason.name.lowercase())
            putString("error_kind", when (diagnostic.error) {
                DshProviderError.NONE -> "none"
                DshProviderError.OTHER -> "other"
                else -> diagnostic.error.name
            })
            putInt("event_count", diagnostic.eventCount); putInt("tool_count", diagnostic.toolCount)
            putInt("http_status", diagnostic.httpStatus); putInt("rpc_code", diagnostic.rpcCode)
        })
    }
    private fun publish(code: Int, name: String, detail: String) {
        currentOperation = "$name status=$code"
        lastProgress = SystemClock.elapsedRealtime()
        instrumentation.sendStatus(code, Bundle().apply {
        putString("id", "SucruneLinux"); putString("class", LinuxChecks::class.java.name); putString("test", name)
        putInt("current", current); putInt("numtests", total); putString("stream", "\n$name: $detail\n")
        })
    }
}
