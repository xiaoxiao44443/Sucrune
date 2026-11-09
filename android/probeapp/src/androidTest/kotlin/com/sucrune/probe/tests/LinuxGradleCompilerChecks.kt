package com.sucrune.probe.tests

import com.sucrune.probe.RuntimeClient
import org.json.JSONObject
import java.io.ByteArrayOutputStream
import java.util.UUID
import java.util.zip.ZipInputStream

internal const val GRADLE_PROBE_PACKAGE = "dev.sucrune.gradleprobe"
private const val GRADLE_HOME = "/opt/gradle"
private const val ANDROID_SDK = "/opt/android-sdk"
private const val GRADLE_CLI = "$GRADLE_HOME/lib/gradle-gradle-cli-main-9.3.1.jar"
private const val GRADLE_JAVA = "$COMPILER_JAVA_HOME/bin/java"

internal fun gradleThreadSnapshots(client: RuntimeClient, project: String, cwd: String): List<String> {
    val entries = client.listFiles(project, cwd).getJSONArray("entries")
    return (0 until entries.length()).map { entries.getJSONObject(it).getString("name") }
        .filter { it.matches(Regex("gradle-threads-[0-9]+\\.txt")) }.sorted().take(4)
        .map { client.readFile(project, "$cwd/$it").decodeToString().take(16000) }
}

internal fun gradleFailureSummary(stdout: String, stderr: String): String {
    val log = (stderr + "\n" + stdout).lineSequence().filterNot { it.startsWith("[Sucrune Gradle probe]") }.toList()
    val start = log.indexOfFirst { it.trim() == "* What went wrong:" }
    val explanation = if (start < 0) "" else log.drop(start).takeWhile {
        it.trim() !in listOf("* Try:", "* Exception is:", "* Get more help at")
    }.joinToString("\n").take(3500)
    val failures = log.filter { (it.startsWith("> Task ") && it.endsWith(" FAILED")) ||
        it.startsWith("Caused by:") || it.contains("error:", ignoreCase = true) }.distinct().take(12).joinToString("\n")
    return listOf(explanation, failures.take(1800)).filter { it.isNotBlank() }.joinToString("\n")
}

internal fun linuxGradleCompilerCases(
    client: RuntimeClient,
    project: String,
    execute: ToolboxExec,
    buildAndroid: Boolean,
    diagnose: Boolean,
    threadDumps: Boolean,
    traceFaults: Boolean,
    resourcesFirst: Boolean,
    vmMode: String,
    gradleTimeout: Long,
    export: ((ByteArray, String) -> Unit)?
): List<Pair<String, () -> String>> {
    val cwd = "/workspace/gradle-probe"
    require(vmMode in setOf("interpreter", "c1")) { "Unknown gradle_vm: $vmMode" }
    require(gradleTimeout in 1_000L..1_800_000L) { "Invalid gradle_timeout_ms" }
    val c1Checks = if (vmMode == "c1")
        listOf("-XX:+UnlockDiagnosticVMOptions", "-XX:-ImplicitNullChecks") else emptyList()
    val vm = compilerJvmOptions.filterNot { it.startsWith("-Xmx") }
        .map { if (it == "-Xint" && vmMode == "c1") "-XX:TieredStopAtLevel=1" else it } + listOf(
        if (vmMode == "c1") "-Xmx512m" else "-Xmx384m", "-Duser.home=/home/agent", "-Dfile.encoding=UTF-8",
        "-Djdk.lang.Process.launchMechanism=FORK", "-Djava.net.preferIPv4Stack=true") + c1Checks
    // Keep Python's helper processes independent of bytecode caches written by other workflows.
    val pythonEnvironment = listOf("PYTHONDONTWRITEBYTECODE=1", "PYTHONPYCACHEPREFIX=/tmp/gradle-probe-pyc")
    val environment = compilerJavaEnv.filterNot { it.startsWith("LD_LIBRARY_PATH=") } + pythonEnvironment + listOf(
        "LD_LIBRARY_PATH=$COMPILER_JAVA_HOME/lib:$ANDROID_SDK/lib:/lib/aarch64-linux-gnu:/usr/lib/aarch64-linux-gnu",
        "ANDROID_HOME=$ANDROID_SDK", "GRADLE_USER_HOME=/home/agent/.gradle",
        "PATH=$COMPILER_JAVA_HOME/bin:/usr/bin:/bin", "SUCRUNE_NETWORK_POLICY=loopback",
        "SUCRUNE_FD_PROFILE=build") + if (traceFaults) listOf("SUCRUNE_TRACE_FAULTS=1") else emptyList()
    fun write(path: String, content: String) {
        client.makeDirectory(project, "$cwd/$path".substringBeforeLast('/'))
        client.writeFile(project, "$cwd/$path", (content.trimIndent() + "\n").toByteArray())
    }
    fun run(stage: String, path: String, args: List<String>, timeout: Long): JSONObject {
        client.makeDirectory(project, cwd)
        val result = try {
            execute(path, args, cwd, environment, timeout)
        } catch (failure: Exception) {
            throw IllegalStateException("$stage: ${failure.message}", failure)
        }
        val output = result.optString("stdout")
        val errors = result.optString("stderr")
        check(result.optInt("exit_code", -1) == 0) {
            val native = result.optJSONObject("result")?.optJSONObject("native")
            val lastTasks = output.lineSequence().filter { it.startsWith("> Task ") }.toList().takeLast(8)
            "$stage exit=${result.optInt("exit_code", -1)}\n" + gradleFailureSummary(output, errors) + "\ntasks=$lastTasks\n" +
                "fd_peak=${native?.opt("fd_peak")} fd_limit=${native?.opt("fd_limit")} " +
                "fds_live_before_exit=${native?.opt("fds_live_before_exit")} last_unsupported_syscall=${native?.opt("last_unsupported_syscall")}\n" +
                output.takeLast(1800) + "\n" + errors.take(2600) + if (errors.length > 2600) errors.takeLast(900) else ""
        }
        return result
    }
    val traceJar = "$cwd/gradle-thread-probe.jar"
    // Use JDK 17's legacy socket implementation for the Gradle lock listener.
    // The NIO close path requires sibling realtime signals in the guest.
    val gradleVm = vm + "-Djdk.net.usePlainDatagramSocketImpl=true" +
        if (threadDumps) listOf("-javaagent:$traceJar") else emptyList()
    var traceAgentReady = false
    fun prepareTraceAgent() {
        if (!threadDumps || traceAgentReady) return
        write("diagnostic/GradleThreadProbe.java", """
            import java.io.*;
            import java.nio.charset.StandardCharsets;
            import java.util.*;
            public final class GradleThreadProbe {
                public static void premain(String ignored) {
                    Thread sampler = new Thread(() -> {
                        long pid = ProcessHandle.current().pid();
                        File path = new File("$cwd/gradle-threads-" + pid + ".txt");
                        for (;;) {
                            try {
                                Thread.sleep(12000);
                                Map<Thread, StackTraceElement[]> stacks = Thread.getAllStackTraces();
                                List<Thread> threads = new ArrayList<>(stacks.keySet());
                                threads.sort(Comparator.comparingLong(Thread::getId));
                                StringBuilder out = new StringBuilder("pid=" + pid + " command=" +
                                    System.getProperty("sun.java.command", "").split(" ")[0] + "\n");
                                for (Thread t : threads) {
                                    if (t == Thread.currentThread()) continue;
                                    StackTraceElement[] stack = stacks.get(t);
                                    boolean related = t.getName().equals("main");
                                    for (StackTraceElement frame : stack)
                                        if (frame.getClassName().startsWith("org.gradle.")) related = true;
                                    if (!related || out.length() > 20000) continue;
                                    out.append(t.getName()).append(" [").append(t.getState()).append("]\n");
                                    for (int i = 0; i < Math.min(12, stack.length); i++)
                                        out.append("  ").append(stack[i]).append('\n');
                                }
                                byte[] bytes = out.toString().getBytes(StandardCharsets.UTF_8);
                                try (FileOutputStream sink = new FileOutputStream(path)) {
                                    for (int i = 0; i < bytes.length; i += 2048)
                                        sink.write(bytes, i, Math.min(2048, bytes.length - i));
                                }
                            } catch (InterruptedException stopped) { return; }
                              catch (Exception failure) { System.err.println("[Sucrune Gradle probe] " + failure); return; }
                        }
                    }, "sucrune-gradle-sampler");
                    sampler.setDaemon(true);
                    sampler.start();
                }
            }
        """)
        write("diagnostic/MANIFEST.MF", "Manifest-Version: 1.0\nPremain-Class: GradleThreadProbe\n")
        run("Compile optional Gradle stack sampler", GRADLE_JAVA, vm + listOf("-m", "jdk.compiler/com.sun.tools.javac.Main",
            "-d", "diagnostic", "diagnostic/GradleThreadProbe.java"), 90_000)
        run("Package optional Gradle stack sampler", GRADLE_JAVA, vm + listOf("-m", "jdk.jartool/sun.tools.jar.Main",
            "--create", "--file", traceJar, "--manifest", "diagnostic/MANIFEST.MF", "-C", "diagnostic", "GradleThreadProbe.class"), 60_000)
        traceAgentReady = true
    }
    fun lastThreadDumps(): String {
        if (!threadDumps) return ""
        return runCatching {
            gradleThreadSnapshots(client, project, cwd).joinToString("\n", prefix = "\n")
        }.getOrElse { "\nThread snapshot unavailable: ${it.message}" }
    }
    fun gradle(stage: String, options: List<String>): JSONObject {
        prepareTraceAgent()
        val buildTask = options.any { it.startsWith(":app:") }
        val receipt = "$cwd/gradle-build-failure.txt"
        if (buildTask) client.writeFile(project, receipt, byteArrayOf())
        try {
            return run(stage, GRADLE_JAVA, gradleVm + listOf("-Dorg.gradle.native=false",
                "-Dorg.gradle.internal.instrumentation.agent=false", "-jar", GRADLE_CLI,
                "--offline", "--no-daemon", "--no-watch-fs", "--console=plain", "--max-workers=1") +
                (if (buildTask) listOf("--init-script", "$cwd/diagnostic/build-failure.gradle") else emptyList()) + options, gradleTimeout)
        } catch (failure: Exception) {
            val buildFailure = if (buildTask) runCatching {
                client.readFile(project, receipt).decodeToString().take(10000)
            }.getOrDefault("") else ""
            val details = if (buildFailure.isBlank()) failure.message.orEmpty()
                else "$stage build failure:\n$buildFailure\n${failure.message}"
            val dumps = lastThreadDumps()
            if (!diagnose) {
                throw IllegalStateException(details + dumps, failure)
            }
            // Run after the failed JVM exits so this check cannot affect its descriptor budget.
            val inspect = """
                import os, resource, zipfile
                from pathlib import Path
                lib = Path('/opt/gradle/lib')
                with zipfile.ZipFile(lib / 'gradle-launcher-9.3.1.jar') as z:
                    entry = 'org/gradle/launcher/bootstrap/EntryPoint.class' in z.namelist()
                jars = sorted(lib.glob('*.jar'))
                opened = []
                reason = 'all-open'
                try:
                    for p in jars: opened.append(open(p, 'rb'))
                except OSError as error: reason = str(error.errno)
                finally:
                    for f in opened: f.close()
                print('guest class entry=%s, jars=%d, open=%d, rlimit=%r, errno=%s' %
                      (entry, len(jars), len(opened), resource.getrlimit(resource.RLIMIT_NOFILE), reason))
            """.trimIndent()
            val diagnostic = runCatching { run("Inspect Gradle jars", "/usr/bin/python3",
                listOf("-c", inspect), 30_000).getString("stdout").trim() }.getOrElse { "inspection failed: ${it.message}" }
            throw IllegalStateException("$details\n$diagnostic$dumps", failure)
        }
    }
    fun checkDatagram(plain: Boolean): String {
        val mode = if (plain) "plain" else "nio"
        write("DatagramClose.java", """
            import java.net.*;
            import java.util.concurrent.*;
            import java.util.concurrent.atomic.AtomicReference;
            public class DatagramClose {
                public static void main(String[] args) throws Exception {
                    InetAddress loopback = InetAddress.getByName("127.0.0.1");
                    boolean plain = args[0].equals("plain");
                    try (DatagramSocket listener = new DatagramSocket(new InetSocketAddress(loopback, 0));
                         DatagramSocket sender = new DatagramSocket(new InetSocketAddress(loopback, 0))) {
                        byte[] two = { 79, 75 };
                        sender.send(new DatagramPacket(two, two.length, loopback, listener.getLocalPort()));
                        listener.setSoTimeout(2000);
                        DatagramPacket packet = new DatagramPacket(new byte[8], 8);
                        listener.receive(packet);
                        if (packet.getLength() != 2 || packet.getData()[0] != 79 || packet.getData()[1] != 75 ||
                            packet.getPort() != sender.getLocalPort()) throw new AssertionError("UDP round trip");
                    }
                    // Use a freshly bound blocking socket, just as Gradle's lock listener does.
                    DatagramSocket listener = new DatagramSocket(new InetSocketAddress(0));
                    AtomicReference<Throwable> outcome = new AtomicReference<>();
                    Thread reader = new Thread(() -> {
                        try { listener.receive(new DatagramPacket(new byte[1], 1)); }
                        catch (Throwable error) { outcome.set(error); }
                    }, "probe-datagram-reader");
                    reader.setDaemon(true);
                    reader.start();
                    StackTraceElement entered = null;
                    long deadline = System.nanoTime() + TimeUnit.SECONDS.toNanos(2);
                    while (entered == null && System.nanoTime() < deadline) {
                        for (StackTraceElement frame : reader.getStackTrace()) {
                            if (!frame.isNativeMethod()) continue;
                            String name = frame.getClassName();
                            boolean expected = plain ? name.startsWith("java.net.") : name.startsWith("sun.nio.ch.");
                            String operation = frame.getMethodName().toLowerCase(java.util.Locale.ROOT);
                            if (expected && (operation.contains("receive") || operation.contains("poll"))) {
                                entered = frame;
                                break;
                            }
                        }
                        if (entered == null) Thread.sleep(10);
                    }
                    if (entered == null) throw new AssertionError(args[0] + " reader did not enter native receive: " +
                        java.util.Arrays.toString(reader.getStackTrace()), outcome.get());
                    AtomicReference<Throwable> closeFailure = new AtomicReference<>();
                    Thread closer = new Thread(listener::close, "probe-datagram-closer");
                    closer.setUncaughtExceptionHandler((thread, error) -> closeFailure.set(error));
                    closer.setDaemon(true);
                    closer.start();
                    closer.join(2500);
                    reader.join(2500);
                    if (closeFailure.get() != null || closer.isAlive() || reader.isAlive() || !listener.isClosed() ||
                        !(outcome.get() instanceof SocketException)) {
                        throw new AssertionError(args[0] + " entered=" + entered + " close=" + closer.getState() + " read=" + reader.getState() +
                            " result=" + outcome.get() + " reader=" + java.util.Arrays.toString(reader.getStackTrace()) +
                            " closer=" + java.util.Arrays.toString(closer.getStackTrace()), closeFailure.get());
                    }
                    System.out.println("udp-receive-close-ok");
                }
            }
        """)
        run("Compile DatagramSocket probe", GRADLE_JAVA, vm + listOf("-m", "jdk.compiler/com.sun.tools.javac.Main",
            "DatagramClose.java"), 60_000)
        val result = run("DatagramSocket ($mode) close wakes receive", GRADLE_JAVA,
            vm + listOf("-Djdk.net.usePlainDatagramSocketImpl=$plain", "-cp", ".", "DatagramClose", mode), 12_000)
        check(result.optString("stdout").trim() == "udp-receive-close-ok")
        return "Guest JDK 17 ($mode) exchanged real loopback UDP bytes and closed a blocking native receive from a second thread without a close error."
    }
    val cases = mutableListOf<Pair<String, () -> String>>(
        "linux_gradle_build_fd_profile" to {
            val baseline = execute("/usr/bin/python3", listOf("-c",
                "import resource; print(*resource.getrlimit(resource.RLIMIT_NOFILE))"),
                "/workspace", pythonEnvironment, 20_000)
            check(baseline.optInt("exit_code", -1) == 0 && baseline.optString("stdout").trim() == "1024 1024") {
                "Default guest RLIMIT_NOFILE: ${baseline.optString("stdout")} ${baseline.optString("stderr").takeLast(300)}"
            }
            write("verify-exec-fds.py", """
                import errno, os, select
                assert os.read(900, 3) == b'ILE'
                try: os.fstat(901)
                except OSError as error: assert error.errno == errno.EBADF
                else: raise AssertionError('FD_CLOEXEC descriptor survived exec')
                assert select.select([1022], [], [], 0)[0] == [1022]
                poll = select.poll()
                poll.register(1022, select.POLLIN)
                assert poll.poll(0) == [(1022, select.POLLIN)]
                assert os.read(1022, 1) == b'P'
                os.write(1023, b'Q')
            """)
            val probe = """
                import os, resource
                limit = resource.getrlimit(resource.RLIMIT_NOFILE)
                assert limit == (1024, 1024), limit
                fd = os.open('high-fd-file', os.O_CREAT | os.O_RDWR | os.O_TRUNC, 0o600)
                os.write(fd, b'FILE')
                os.lseek(fd, 0, os.SEEK_SET)
                os.dup2(fd, 900, inheritable=True)
                os.dup2(fd, 901, inheritable=False)
                os.close(fd)
                r, w = os.pipe()
                os.dup2(r, 1022, inheritable=True)
                os.dup2(w, 1023, inheritable=True)
                os.close(r)
                os.close(w)
                os.write(1023, b'P')
                pid = os.fork()
                if pid == 0:
                    if os.read(900, 1) != b'F': os._exit(92)
                    os.execv('/usr/bin/python3', ['python3', 'verify-exec-fds.py'])
                reaped, status = os.waitpid(pid, 0)
                assert reaped == pid and os.waitstatus_to_exitcode(status) == 0, status
                assert os.lseek(900, 0, os.SEEK_CUR) == 4 and os.read(1022, 1) == b'Q'
                print('high-fds-ok')
            """.trimIndent()
            val verified = run("Build profile fork/exec high descriptors", "/usr/bin/python3", listOf("-c", probe), 60_000)
            check(verified.optString("stdout").trim() == "high-fds-ok")
            "Linux RLIMIT_NOFILE was 1024 for both profiles. The build guest preserved high regular and pipe descriptors across fork/exec, CLOEXEC, file offset, select and poll."
        },
        "linux_gradle_datagram_close" to { checkDatagram(false) },
        "linux_gradle_plain_datagram_close" to { checkDatagram(true) },
        "linux_gradle_filechannel_transfer" to {
            write("TransferCheck.java", """
                import java.nio.channels.FileChannel;
                import java.nio.file.*;
                import java.util.Arrays;
                import static java.nio.file.StandardOpenOption.*;
                public class TransferCheck {
                    public static void main(String[] args) throws Exception {
                        byte[] data = new byte[256 * 1024 + 13];
                        new java.util.Random(91).nextBytes(data);
                        Path source = Path.of("transfer-source"), target = Path.of("transfer-target");
                        Files.write(source, data);
                        byte[] prefix = {1, 2, 3};
                        Files.write(target, prefix);
                        int offset = 151, count = data.length - offset - 37;
                        try (FileChannel in = FileChannel.open(source, READ);
                             FileChannel out = FileChannel.open(target, WRITE)) {
                            in.position(29);
                            out.position(prefix.length);
                            for (long n = 0; n < count;) {
                                long sent = in.transferTo(offset + n, count - n, out);
                                if (sent <= 0 || sent > count - n) throw new AssertionError("transferTo=" + sent);
                                n += sent;
                            }
                            if (in.position() != 29 || out.position() != prefix.length + count)
                                throw new AssertionError("channel positions: " + in.position() + "/" + out.position());
                        }
                        byte[] expected = Arrays.copyOf(prefix, prefix.length + count);
                        System.arraycopy(data, offset, expected, prefix.length, count);
                        if (!Arrays.equals(expected, Files.readAllBytes(target))) throw new AssertionError("transfer bytes");
                        System.out.println("filechannel-transfer-ok");
                    }
                }
            """)
            run("Compile FileChannel transfer probe", GRADLE_JAVA,
                vm + listOf("-m", "jdk.compiler/com.sun.tools.javac.Main", "TransferCheck.java"), 60_000)
            val result = run("FileChannel.transferTo", GRADLE_JAVA, vm + listOf("-cp", ".", "TransferCheck"), 15_000)
            check(result.getString("stdout").trim() == "filechannel-transfer-ok")
            "Guest JDK FileChannel copied the requested file range, preserved source position and advanced the target."
        },
        "linux_gradle_version" to {
            val output = gradle("Gradle --version", listOf("--version")).getString("stdout")
            check("Gradle 9.3.1" in output && "Kotlin:" in output) { output.takeLast(1300) }
            "The guest OpenJDK launched the original Gradle 9.3.1 CLI."
        },
        "linux_kotlin_compile_run" to {
            val version = "2.2.21"
            val libs = listOf("kotlin-compiler-embeddable-$version", "kotlin-stdlib-$version",
                "kotlin-script-runtime-$version", "kotlin-reflect-$version", "kotlin-daemon-embeddable-$version",
                "kotlinx-coroutines-core-jvm-1.10.2", "annotations-24.0.1")
            val classpath = libs.joinToString(":") { "$GRADLE_HOME/lib/$it.jar" }
            val stdlib = "$GRADLE_HOME/lib/kotlin-stdlib-$version.jar"
            val marker = "guest-kotlin-" + UUID.randomUUID().toString().take(8)
            write("Hello.kt", """fun main() = println("$marker")""")
            run("Kotlin CLI compilation", GRADLE_JAVA, vm + listOf("-cp", classpath,
                "org.jetbrains.kotlin.cli.jvm.K2JVMCompiler", "-no-stdlib", "-no-reflect", "-classpath", stdlib,
                "-jvm-target", "17", "-d", "hello-classes", "Hello.kt"), 240_000)
            val cls = client.readFile(project, "$cwd/hello-classes/HelloKt.class")
            check(cls.take(4) == listOf(0xca, 0xfe, 0xba, 0xbe).map(Int::toByte))
            val out = run("Kotlin class execution", GRADLE_JAVA, vm + listOf("-cp", "hello-classes:$stdlib", "HelloKt"), 60_000)
            check(out.getString("stdout").trim() == marker)
            "Guest Kotlin $version compiled a fresh JVM 17 class; a second guest JVM executed its run-specific output."
        }
    )
    if (buildAndroid) cases += "linux_gradle_zipflinger" to {
        val jar = "/opt/maven/com/android/zipflinger/9.1.1/zipflinger-9.1.1.jar"
        write("ZipflingerCheck.java", """
            import com.android.zipflinger.*;
            import java.io.*;
            import java.nio.ByteBuffer;
            import java.nio.channels.FileChannel;
            import java.nio.file.*;
            import java.util.Arrays;
            import java.util.zip.*;
            public class ZipflingerCheck {
                static long crc(byte[] data) {
                    CRC32 sum = new CRC32();
                    sum.update(data);
                    return sum.getValue();
                }
                static boolean compare(String label, byte[] expected, byte[] actual) {
                    int diff = Arrays.mismatch(expected, actual);
                    System.out.println(label + " bytes=" + actual.length + " crc=" + crc(actual) +
                        " firstDiff=" + diff + (diff >= 0 && diff < actual.length && diff < expected.length ?
                            " expected=" + (expected[diff] & 255) + " actual=" + (actual[diff] & 255) : ""));
                    return diff == -1;
                }
                static boolean inspect(Path path, String name, byte[] data) throws IOException {
                    boolean valid = false;
                    try (ZipFile zip = new ZipFile(path.toFile())) {
                        System.out.println(path + " size=" + Files.size(path) + " entries=" + zip.size());
                        zip.stream().limit(4).forEach(e -> System.out.println("  " + e.getName() +
                            " size=" + e.getSize() + " compressed=" + e.getCompressedSize() + " crc=" + e.getCrc()));
                        ZipEntry e = zip.getEntry(name);
                        if (e != null) try (InputStream stream = zip.getInputStream(e)) {
                            valid = compare(path + "/ZipFile", data, stream.readAllBytes()) &&
                                zip.size() == 1 && e.getSize() == data.length && e.getCrc() == crc(data);
                        }
                    } catch (IOException error) { System.out.println(path + "/ZipFile error=" + error); }
                    ByteArrayOutputStream bytes = new ByteArrayOutputStream();
                    try (ZipInputStream stream = new ZipInputStream(Files.newInputStream(path))) {
                        ZipEntry e = stream.getNextEntry();
                        valid &= e != null && name.equals(e.getName());
                        byte[] chunk = new byte[8192];
                        int count;
                        while ((count = stream.read(chunk)) != -1) bytes.write(chunk, 0, count);
                        valid &= stream.getNextEntry() == null;
                    } catch (IOException error) {
                        System.out.println(path + "/ZipInputStream error=" + error);
                        valid = false;
                    }
                    return compare(path + "/ZipInputStream", data, bytes.toByteArray()) && valid;
                }
                static void compareIoSizes(byte[] data) throws IOException {
                    Path test = Path.of("zip-channel-io");
                    try (FileChannel ch = FileChannel.open(test, StandardOpenOption.CREATE,
                            StandardOpenOption.TRUNCATE_EXISTING, StandardOpenOption.READ, StandardOpenOption.WRITE)) {
                        int singleWrite = ch.write(ByteBuffer.wrap(data));
                        ch.position(0);
                        int smallestWrite = 8192;
                        for (int i = 0; i < data.length;) {
                            int requested = Math.min(8192, data.length - i);
                            int wrote = ch.write(ByteBuffer.wrap(data, i, requested));
                            if (wrote <= 0) throw new IOException("zero-length progress on regular file");
                            if (requested == 8192) smallestWrite = Math.min(smallestWrite, wrote);
                            i += wrote;
                        }
                        ch.position(0);
                        ByteBuffer back = ByteBuffer.allocate(data.length);
                        int singleRead = ch.read(back);
                        while (back.hasRemaining() && ch.read(back) > 0) {}
                        System.out.println("FileChannel requested=" + data.length + " singleWrite=" + singleWrite +
                            " min8kWrite=" + smallestWrite + " singleRead=" + singleRead);
                        if (!compare("8k-written file", data, Arrays.copyOf(back.array(), back.position())))
                            throw new AssertionError("8k-written file");
                    }
                }
                public static void main(String[] args) throws Exception {
                    byte[] data = new byte[1024 * 1024 + 13];
                    new java.util.Random(91).nextBytes(data);
                    Path source = Path.of("input.zip"), target = Path.of("output.zip");
                    System.out.println("expected bytes=" + data.length + " crc=" + crc(data));
                    compareIoSizes(data);
                    try (ZipArchive archive = new ZipArchive(source)) {
                        archive.add(new BytesSource(data, "payload", 0));
                    }
                    boolean valid = inspect(source, "payload", data);
                    ZipSource selected = new ZipSource(source);
                    selected.select("payload", "assets/payload");
                    try (ZipArchive archive = new ZipArchive(target)) { archive.add(selected); }
                    valid &= inspect(target, "assets/payload", data);
                    if (!valid) throw new AssertionError("zipflinger archive content");
                    System.out.println("zipflinger-ok");
                }
            }
        """)
        run("Compile AGP zipflinger probe", GRADLE_JAVA, vm + listOf("-m", "jdk.compiler/com.sun.tools.javac.Main",
            "-cp", jar, "ZipflingerCheck.java"), 60_000)
        val result = run("AGP zipflinger archive copy", GRADLE_JAVA,
            vm + listOf("-cp", ".:$jar", "ZipflingerCheck"), 15_000)
        check(result.getString("stdout").trim().endsWith("zipflinger-ok"))
        "Guest AGP zipflinger wrote and copied an uncompressed entry, verified by the JDK ZIP reader."
    }
    if (buildAndroid) cases += "linux_gradle_kotlin_apk" to {
        val marker = "Sucrune Kotlin " + UUID.randomUUID().toString().take(8)
        write("settings.gradle", """
            pluginManagement { repositories { maven { url = uri('/opt/maven') } } }
            dependencyResolutionManagement { repositories { maven { url = uri('/opt/maven') } } }
            rootProject.name = 'SucruneGuest'
            include ':app'
        """)
        write("gradle.properties", """
            org.gradle.jvmargs=${gradleVm.joinToString(" ")}
            org.gradle.workers.max=1
            org.gradle.parallel=false
            org.gradle.java.installations.auto-detect=false
            org.gradle.java.installations.auto-download=false
            kotlin.compiler.execution.strategy=in-process
            kotlin.incremental=false
            android.aapt2FromMavenOverride=$ANDROID_SDK/build-tools/36.0.0/aapt2
            android.useAndroidX=true
        """)
        write("app/build.gradle", """
            plugins { id 'com.android.application' version '9.1.1' }
            android {
                namespace '$GRADLE_PROBE_PACKAGE'
                compileSdk { version = release(37) }
                buildToolsVersion '36.0.0'
                defaultConfig {
                    applicationId '$GRADLE_PROBE_PACKAGE'
                    minSdk 29
                    targetSdk 35
                    versionCode 1
                    versionName '1'
                }
            }
        """)
        write("app/src/main/AndroidManifest.xml", """
            <manifest xmlns:android="http://schemas.android.com/apk/res/android">
              <application android:label="Sucrune Kotlin probe">
                <activity android:name=".MainActivity" android:exported="true">
                  <intent-filter>
                    <action android:name="android.intent.action.MAIN"/>
                    <category android:name="android.intent.category.LAUNCHER"/>
                  </intent-filter>
                </activity>
              </application>
            </manifest>
        """)
        write("app/src/main/kotlin/dev/sucrune/gradleprobe/MainActivity.kt", """
            package $GRADLE_PROBE_PACKAGE

            import android.app.Activity
            import android.os.Bundle
            import android.widget.TextView

            class MainActivity : Activity() {
                override fun onCreate(savedInstanceState: Bundle?) {
                    super.onCreate(savedInstanceState)
                    setContentView(TextView(this).apply { text = "$marker" })
                }
            }
        """)
        write("diagnostic/build-failure.gradle", """
            gradle.buildFinished { result ->
                if (result.failure == null) return
                def queue = new ArrayDeque()
                def visited = Collections.newSetFromMap(new IdentityHashMap())
                def ordered = []
                queue.add([result.failure, 0])
                while (!queue.isEmpty() && visited.size() < 64) {
                    def entry = queue.removeFirst()
                    def (cause, depth) = entry
                    if (!visited.add(cause)) continue
                    ordered.add(entry)
                    def next = [cause.cause]
                    if (cause.metaClass.respondsTo(cause, 'getCauses')) next.addAll(cause.getCauses())
                    next.addAll(cause.suppressed.toList())
                    next.findAll { it != null }.each { queue.addLast([it, depth + 1]) }
                }
                ordered.sort { a, b -> b[1] <=> a[1] }
                def lines = []
                ordered.take(5).each { entry ->
                    def cause = entry[0]
                    lines.add(cause.class.name + ': ' + (cause.message ?: '').take(640))
                    cause.stackTrace.take(12).each { frame -> lines.add('  at ' + frame.toString()) }
                }
                def receipt = new ByteArrayOutputStream()
                for (def line : lines) {
                    def encoded = (line + '\n').getBytes('UTF-8')
                    if (receipt.size() + encoded.length >= 8000) break
                    receipt.write(encoded, 0, encoded.length)
                }
                def bytes = receipt.toByteArray()
                new File('$cwd/gradle-build-failure.txt').withOutputStream { out ->
                    for (int pos = 0; pos < bytes.length; pos += 2048)
                        out.write(bytes, pos, Math.min(2048, bytes.length - pos))
                }
            }
        """)
        if (resourcesFirst) {
            val resources = gradle(":app:processDebugResources", listOf(":app:processDebugResources"))
            val progress = resources.getString("stdout")
            check("BUILD SUCCESSFUL" in progress && ":app:processDebugResources" in progress) {
                "Missing resource processing result: ${progress.takeLast(900)}"
            }
        }
        val build = gradle(":app:assembleDebug", listOf(":app:assembleDebug"))
        val stdout = build.getString("stdout")
        check("BUILD SUCCESSFUL" in stdout && ":app:compileDebugKotlin" in stdout && ":app:packageDebug" in stdout) {
            "Gradle did not report Kotlin compilation, APK packaging and build success: ${stdout.takeLast(900)}"
        }
        val apkPath = "app/build/outputs/apk/debug/app-debug.apk"
        // file.read is bounded to 1 MiB; split the produced APK into ordinary project files for export.
        val split = """
            from pathlib import Path
            import hashlib
            p = Path('$apkPath')
            total = p.stat().st_size
            assert 0 < total <= 16 * 1024 * 1024
            digest = hashlib.sha256()
            count = 0
            with p.open('rb') as src:
                while chunk := src.read(512 * 1024):
                    digest.update(chunk)
                    Path('apk-part-%d' % count).write_bytes(chunk)
                    count += 1
            print(count, total, digest.hexdigest())
        """.trimIndent()
        val receipt = run("Read built APK", "/usr/bin/python3", listOf("-c", split), 60_000).getString("stdout").trim().split(' ')
        val size = receipt[1].toInt()
        check(size in 1..16 * 1024 * 1024 && receipt[0].toInt() == (size + 524287) / 524288)
        val apk = ByteArrayOutputStream(size).use { out ->
            repeat(receipt[0].toInt()) { out.write(client.readFile(project, "$cwd/apk-part-$it")) }
            out.toByteArray()
        }
        val sha = java.security.MessageDigest.getInstance("SHA-256").digest(apk).joinToString("") { "%02x".format(it) }
        check(size == apk.size && receipt[2] == sha)
        var found = false
        ZipInputStream(apk.inputStream()).use { zip ->
            while (true) {
                val entry = zip.nextEntry ?: break
                if (entry.name.matches(Regex("classes(?:[0-9]+)?\\.dex"))) {
                    val dex = zip.readBytes().toString(Charsets.ISO_8859_1)
                    found = found || (dex.startsWith("dex\n") && "Ldev/sucrune/gradleprobe/MainActivity;" in dex && marker in dex)
                }
            }
        }
        check(found) { "Packaged DEX does not contain the Kotlin Activity and run-specific marker" }
        export?.invoke(apk, marker)
        "Guest Gradle 9.3.1 and AGP 9.1.1 compiled Kotlin and packaged a debug APK ($size bytes, sha256=$sha)."
    }
    return cases
}
