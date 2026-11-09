package com.sucrune.probe.tests

import com.sucrune.probe.RuntimeClient
import java.util.UUID
import java.util.zip.ZipInputStream

internal fun linuxAaptDaemonCase(client: RuntimeClient, project: String, execute: ToolboxExec): Pair<String, () -> String> =
    "linux_jdk_aapt2_daemon" to {
        val cwd = "/workspace/aapt-daemon-${UUID.randomUUID().toString().take(8)}"
        val sdk = "/opt/android-sdk"
        val binary = "$sdk/build-tools/36.0.0/aapt2"
        val framework = "$sdk/platforms/android-37.0/android.jar"
        client.makeDirectory(project, "$cwd/res/values")
        fun write(name: String, text: String) = client.writeFile(project, "$cwd/$name", text.trimIndent().toByteArray())
        write("AndroidManifest.xml", """<manifest xmlns:android="http://schemas.android.com/apk/res/android"
            package="dev.sucrune.aaptprobe"><application android:label="@string/probe_label"/></manifest>""")
        write("res/values/strings.xml", """<resources><string name="probe_label">daemon-pipe</string></resources>""")
        write("GuestAaptDaemon.java", """
            import java.io.*;
            import java.net.*;
            import java.nio.channels.DatagramChannel;
            import java.nio.charset.StandardCharsets;
            import java.util.ArrayList;
            import java.util.List;
            import java.util.concurrent.*;

            public final class GuestAaptDaemon {
                static BlockingQueue<String> drain(InputStream stream, String name) {
                    BlockingQueue<String> lines = new LinkedBlockingQueue<>();
                    Thread reader = new Thread(() -> {
                        try (BufferedReader in = new BufferedReader(new InputStreamReader(stream, StandardCharsets.UTF_8))) {
                            String line;
                            while ((line = in.readLine()) != null) {
                                System.out.println(name + " " + line);
                                lines.add(line);
                            }
                        } catch (IOException ex) { System.out.println(name + " pipe: " + ex); }
                        finally { lines.add("<EOF>"); }
                    }, name);
                    reader.setDaemon(true);
                    reader.start();
                    return lines;
                }
                static void expect(BlockingQueue<String> lines, String expected, String label) throws Exception {
                    long deadline = System.nanoTime() + TimeUnit.SECONDS.toNanos(20);
                    for (;;) {
                        String line = lines.poll(Math.max(0, deadline - System.nanoTime()), TimeUnit.NANOSECONDS);
                        if (expected.equals(line)) return;
                        if (line == null || line.equals("<EOF>") || line.equals("Error"))
                            throw new IOException(label + ": expected " + expected + ", saw " + line);
                    }
                }
                static void command(BufferedWriter in, String... args) throws IOException {
                    for (String arg : args) { in.write(arg); in.write('\n'); }
                    in.write('\n'); in.flush();
                }
                static void build(String label, String binary, String framework) throws Exception {
                    System.out.println(label + " ProcessBuilder.start");
                    Process child = new ProcessBuilder(binary, "daemon").start();
                    try {
                        BlockingQueue<String> out = drain(child.getInputStream(), label + " stdout");
                        BlockingQueue<String> err = drain(child.getErrorStream(), label + " stderr");
                        try (BufferedWriter in = new BufferedWriter(new OutputStreamWriter(child.getOutputStream(), StandardCharsets.UTF_8))) {
                            expect(out, "Ready", label + " startup");
                            System.out.println(label + " compile");
                            String compiled = new File(label + ".zip").getAbsolutePath();
                            command(in, "compile", new File("res/values/strings.xml").getAbsolutePath(), "-o", compiled);
                            expect(err, "Done", label + " compile");
                            System.out.println(label + " link");
                            command(in, "link", "--manifest", new File("AndroidManifest.xml").getAbsolutePath(),
                                "-I", framework, "-o", new File(label + ".apk").getAbsolutePath(), compiled);
                            expect(err, "Done", label + " link");
                            command(in, "quit");
                        }
                        if (!child.waitFor(10, TimeUnit.SECONDS) || child.exitValue() != 0)
                            throw new IOException(label + ": daemon failed to exit normally");
                        expect(out, "Exiting daemon", label + " shutdown");
                        System.out.println(label + " complete");
                    } finally {
                        if (child.isAlive()) child.destroyForcibly();
                    }
                }
                static void checkSocket(String label, DatagramSocket listener, String[] args) throws Exception {
                        listener.bind(new InetSocketAddress(InetAddress.getByName("127.0.0.1"), 0));
                        if (!listener.isBound() || listener.getSoTimeout() != 0) throw new IOException("blocking UDP bind failed");
                        System.out.println(label + " blocking UDP bound");
                        build(label, args[0], args[1]);
                        try (DatagramSocket sender = new DatagramSocket()) {
                            sender.send(new DatagramPacket(new byte[]{79}, 1, listener.getLocalSocketAddress()));
                            listener.setSoTimeout(3000);
                            DatagramPacket reply = new DatagramPacket(new byte[1], 1);
                            listener.receive(reply);
                            if (reply.getLength() != 1 || reply.getData()[0] != 79) throw new IOException("parent UDP mismatch");
                        }
                        System.out.println(label + " parent UDP survived");
                }
                public static void main(String[] args) throws Exception {
                    boolean plain = false, socket = false, high = false;
                    try { build("plain", args[0], args[1]); plain = true; }
                    catch (Exception ex) { System.err.println("plain failed"); ex.printStackTrace(); }
                    try (DatagramSocket listener = new DatagramSocket(null)) {
                        checkSocket("socket", listener, args); socket = true;
                    } catch (Exception ex) { System.err.println("socket failed"); ex.printStackTrace(); }
                    List<FileInputStream> held = new ArrayList<>();
                    try {
                        for (int i = 0; i < 280; i++) held.add(new FileInputStream("AndroidManifest.xml"));
                        try (DatagramChannel channel = DatagramChannel.open(StandardProtocolFamily.INET)) {
                            if (System.getProperty("os.name").equals("Linux")) {
                                // Inspect the logical Linux fd from this pinned JDK. The class exists in Java 17.
                                int fd = (Integer)Class.forName("sun.nio.ch.SelChImpl").getMethod("getFDVal").invoke(channel);
                                System.out.println("high 280 files held, UDP fd=" + fd);
                                if (fd < 256) throw new IOException("UDP fd below high descriptor threshold");
                            }
                            checkSocket("high", channel.socket(), args); high = true;
                        }
                    } catch (Exception ex) { System.err.println("high failed"); ex.printStackTrace(); }
                    finally { for (FileInputStream input : held) input.close(); }
                    if (!plain || !socket || !high)
                        throw new IOException("plain=" + plain + " socket=" + socket + " high=" + high);
                }
            }
        """)
        val vm = compilerJvmOptions + listOf("-Djdk.lang.Process.launchMechanism=FORK", "-Djava.net.preferIPv4Stack=true",
            "--add-exports=java.base/sun.nio.ch=ALL-UNNAMED")
        val environment = compilerJavaEnv + listOf("SUCRUNE_NETWORK_POLICY=loopback", "SUCRUNE_FD_PROFILE=build")
        fun java(stage: String, args: List<String>, timeout: Long): String {
            val result = execute("$COMPILER_JAVA_HOME/bin/java", vm + args, cwd, environment, timeout)
            val out = result.optString("stdout")
            check(result.optInt("exit_code", -1) == 0) {
                val native = result.optJSONObject("result")?.optJSONObject("native")
                "$stage exit=${result.optInt("exit_code", -1)} fd_peak=${native?.opt("fd_peak")}\n" +
                    out.takeLast(1700) + "\n" + result.optString("stderr").takeLast(2200)
            }
            return out
        }
        java("Compile ProcessBuilder fixture", listOf("-m", "jdk.compiler/com.sun.tools.javac.Main", "-d", ".", "GuestAaptDaemon.java"), 90_000)
        val out = java("Run AAPT2 daemon", listOf("-cp", ".", "GuestAaptDaemon", binary, framework), 150_000)
        for (label in listOf("plain", "socket", "high")) {
            check(out.contains("$label complete")) { out.takeLast(700) }
            val entries = mutableMapOf<String, ByteArray>()
            ZipInputStream(client.readFile(project, "$cwd/$label.apk").inputStream()).use { zip ->
                while (true) {
                    val entry = zip.nextEntry ?: break
                    if (entry.name in setOf("AndroidManifest.xml", "resources.arsc")) entries[entry.name] = zip.readBytes()
                }
            }
            check(entries["AndroidManifest.xml"]?.take(4) == listOf<Byte>(3, 0, 8, 0)) { "$label missing binary manifest" }
            check(entries["resources.arsc"]?.take(2) == listOf<Byte>(2, 0)) { "$label missing resource table" }
        }
        val highFd = out.lineSequence().first { it.startsWith("high 280 files held, UDP fd=") }
        "Guest JDK FORK built three AAPT2 resource APKs over separate pipes, including blocking UDP with $highFd."
    }
