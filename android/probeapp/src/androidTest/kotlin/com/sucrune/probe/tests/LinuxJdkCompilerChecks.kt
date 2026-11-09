package com.sucrune.probe.tests

import com.sucrune.probe.RuntimeClient
import org.json.JSONObject

internal const val COMPILER_JAVA_HOME = "/usr/lib/jvm/java-17-openjdk-arm64"

// Keep the public JVM tool defaults small enough for this foreground test device.
internal val compilerJvmOptions = listOf("-Xint", "-Xshare:off", "-Xms16m", "-Xmx160m",
    "-XX:+UseSerialGC", "-XX:ActiveProcessorCount=1", "-XX:-UseContainerSupport",
    "-XX:-UseCompressedOops", "-XX:-UseCompressedClassPointers", "-XX:-UsePerfData",
    "-Djava.awt.headless=true", "-Djava.security.egd=file:/dev/urandom",
    "-XX:ErrorFile=/workspace/jdk-vm-error.log")

internal val compilerJavaEnv = listOf("JAVA_HOME=$COMPILER_JAVA_HOME", "SUCRUNE_MEMORY_POLICY=linux-jit",
    "LD_LIBRARY_PATH=$COMPILER_JAVA_HOME/lib:/lib/aarch64-linux-gnu:/usr/lib/aarch64-linux-gnu")

internal fun linuxJdkCompilerCases(client: RuntimeClient, project: String, execute: ToolboxExec, zero: Boolean): List<Pair<String, () -> String>> {
    val cwd = "/workspace/jdk-compile"
    fun run(binary: String, arguments: List<String>, timeout: Long): JSONObject {
        val vm = if (binary == "javac") compilerJvmOptions.map { "-J$it" } else compilerJvmOptions
        val record = execute("$COMPILER_JAVA_HOME/bin/$binary", vm + arguments, cwd, compilerJavaEnv, timeout)
        check(record.optInt("exit_code", -1) == 0) {
            "$binary failed with ${record.optInt("exit_code", -1)}. " +
                (record.optString("stderr") + record.optString("stdout")).takeLast(1400)
        }
        return record
    }
    return listOf(
        "jdk_openjdk_version" to {
            client.makeDirectory(project, cwd)
            val result = run("java", listOf("-version"), 60_000)
            val version = result.getString("stderr")
            val vm = if (zero) "OpenJDK 64-Bit Zero VM" else "OpenJDK 64-Bit Server VM"
            check(version.contains("openjdk version \"17.0.21\"") && version.contains(vm)) { version.takeLast(800) }
            version.lineSequence().first { it.contains(vm) }
        },
        "jdk_javac_class_and_execute" to {
            client.makeDirectory(project, cwd)
            val source = """
                public final class GuestJavac {
                    public static void main(String[] args) {
                        java.security.SecureRandom rng = new java.security.SecureRandom();
                        if (!"NativePRNG".equals(rng.getAlgorithm()) || rng.generateSeed(32).length != 32) {
                            throw new AssertionError("Default SecureRandom must use the Linux device provider");
                        }
                        System.out.println("guest-javac-" + Integer.parseInt(args[0]) * 7);
                    }
                }
            """.trimIndent().toByteArray()
            client.writeFile(project, "$cwd/GuestJavac.java", source)
            run("javac", listOf("--release", "17", "-d", ".", "GuestJavac.java"), 120_000)
            val cls = client.readFile(project, "$cwd/GuestJavac.class")
            check(cls.size > 8 && cls.take(8) == listOf(0xca, 0xfe, 0xba, 0xbe, 0, 0, 0, 61).map { it.toByte() })
            val result = run("java", listOf("-cp", ".", "GuestJavac", "6"), 60_000)
            check(result.optString("stdout").trim() == "guest-javac-42")
            "Guest javac emitted a Java 17 class; a second guest JVM executed it and read NativePRNG seed bytes."
        }
    )
}
