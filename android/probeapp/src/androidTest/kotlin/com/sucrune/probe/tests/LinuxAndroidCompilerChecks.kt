package com.sucrune.probe.tests

import com.sucrune.probe.RuntimeClient
import org.json.JSONObject
import java.util.UUID
import java.util.zip.ZipInputStream

/** All APK mutations run in the guest. The test client independently reads the resulting bytes. */
internal fun linuxAndroidCompilerCases(
    client: RuntimeClient, project: String, execute: ToolboxExec, includeKotlin: Boolean,
    export: ((ByteArray, String) -> Unit)? = null
): List<Pair<String, () -> String>> {
    val sdk = "/opt/android-sdk"
    val packageId = "dev.sucrune.compiled"
    val nativeEnvironment = listOf("LD_LIBRARY_PATH=$sdk/lib:/lib/aarch64-linux-gnu:/usr/lib/aarch64-linux-gnu")
    fun run(path: String, args: List<String>, cwd: String, environment: List<String>, timeout: Long = 60_000L): JSONObject {
        val record = execute(path, args, cwd, environment, timeout)
        check(record.optString("state") == "exited" && record.optInt("exit_code", -1) == 0) {
            "${path.substringAfterLast('/')} ${args.take(3).joinToString(" ")}: " +
                "${record.optString("state")} exit=${record.optInt("exit_code", -1)} " +
                record.optString("stderr").takeLast(1700) + " " + record.optString("stdout").takeLast(500)
        }
        return record
    }
    fun write(cwd: String, path: String, source: String) {
        client.writeFile(project, "$cwd/$path", source.trimIndent().toByteArray())
    }
    fun tool(cwd: String, program: String, vararg args: String) =
        run("$sdk/bin/$program", args.toList(), cwd, nativeEnvironment)
    fun java(cwd: String, vararg args: String): JSONObject {
        try {
            return run("$COMPILER_JAVA_HOME/bin/java", compilerJvmOptions + args.toList(), cwd, compilerJavaEnv, 240_000L)
        } catch (error: Exception) {
            throw IllegalStateException("java ${args.take(3).joinToString(" ")}: ${error.message}", error)
        }
    }
    fun entries(cwd: String, file: String): Map<String, ByteArray> {
        val map = mutableMapOf<String, ByteArray>()
        ZipInputStream(client.readFile(project, "$cwd/$file").inputStream()).use { zip ->
            while (true) {
                val entry = zip.nextEntry ?: break
                check(map.put(entry.name, zip.readBytes()) == null)
            }
        }
        return map
    }
    fun resources(cwd: String, hasCode: Boolean) {
        listOf("res/values", "res/layout").forEach { client.makeDirectory(project, "$cwd/$it") }
        write(cwd, "res/values/strings.xml", """<resources><string name="app_name">Sucrune Build Probe</string></resources>""")
        write(cwd, "res/layout/main.xml", """
            <TextView xmlns:android="http://schemas.android.com/apk/res/android"
                android:layout_width="match_parent" android:layout_height="wrap_content" android:text="@string/app_name" />
        """)
        val activity = if (hasCode) """<activity android:name=".MainActivity" android:exported="true" />""" else ""
        write(cwd, "AndroidManifest.xml", """
            <manifest xmlns:android="http://schemas.android.com/apk/res/android" package="$packageId"
                android:versionCode="1" android:versionName="1">
                <uses-sdk android:minSdkVersion="29" android:targetSdkVersion="35" />
                <application android:hasCode="$hasCode" android:label="@string/app_name">$activity</application>
            </manifest>
        """)
        tool(cwd, "aapt2", "compile", "--dir", "res", "-o", "compiled.zip")
        val compiled = entries(cwd, "compiled.zip").keys
        check(compiled.any { it.endsWith("main.xml.flat") } && compiled.any { it.endsWith("strings.arsc.flat") }) { compiled.toString() }
        tool(cwd, "aapt2", "link", "-o", "unaligned.apk", "-I", "$sdk/platform/framework-res.apk",
            "--manifest", "AndroidManifest.xml", "compiled.zip")
        val apk = entries(cwd, "unaligned.apk")
        check(apk.getValue("AndroidManifest.xml").take(4) == listOf<Byte>(3, 0, 8, 0))
        check(apk.getValue("resources.arsc").take(2) == listOf<Byte>(2, 0))
        check(apk.containsKey("res/layout/main.xml") && !apk.containsKey("classes.dex"))
        val badging = tool(cwd, "aapt", "dump", "badging", "unaligned.apk").getString("stdout")
        check("package: name='$packageId'" in badging && "Sucrune Build Probe" in badging &&
            "targetSdkVersion:'35'" in badging) { badging.take(1200) }
    }
    fun signedActivity(kotlin: Boolean): String {
        val cwd = if (kotlin) "/workspace/android-kotlin-build" else "/workspace/android-java-build"
        listOf("src", "classes", "dex").forEach { client.makeDirectory(project, "$cwd/$it") }
        val androidJar = "$sdk/platform/android.jar"
        val marker = if (kotlin) "Sucrune Kotlin SDK " + UUID.randomUUID() else "Sucrune Build Probe"
        if (kotlin) {
            write(cwd, "src/MainActivity.kt", """
                package dev.sucrune.compiled
                class MainActivity : android.app.Activity() {
                    override fun onCreate(state: android.os.Bundle?) {
                        super.onCreate(state)
                        val label = android.widget.TextView(this)
                        label.text = "$marker"
                        setContentView(label)
                    }
                }
            """)
            val libs = "/opt/gradle/lib"
            val stdlib = "$libs/kotlin-stdlib-2.2.21.jar"
            val compiler = listOf("kotlin-compiler-embeddable-2.2.21", "kotlin-stdlib-2.2.21",
                "kotlin-reflect-2.2.21", "kotlin-script-runtime-2.2.21", "kotlin-daemon-embeddable-2.2.21",
                "kotlinx-coroutines-core-jvm-1.10.2", "annotations-24.0.1").joinToString(":") { "$libs/$it.jar" }
            val vm = compilerJvmOptions.filterNot { it.startsWith("-Xmx") } + "-Xmx384m"
            run("$COMPILER_JAVA_HOME/bin/java", vm + listOf("-cp", compiler,
                "org.jetbrains.kotlin.cli.jvm.K2JVMCompiler", "-no-stdlib", "-no-reflect", "-jvm-target", "1.8",
                "-no-jdk", "-classpath", "$androidJar:$stdlib", "-d", "classes", "src/MainActivity.kt"),
                cwd, compilerJavaEnv + "SUCRUNE_FD_PROFILE=build", 240_000L)
        } else {
            write(cwd, "src/MainActivity.java", """
                package dev.sucrune.compiled;
                public final class MainActivity extends android.app.Activity {
                    @Override public void onCreate(android.os.Bundle state) {
                        super.onCreate(state);
                        setContentView(getResources().getIdentifier("main", "layout", getPackageName()));
                    }
                }
            """)
            java(cwd, "-m", "jdk.compiler/com.sun.tools.javac.Main", "--release", "8", "-classpath", androidJar,
                "-d", "classes", "src/MainActivity.java")
        }
        val classFile = "classes/dev/sucrune/compiled/MainActivity.class"
        check(client.readFile(project, "$cwd/$classFile").take(4) == listOf(0xca, 0xfe, 0xba, 0xbe).map(Int::toByte))
        java(cwd, "-cp", "$sdk/lib/d8.jar", "com.android.tools.r8.D8", "--min-api", "29", "--lib", androidJar,
            "--output", "dex", classFile)
        val dex = client.readFile(project, "$cwd/dex/classes.dex")
        check(dex.size >= 112 && dex.copyOfRange(0, 4).decodeToString() == "dex\n")
        check(dex.toString(Charsets.ISO_8859_1).contains("Ldev/sucrune/compiled/MainActivity;"))
        if (kotlin) {
            val strings = dex.toString(Charsets.ISO_8859_1)
            check("Lkotlin/Metadata;" in strings && marker in strings) { "Missing Kotlin class metadata or this build’s UI text in DEX" }
        }
        resources(cwd, true)
        tool("$cwd/dex", "zip", "-X", "-q", "-0", "../unaligned.apk", "classes.dex")
        tool(cwd, "zipalign", "-f", "4", "unaligned.apk", "aligned.apk")
        // A disposable test identity is generated inside this project.
        java(cwd, "-m", "java.base/sun.security.tools.keytool.Main", "-genkeypair", "-alias", "test",
            "-keyalg", "EC", "-groupname", "secp256r1", "-dname", "CN=Sucrune Android build test", "-validity", "7",
            "-storetype", "PKCS12", "-keystore", "test.p12", "-storepass", "fixture-only", "-keypass", "fixture-only", "-noprompt")
        java(cwd, "-jar", "$sdk/lib/apksigner.jar", "sign", "--ks", "test.p12", "--ks-key-alias", "test",
            "--ks-pass", "pass:fixture-only", "--key-pass", "pass:fixture-only", "--min-sdk-version", "29",
            "--v1-signing-enabled", "false", "--v2-signing-enabled", "true", "--v3-signing-enabled", "false", "--v4-signing-enabled", "false",
            "--out", "app.apk", "aligned.apk")
        val verified = java(cwd, "-jar", "$sdk/lib/apksigner.jar", "verify", "--verbose", "--print-certs",
            "--min-sdk-version", "29", "app.apk").getString("stdout")
        check("Verified using v2 scheme (APK Signature Scheme v2): true" in verified &&
            "CN=Sucrune Android build test" in verified) { verified.take(900) }
        tool(cwd, "zipalign", "-c", "4", "app.apk")
        check(entries(cwd, "app.apk").getValue("classes.dex").contentEquals(dex))
        export?.invoke(client.readFile(project, "$cwd/app.apk"), marker)
        val frontend = if (kotlin) "Kotlin 2.2.21" else "javac"
        return "Guest $frontend, D8, AAPT2, zipalign and apksigner built an Activity APK; the V2 signer, aligned archive and original DEX bytes were checked."
    }
    return listOf(
        "linux_android_aapt2_resource_apk" to {
            val cwd = "/workspace/android-resource-build"
            resources(cwd, false)
            tool(cwd, "zipalign", "-f", "4", "unaligned.apk", "resource.apk")
            tool(cwd, "zipalign", "-c", "4", "resource.apk")
            check(entries(cwd, "resource.apk").keys == entries(cwd, "unaligned.apk").keys)
            "Debian ARM64 AAPT2 compiled XML, linked framework resources and emitted a no-code APK; aapt verified the package/label and zipalign verified alignment."
        },
        "linux_android_java_signed_apk" to { signedActivity(false) }
    ) + if (includeKotlin) listOf("linux_android_kotlin_sdk_apk" to { signedActivity(true) }) else emptyList()
}
