package com.sucrune.probe.tests

import com.sucrune.probe.RuntimeClient
import java.nio.ByteBuffer
import java.nio.ByteOrder
import java.util.zip.ZipInputStream

private fun aarch64Elf(bytes: ByteArray, fileType: Int): ByteBuffer {
    val elf = ByteBuffer.wrap(bytes).order(ByteOrder.LITTLE_ENDIAN)
    check(bytes.size >= 64 && bytes.take(6) == listOf<Byte>(127, 69, 76, 70, 2, 1))
    check(elf.getShort(16).toInt() == fileType && elf.getShort(18).toInt() == 183)
    return elf
}

private fun verifyNativeActivityLibrary(bytes: ByteArray) {
    val elf = aarch64Elf(bytes, 3) // ET_DYN
    val sectionTable = elf.getLong(40).toInt()
    val sectionSize = elf.getShort(58).toInt()
    val sections = (0 until elf.getShort(60).toInt()).map { sectionTable + it * sectionSize }
    fun table(section: Int): IntProgression {
        val start = elf.getLong(section + 24).toInt()
        val size = elf.getLong(section + 32).toInt()
        return (start until start + size) step elf.getLong(section + 56).toInt()
    }
    fun string(section: Int, relative: Int): String {
        val strings = sections[elf.getInt(section + 40)]
        val start = elf.getLong(strings + 24).toInt() + relative
        var end = start
        while (bytes[end] != 0.toByte()) end++
        return bytes.decodeToString(start, end)
    }
    val symbols = sections.single { elf.getInt(it + 4) == 11 } // SHT_DYNSYM
    val names = table(symbols).associate { string(symbols, elf.getInt(it)) to elf.getShort(it + 6).toInt() }
    check(names.getValue("ANativeActivity_onCreate") != 0 && names.getValue("ANativeActivity_finish") == 0)
    val dynamic = sections.single { elf.getInt(it + 4) == 6 } // SHT_DYNAMIC
    val libraries = table(dynamic).filter { elf.getLong(it) == 1L }.map { string(dynamic, elf.getLong(it + 8).toInt()) }
    check(libraries == listOf("libandroid.so")) { "NativeActivity dependencies: $libraries" }
}

internal fun linuxNativeActivityCompilerCase(client: RuntimeClient, project: String, execute: ToolboxExec):
    Pair<String, () -> String> = "linux_android_native_activity_apk" to {
    val cwd = "/workspace/android-native-build"
    val sdk = "/opt/android-sdk"
    val compiler = "/opt/android-native"
    val libraries = listOf("LD_LIBRARY_PATH=$sdk/lib:/lib/aarch64-linux-gnu:/usr/lib/aarch64-linux-gnu")
    val so = "lib/arm64-v8a/libsucruneactivity.so"
    fun run(program: String, vararg args: String): String {
        val record = execute(program, args.toList(), cwd, libraries, 90_000L)
        check(record.optString("state") == "exited" && record.optInt("exit_code", -1) == 0) {
            "${program.substringAfterLast('/')} ${args.take(4)}: ${record.optString("state")} " +
                "exit=${record.optInt("exit_code", -1)} ${record.optString("stderr").takeLast(1200)}"
        }
        return record.optString("stdout")
    }
    fun write(path: String, source: String) {
        client.writeFile(project, "$cwd/$path", source.trimIndent().toByteArray())
    }
    listOf("res/values", "lib/arm64-v8a").forEach { client.makeDirectory(project, "$cwd/$it") }
    write("activity.c", """
        typedef struct ANativeActivity ANativeActivity;
        extern void ANativeActivity_finish(ANativeActivity *activity);
        void ANativeActivity_onCreate(ANativeActivity *activity, void *saved, unsigned long size) {
            (void)saved;
            (void)size;
            ANativeActivity_finish(activity);
        }
    """)
    run("$compiler/bin/tcc", "-nostdinc", "-fPIC", "-c", "activity.c", "-o", "activity.o")
    aarch64Elf(client.readFile(project, "$cwd/activity.o"), 1) // ET_REL
    run("$compiler/bin/tcc", "-nostdlib", "-shared", "-soname", "libsucruneactivity.so",
        "-L$compiler/lib", "-o", so, "activity.o", "-landroid")
    val library = client.readFile(project, "$cwd/$so")
    verifyNativeActivityLibrary(library)
    write("res/values/strings.xml", """<resources><string name="app_name">Sucrune Native Probe</string></resources>""")
    write("AndroidManifest.xml", """
        <manifest xmlns:android="http://schemas.android.com/apk/res/android" package="dev.sucrune.nativeprobe"
            android:versionCode="1" android:versionName="1">
            <uses-sdk android:minSdkVersion="29" android:targetSdkVersion="35" />
            <application android:hasCode="false" android:extractNativeLibs="true" android:label="@string/app_name">
                <activity android:name="android.app.NativeActivity" android:exported="true">
                    <meta-data android:name="android.app.lib_name" android:value="sucruneactivity" />
                    <intent-filter>
                        <action android:name="android.intent.action.MAIN" />
                        <category android:name="android.intent.category.LAUNCHER" />
                    </intent-filter>
                </activity>
            </application>
        </manifest>
    """)
    run("$sdk/bin/aapt2", "compile", "--dir", "res", "-o", "compiled.zip")
    run("$sdk/bin/aapt2", "link", "-o", "unsigned.apk", "-I", "$sdk/platform/framework-res.apk",
        "--manifest", "AndroidManifest.xml", "compiled.zip")
    run("$sdk/bin/zip", "-q", "-X", "-0", "unsigned.apk", so)
    run("$sdk/bin/zipalign", "-f", "4", "unsigned.apk", "native.apk")
    run("$sdk/bin/zipalign", "-c", "4", "native.apk")
    val badging = run("$sdk/bin/aapt", "dump", "badging", "native.apk")
    check("package: name='dev.sucrune.nativeprobe'" in badging &&
        "launchable-activity: name='android.app.NativeActivity'" in badging && "native-code: 'arm64-v8a'" in badging) {
        badging.take(1500)
    }
    val archive = mutableMapOf<String, ByteArray>()
    ZipInputStream(client.readFile(project, "$cwd/native.apk").inputStream()).use { zip ->
        while (true) {
            val entry = zip.nextEntry ?: break
            check(archive.put(entry.name, zip.readBytes()) == null)
        }
    }
    check(archive.getValue("AndroidManifest.xml").take(4) == listOf<Byte>(3, 0, 8, 0))
    check(archive.getValue("resources.arsc").take(2) == listOf<Byte>(2, 0))
    check(archive.getValue(so).contentEquals(library) && !archive.containsKey("classes.dex"))
    "Compiled ARM64 C, linked NativeActivity to the NDK API 29 libandroid.so stub and built a zipaligned unsigned APK. Verified the ELF dependency, entry point, manifest and archived library."
}
