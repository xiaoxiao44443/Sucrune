package com.sucrune.probe.tests

import android.app.Instrumentation
import android.os.Bundle
import android.util.Base64
import org.json.JSONObject
import java.security.MessageDigest

/** Transport only the synthetic application produced by this explicit build test. */
internal fun emitInstallableApk(instrumentation: Instrumentation, apk: ByteArray, packageName: String, activityName: String, marker: String) {
    require(packageName == "dev.sucrune.compiled" || packageName == "dev.sucrune.gradleprobe")
    require(apk.size in 1..(16 * 1024 * 1024))
    val digest = MessageDigest.getInstance("SHA-256").digest(apk).joinToString("") { "%02x".format(it) }
    val chunkBytes = 12 * 1024
    for (offset in apk.indices step chunkBytes) {
        val text = Base64.encodeToString(apk, offset, minOf(chunkBytes, apk.size - offset), Base64.NO_WRAP)
        instrumentation.sendStatus(2, Bundle().apply { putString("sucrune_apk_chunk", "${offset / chunkBytes}:$text") })
    }
    val metadata = JSONObject().put("package", packageName).put("activity", activityName).put("marker", marker)
        .put("bytes", apk.size).put("sha256", digest).put("chunks", (apk.size + chunkBytes - 1) / chunkBytes)
    instrumentation.sendStatus(2, Bundle().apply { putString("sucrune_apk", metadata.toString()) })
}
