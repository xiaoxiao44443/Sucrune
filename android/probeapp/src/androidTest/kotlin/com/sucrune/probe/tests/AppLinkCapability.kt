package com.sucrune.probe.tests

import android.app.Activity
import android.app.Instrumentation
import android.content.Context
import android.os.Bundle
import android.system.ErrnoException
import android.system.Os
import java.io.File
import java.nio.file.Files
import java.util.UUID

/** Measure only freshly-created files in the manager's own private project storage domain. */
internal fun appLinkCapability(test: Instrumentation, context: Context) {
    val dir = File(context.filesDir, "sucrune-link-probe-" + UUID.randomUUID())
    val src = File(dir, "source")
    val dst = File(dir, "hard")
    val soft = File(dir, "soft")
    val result = Bundle()
    var ok = false
    try {
        check(dir.mkdir())
        src.writeText("source")
        try {
            Os.link(src.path, dst.path)
            val a = Os.stat(src.path); val b = Os.stat(dst.path)
            check(a.st_ino == b.st_ino && a.st_dev == b.st_dev && a.st_nlink == 2L)
            result.putInt("direct_hardlink_errno", 0)
        } catch (e: ErrnoException) { result.putInt("direct_hardlink_errno", e.errno) }
        try {
            Os.symlink("source", soft.path)
            check(Os.readlink(soft.path) == "source" && soft.readText() == "source")
            result.putInt("symlink_errno", 0)
        } catch (e: ErrnoException) { result.putInt("symlink_errno", e.errno) }
        ok = true
    } catch (_: Exception) { result.putString("probe_error", "setup_or_assertion") }
    finally {
        try {
            listOf(soft, dst, src, dir).forEach { Files.deleteIfExists(it.toPath()) }
            check(!dir.exists())
            result.putBoolean("scratch_removed", true)
        } catch (_: Exception) { ok = false }
        test.finish(if (ok) Activity.RESULT_OK else Activity.RESULT_CANCELED, result)
    }
}
