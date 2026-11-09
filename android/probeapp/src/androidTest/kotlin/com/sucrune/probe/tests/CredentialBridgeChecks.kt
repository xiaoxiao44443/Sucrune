package com.sucrune.probe.tests

import android.app.Activity
import android.app.Application
import android.app.Instrumentation
import android.os.Bundle
import android.os.Process

/** Dedicated synthetic-only Android transport test. Never invokes DSH, opens a
 * real credential source, launches a guest or creates a workspace. The matching
 * host entry is scripts/send-dsh-credential-synthetic.cjs, not the real sender. */
internal class CredentialBridgeChecks(private val instrumentation: Instrumentation) {
    fun run() {
        val name = "synthetic_android_credential_bridge"
        fun status(code: Int, detail: String, descriptor: String? = null) {
            instrumentation.sendStatus(code, Bundle().apply {
                putString("id", "SucruneCredentialBridge"); putString("class", CredentialBridgeChecks::class.java.name)
                putString("test", name); putInt("current", 1); putInt("numtests", 1)
                putString("stream", "\n$name: $detail\n")
                if (descriptor != null) putString("credential_bridge_descriptor", descriptor)
            })
        }
        var success = false
        var detail = "setup"
        try {
            val context = instrumentation.targetContext
            if (Application.getProcessName() != context.packageName || Process.myUid() != context.applicationInfo.uid ||
                Process.myUid() == 0 || Process.myUid() == 2000) throw DshCredentialFailure("app_identity")
            status(1, "Starting one-shot synthetic Android receiver")
            val value = DshCredentialBridge.receive(announce = { publicDescriptor ->
                // Exactly one compact public line; no input values, shared keys,
                // private keys or authentication credential in this descriptor.
                status(2, "Waiting for the synthetic sender on an authenticated ADB-forwarded local socket", publicDescriptor.toString())
            }, timeoutMs = 60_000)
            val expected = "sucrune-synthetic-device-bridge-v1".toCharArray()
            try { if (!value.contentEquals(expected)) throw DshCredentialFailure("synthetic_marker_mismatch") }
            finally { value.fill('\u0000'); expected.fill('\u0000') }
            success = true
            detail = "Application receiver checked shell peer UID 2000, verified the single authenticated payload, matched the synthetic marker and cleared its returned buffer; no credential store or model was used"
        } catch (failure: DshCredentialFailure) { detail = "bridge stage=${failure.phase}" }
        catch (_: Exception) { detail = "bridge stage=instrumentation" }
        finally {
            status(if (success) 0 else -2, (if (success) "PASS " else "FAIL ") + detail)
            instrumentation.finish(if (success) Activity.RESULT_OK else Activity.RESULT_CANCELED, Bundle().apply {
                putInt("passed", if (success) 1 else 0); putInt("failed", if (success) 0 else 1); putInt("expected_tests", 1)
                putString("probe", "credential_bridge_synthetic"); putString("stream", "\n$name: $detail\n")
            })
        }
    }
}
