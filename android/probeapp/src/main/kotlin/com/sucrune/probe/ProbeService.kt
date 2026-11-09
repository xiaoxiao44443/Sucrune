package com.sucrune.probe

import android.app.Service
import android.content.Intent
import android.content.pm.ApplicationInfo
import android.os.Build
import android.os.Bundle
import android.os.Handler
import android.os.IBinder
import android.os.Looper
import android.os.Message
import android.os.Messenger
import android.os.Process
import android.os.RemoteException
import org.json.JSONObject

/** One experiment per disposable process. A missing response is never a pass. */
abstract class ProbeService : Service() {
    protected abstract val executionIdentity: String
    private val main = Handler(Looper.getMainLooper())
    private var started = false
    private val messenger = Messenger(object : Handler(Looper.getMainLooper()) {
        override fun handleMessage(message: Message) {
            when (message.what) {
                STOP -> finishProcess()
                RUN -> {
                    val reply = message.replyTo ?: return
                    val request = message.arg1
                    val requestId = message.data.getString("request_id") ?: "unknown"
                    val probe = if (message.data.containsKey("probe")) {
                        message.data.getString("probe") ?: ""
                    } else {
                        PROBE_SYSCALL
                    }
                    if (started) {
                        // An Activity can reconnect while the previous process is
                        // shutting down. Reply explicitly instead of ignoring RUN.
                        val report = JSONObject()
                            .put("schema_version", 1)
                            .put("probe", probe)
                            .put("status", "failed")
                            .put("stage", "process_busy")
                            .put("message", "This one-shot process already ran a probe; wait for it to exit and retry.")
                            .put("request_id", requestId)
                            .put("android", androidIdentity())
                        sendReport(reply, request, report)
                        return
                    }
                    started = true
                    // Remains effective if the Activity disappears or JNI hangs.
                    main.postDelayed({ finishProcess() }, 20_000)
                    Thread({ runOnce(reply, request, requestId, probe) }, "sucrune-probe-controller").start()
                }
                else -> super.handleMessage(message)
            }
        }
    })

    override fun onBind(intent: Intent): IBinder = messenger.binder

    private fun androidIdentity(): JSONObject = JSONObject()
        .put("api_level", Build.VERSION.SDK_INT)
        .put("target_sdk", applicationInfo.targetSdkVersion)
        .put("identity", executionIdentity)
        .put("process_uid", Process.myUid())
        .put("process_pid", Process.myPid())
        .put("debuggable", applicationInfo.flags and ApplicationInfo.FLAG_DEBUGGABLE != 0)
        .put("manufacturer", Build.MANUFACTURER)
        .put("model", Build.MODEL)
        .put("build_fingerprint", Build.FINGERPRINT)

    private fun runOnce(reply: Messenger, request: Int, requestId: String, probe: String) {
        val report = try {
            when (probe) {
                PROBE_SYSCALL -> JSONObject(NativeProbe.runProbe())
                PROBE_ELF -> JSONObject(NativeProbe.runElfProbe())
                else -> JSONObject()
                    .put("schema_version", 1)
                    .put("probe", probe)
                    .put("status", "failed")
                    .put("stage", "unknown_probe")
                    .put("message", "Unsupported probe name: $probe")
            }
        } catch (failure: Throwable) {
            JSONObject()
                .put("schema_version", 1)
                .put("probe", probe)
                .put("status", "failed")
                .put("stage", "java_or_native_entry")
                .put("message", "${failure.javaClass.simpleName}: ${failure.message}")
        }
        report.put("request_id", requestId)
        report.put("android", androidIdentity())
        sendReport(reply, request, report)
        // The UI acknowledges via STOP. This handles a disconnected client.
        main.postDelayed({ finishProcess() }, 3_000)
    }

    private fun sendReport(reply: Messenger, request: Int, report: JSONObject) {
        val result = Message.obtain(null, RESULT).apply {
            arg1 = request
            data = Bundle().apply { putString("report", report.toString()) }
        }
        try {
            reply.send(result)
        } catch (_: RemoteException) {
            // The caller can disappear at any time; watchdog still ends process.
        }
    }

    private fun finishProcess() {
        main.removeCallbacksAndMessages(null)
        stopSelf()
        Process.killProcess(Process.myPid())
    }

    companion object {
        internal const val RUN = 1
        internal const val RESULT = 2
        internal const val STOP = 3
        internal const val PROBE_SYSCALL = "seccomp_sigsys_return"
        internal const val PROBE_ELF = "arm64_elf"
    }
}
