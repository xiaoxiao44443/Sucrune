package com.sucrune.probe

import android.app.Service
import android.content.Intent
import android.os.Build
import android.os.Bundle
import android.os.Handler
import android.os.IBinder
import android.os.Looper
import android.os.Message
import android.os.Messenger
import android.os.ParcelFileDescriptor
import android.os.Process
import android.os.RemoteException
import org.json.JSONObject

/** One bounded localhost capability measurement in a disposable isolated UID. */
class NetworkProbeService : Service() {
    private val main = Handler(Looper.getMainLooper())
    private var started = false
    private var requestId = ""
    private val die = Runnable { terminate() }
    private val inbox = Messenger(object : Handler(Looper.getMainLooper()) {
        override fun handleMessage(message: Message) {
            when (message.what) {
                RUN -> startProbe(message)
                STOP -> if (requestId.isEmpty() || message.data.getString("request_id") == requestId) terminate()
            }
        }
    })

    override fun onBind(intent: Intent?): IBinder {
        // A bind that never sends RUN must not leave an idle isolated process.
        main.postDelayed(die, 8_000)
        return inbox.binder
    }

    @Suppress("DEPRECATION")
    private fun startProbe(message: Message) {
        val data = message.data.apply { classLoader = ParcelFileDescriptor::class.java.classLoader }
        val descriptor = data.getParcelable<ParcelFileDescriptor>("socket")
        val reply = message.replyTo
        val requested = data.getString("request_id") ?: ""
        val mode = data.getInt("mode", -1)
        val port = data.getInt("port", 0)
        val timeout = data.getInt("timeout_ms", 0)
        if (started || reply == null || !requested.matches(Regex("[0-9a-f]{32}")) ||
            mode !in 0..3 || (mode == 0) != (descriptor == null) || timeout !in 1..3_000 ||
            port !in 0..65_535 || (mode == 2 && port == 0)) {
            try { descriptor?.close() } catch (_: Exception) { }
            if (reply != null) send(reply, RESULT, requested, JSONObject().put("protocol_error", "invalid_or_repeated_request"))
            if (!started) terminate()
            return
        }
        started = true
        requestId = requested
        main.removeCallbacks(die)
        main.postDelayed(die, timeout.toLong() + 2_000)
        try { reply.binder.linkToDeath({ terminate() }, 0) }
        catch (_: RemoteException) { descriptor?.close(); terminate(); return }
        send(reply, STARTED, requestId, JSONObject().put("worker", identity()))
        Thread({
            var closed = false
            var closeError: String? = null
            val native = try {
                JSONObject(NativeProbe.runNetworkProbe(mode, descriptor?.fd ?: -1, port, timeout))
            } catch (failure: Throwable) {
                JSONObject().put("entry_exception", failure.toString())
            } finally {
                try { descriptor?.close(); closed = true }
                catch (failure: Exception) { closeError = failure.toString() }
            }
            val result = JSONObject().put("schema_version", 1).put("request_id", requestId)
                .put("mode", mode).put("worker", identity()).put("native", native)
                .put("transport", "binder_parcel_file_descriptor").put("received_fd_count", if (descriptor == null) 0 else 1)
                .put("received_descriptor_closed", closed)
            closeError?.let { result.put("close_error", it) }
            main.post {
                send(reply, RESULT, requestId, result)
                // Manager sends STOP after receiving the report; this is a
                // bounded fallback if the manager disappears or forgets STOP.
                main.postDelayed(die, 1_000)
            }
        }, "sucrune-network-probe").start()
    }

    private fun identity(): JSONObject = JSONObject().put("identity", "isolated_network_probe")
        .put("uid", Process.myUid()).put("pid", Process.myPid()).put("api_level", Build.VERSION.SDK_INT)
        .put("target_sdk", applicationInfo.targetSdkVersion)

    private fun send(target: Messenger, what: Int, id: String, report: JSONObject) {
        try {
            target.send(Message.obtain(null, what).apply {
                data = Bundle().apply { putString("request_id", id); putString("report", report.toString()) }
            })
        } catch (_: RemoteException) { terminate() }
    }

    private fun terminate() { stopSelf(); Process.killProcess(Process.myPid()) }
    override fun onDestroy() {
        main.removeCallbacksAndMessages(null)
        super.onDestroy()
        Process.killProcess(Process.myPid())
    }

    companion object {
        const val RUN = 31
        const val STARTED = 32
        const val RESULT = 33
        const val STOP = 34
    }
}
