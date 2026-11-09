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
import android.os.Process
import android.os.RemoteException
import org.json.JSONObject

/** Disposable isolated process: owns only this bounded probe's native children. */
class ProcessProbeService : Service() {
    private val main = Handler(Looper.getMainLooper())
    private var started = false
    private var requestId = ""
    private val die = Runnable { terminate() }
    private val inbox = Messenger(object : Handler(Looper.getMainLooper()) {
        override fun handleMessage(message: Message) {
            when (message.what) {
                RUN -> runProbe(message)
                STOP -> if (requestId.isEmpty() || message.data.getString("request_id") == requestId) terminate()
            }
        }
    })

    override fun onBind(intent: Intent?): IBinder {
        main.postDelayed(die, 12_000)
        return inbox.binder
    }

    private fun runProbe(message: Message) {
        val id = message.data.getString("request_id") ?: ""
        val reply = message.replyTo
        if (started || reply == null || !id.matches(Regex("[0-9a-f]{32}"))) {
            if (!started) terminate()
            return
        }
        started = true
        requestId = id
        main.removeCallbacks(die)
        main.postDelayed(die, 12_000)
        try { reply.binder.linkToDeath({ terminate() }, 0) }
        catch (_: RemoteException) { terminate(); return }
        send(reply, STARTED, JSONObject().put("worker", identity()))
        // The path comes exclusively from PackageManager's installed native libs.
        val runner = applicationInfo.nativeLibraryDir + "/libsucrune_runner.so"
        Thread({
            val native = try { JSONObject(NativeProbe.runProcessProbe(runner)) }
            catch (failure: Throwable) { JSONObject().put("entry_exception", failure.toString()) }
            val result = JSONObject().put("schema_version", 1).put("request_id", requestId)
                .put("worker", identity()).put("native", native)
                .put("runner_source", "installed_native_library_directory")
            main.post {
                send(reply, RESULT, result)
                main.postDelayed(die, 1_000)
            }
        }, "sucrune-process-probe").start()
    }

    private fun identity(): JSONObject = JSONObject().put("identity", "isolated_process_probe")
        .put("uid", Process.myUid()).put("pid", Process.myPid()).put("api_level", Build.VERSION.SDK_INT)
        .put("target_sdk", applicationInfo.targetSdkVersion)

    private fun send(reply: Messenger, what: Int, value: JSONObject) {
        try {
            reply.send(Message.obtain(null, what).apply {
                data = Bundle().apply { putString("request_id", requestId); putString("report", value.toString()) }
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
        const val RUN = 41
        const val STARTED = 42
        const val RESULT = 43
        const val STOP = 44
    }
}
