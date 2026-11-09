package com.sucrune.probe

import android.app.Service
import android.content.Intent
import android.os.Binder
import android.os.Build
import android.os.Handler
import android.os.IBinder
import android.os.Looper
import android.os.Parcel
import android.os.ParcelFileDescriptor
import android.os.Process
import java.util.concurrent.atomic.AtomicBoolean
import org.json.JSONObject

/** One bounded direct or Binder-transferred PTY measurement in an isolated UID. */
class PtyProbeService : Service() {
    private val main = Handler(Looper.getMainLooper())
    private val started = AtomicBoolean()
    private val die = Runnable { stopSelf(); Process.killProcess(Process.myPid()) }
    private val channel = object : Binder() {
        override fun onTransact(code: Int, data: Parcel, reply: Parcel?, flags: Int): Boolean {
            if (code != RUN && code != STOP && code != IDENTITY) return super.onTransact(code, data, reply, flags)
            data.enforceInterface(INTERFACE)
            if (code == STOP) { main.post(die); return true }
            if (code == IDENTITY) {
                reply?.writeNoException()
                reply?.writeInt(Process.myUid()); reply?.writeInt(Process.myPid())
                return true
            }
            val token = data.readStrongBinder()
            val mode = data.readInt()
            val nonce = data.readInt()
            val descriptor = if (data.readInt() == 1) ParcelFileDescriptor.CREATOR.createFromParcel(data) else null
            val report = JSONObject().put("schema_version", 1).put("uid", Process.myUid()).put("pid", Process.myPid())
                .put("mode", mode).put("api_level", Build.VERSION.SDK_INT).put("received_fds", if (descriptor == null) 0 else 1)
            try {
                require(reply != null && token != null && started.compareAndSet(false, true))
                require(mode in DIRECT..RIGHT_MASTER_CONTROL && (descriptor == null) == (mode == DIRECT))
                token.linkToDeath({ main.post(die) }, 0)
                val native = when (mode) {
                    DIRECT -> PtyNative.direct()
                    EXCHANGE -> PtyNative.endpoint(checkNotNull(descriptor).fd, 1, nonce)
                    CONTROLLING -> PtyNative.controlling(checkNotNull(descriptor).fd)
                    else -> {
                        val right = PtyNative.receiveRight(checkNotNull(descriptor).fd)
                        check(right.size == 5)
                        report.put("scm_local_error", right[0]).put("scm_message_flags", right[1])
                            .put("scm_rights_count", right[2]).put("scm_payload_bytes", right[4])
                        if (right[0] != 0) {
                            check(right[3] == -1)
                            JSONObject().put("ok", false).put("stage", "receive_right").put("errno", right[0]).toString()
                        } else ParcelFileDescriptor.adoptFd(right[3]).use {
                            when (mode) {
                                RIGHT_CONTROLLING -> PtyNative.controlling(it.fd)
                                RIGHT_MASTER_CONTROL -> PtyNative.masterControlling(it.fd, nonce)
                                else -> PtyNative.endpoint(it.fd, 1, nonce)
                            }
                        }
                    }
                }
                report.put("native", JSONObject(native))
            } catch (failure: Exception) {
                report.put("entry_error", failure.javaClass.simpleName)
            } finally {
                try { descriptor?.close(); report.put("descriptor_closed", true) }
                catch (failure: Exception) { report.put("descriptor_closed", false).put("close_error", failure.javaClass.simpleName) }
            }
            reply?.writeNoException()
            reply?.writeString(report.toString())
            return true
        }
    }
    override fun onBind(intent: Intent?): IBinder {
        main.postDelayed(die, 12_000)
        return channel
    }
    override fun onDestroy() {
        main.removeCallbacks(die)
        super.onDestroy()
        Process.killProcess(Process.myPid())
    }
    companion object {
        const val INTERFACE = "com.sucrune.probe.PtyProbe.v1"
        const val RUN = IBinder.FIRST_CALL_TRANSACTION
        const val STOP = RUN + 1
        const val IDENTITY = RUN + 2
        const val DIRECT = 0
        const val EXCHANGE = 1
        const val CONTROLLING = 2
        const val RIGHT_EXCHANGE = 3
        const val RIGHT_CONTROLLING = 4
        const val RIGHT_MASTER_CONTROL = 5
    }
}
