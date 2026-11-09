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
import android.os.ParcelFileDescriptor
import android.os.Process
import android.os.RemoteException
import android.os.SystemClock
import org.json.JSONObject

/** One execution per unique bindIsolatedService instance. Never opens the Go core. */
class RuntimeWorkerService : Service() {
    private val main = Handler(Looper.getMainLooper())
    private var started = false
    private var executionId = ""
    // Main-looper only. Closing the writer interrupts the native supervisor.
    private var linuxRunning = false
    private var linuxResultReady = false
    private var stopWriter: ParcelFileDescriptor? = null
    private val die = Runnable { Process.killProcess(Process.myPid()) }
    private val requestDeadlineStop = Runnable { requestStop() }
    private val inbox = Messenger(object : Handler(Looper.getMainLooper()) {
        override fun handleMessage(message: Message) {
            when (message.what) {
                RUN -> startExecution(message)
                STOP -> if (executionId.isEmpty() || message.data.getString("execution_id") == executionId) {
                    if (!linuxResultReady || message.data.getBoolean("result_ack")) requestStop()
                }
            }
        }
    })

    override fun onBind(intent: Intent?): IBinder = inbox.binder

    @Suppress("DEPRECATION")
    private fun startExecution(message: Message) {
        val data = message.data.apply { classLoader = ParcelFileDescriptor::class.java.classLoader }
        val broker = data.getParcelable<ParcelFileDescriptor>("broker")
        val stdout = data.getParcelable<ParcelFileDescriptor>("stdout")
        val stderr = data.getParcelable<ParcelFileDescriptor>("stderr")
        val stdin = data.getParcelable<ParcelFileDescriptor>("stdin")
        val reply = message.replyTo
        val requestedId = data.getString("execution_id") ?: ""
        val kind = data.getString("kind") ?: "shell"
        val script = data.getString("script") ?: ""
        val programId = data.getString("program_id") ?: ""
        val path = data.getString("path") ?: ""
        val argv = data.getStringArray("argv") ?: emptyArray()
        val env = data.getStringArray("env") ?: emptyArray()
        val cwd = data.getString("cwd") ?: "/"
        val timeout = data.getLong("timeout_ms", -1L)
        val resident = data.getBoolean("resident", false)
        val validLifetime = if (resident) kind == "linux" && timeout == 0L
            else timeout in 1L..RuntimeClient.DEFAULT_TIMEOUT_MS
        val validInput = try {
            require('\u0000' !in cwd && cwd.startsWith('/') && cwd.toByteArray(Charsets.UTF_8).size < 1_024)
            when (kind) {
                "shell" -> require('\u0000' !in script && script.toByteArray(Charsets.UTF_8).size <= 65_536)
                "program" -> {
                    require(RuntimeClient.isBundledProgram(programId))
                    require(stdin != null)
                    RuntimeClient.validateProgramArguments(argv.toList(), env.toList())
                }
                "linux" -> {
                    RuntimeClient.validateLinuxPath(path)
                    require(stdin != null)
                    RuntimeClient.validateProgramArguments(argv.toList(), env.toList())
                }
                else -> error("Unsupported execution kind")
            }
            true
        } catch (_: IllegalArgumentException) { false }
          catch (_: IllegalStateException) { false }
        if (started || reply == null || !requestedId.matches(Regex("exec_[0-9a-f]{32}")) ||
            broker == null || stdout == null || stderr == null ||
            !validInput || !validLifetime) {
            broker?.closeQuietly(); stdout?.closeQuietly(); stderr?.closeQuietly(); stdin?.closeQuietly()
            if (reply != null) send(reply, RESULT, requestedId, JSONObject()
                .put("schema_version", 1).put("kind", kind).put("status", "failed")
                .put("stage", if (started) "process_busy" else "invalid_request")
                .put("message", "Worker requires one execution with a valid lifetime and stream descriptors"))
            if (!started) main.postDelayed(die, 1_000)
            return
        }
        started = true
        executionId = requestedId
        val stopPipe = try {
            if (kind == "linux") ParcelFileDescriptor.createPipe() else null
        } catch (_: java.io.IOException) {
            broker.closeQuietly(); stdout.closeQuietly(); stderr.closeQuietly(); stdin?.closeQuietly()
            send(reply, RESULT, executionId, JSONObject().put("schema_version", 1).put("kind", kind)
                .put("worker", identity()).put("status", "failed").put("stage", "stop_pipe"))
            main.postDelayed(die, 2_000)
            return
        }
        linuxRunning = stopPipe != null
        stopWriter = stopPipe?.get(1)
        if (resident) {
            // A resident has no deadline to reclaim it if its manager disappears.
            // This worker is single-use; its death releases the Binder registration.
            try { reply.binder.linkToDeath({ main.post { requestStop() } }, 0) }
            catch (_: RemoteException) {
                broker.closeQuietly(); stdout.closeQuietly(); stderr.closeQuietly(); stdin?.closeQuietly()
                stopPipe?.forEach { it.closeQuietly() }
                terminate()
                return
            }
        } else if (linuxRunning) main.postDelayed(requestDeadlineStop, timeout + 250)
        else main.postDelayed(die, timeout + 2_000)
        send(reply, STARTED, executionId, JSONObject().put("worker", identity()))
        Thread({
            val nativeStartedAt = SystemClock.elapsedRealtime()
            val result = try {
                // JNI owns a detached read endpoint, including every failure path.
                JSONObject(when (kind) {
                    "program" -> NativeProbe.runProgram(broker.fd, programId, argv, env, cwd, stdout.fd, stderr.fd, stdin!!.detachFd())
                    "linux" -> NativeProbe.runLinux(broker.fd, path, argv, env, cwd, stdout.fd, stderr.fd,
                        stdin!!.detachFd(), stopPipe!![0].fd)
                    else -> NativeProbe.runShell(broker.fd, script, cwd, stdout.fd, stderr.fd)
                })
            } catch (failure: Throwable) {
                JSONObject().put("schema_version", 1).put("kind", kind)
                    .put("status", "failed").put("stage", "java_or_native_entry")
                    .put("message", failure.toString())
            } finally {
                broker.closeQuietly(); stdout.closeQuietly(); stderr.closeQuietly(); stdin?.closeQuietly()
                stopPipe?.get(0)?.closeQuietly()
            }
            result.put("worker", identity()).put("execution_id", executionId)
                .put("native_started_at_elapsed_ms", nativeStartedAt)
                .put("native_finished_at_elapsed_ms", SystemClock.elapsedRealtime())
            main.post {
                linuxRunning = false
                linuxResultReady = stopPipe != null
                stopWriter?.closeQuietly(); stopWriter = null
                main.removeCallbacks(requestDeadlineStop)
                main.removeCallbacks(die)
                send(reply, RESULT, executionId, result)
                main.postDelayed(die, 2_000)
            }
        }, "sucrune-$kind").start()
    }

    private fun identity(): JSONObject = JSONObject()
        .put("identity", "isolated_runtime").put("pid", Process.myPid())
        .put("uid", Process.myUid()).put("api_level", Build.VERSION.SDK_INT)
        .put("abi", Build.SUPPORTED_ABIS.firstOrNull() ?: "unknown")
        .put("debuggable", applicationInfo.flags and ApplicationInfo.FLAG_DEBUGGABLE != 0)

    private fun send(target: Messenger, what: Int, id: String, result: JSONObject) {
        try {
            target.send(Message.obtain(null, what).apply {
                data = Bundle().apply {
                    putString("execution_id", id)
                    putString("report", result.toString())
                }
            })
        } catch (_: RemoteException) { requestStop() }
    }

    private fun requestStop() {
        if (!linuxRunning) { terminate(); return }
        val writer = stopWriter ?: return
        stopWriter = null
        writer.closeQuietly()
        // Last resort if native or the OS gets stuck. A hard death yields no
        // confirmed native reaping report. Repeated STOPs cannot cut cleanup short.
        main.postDelayed(die, 8_000)
    }
    private fun terminate() { stopSelf(); Process.killProcess(Process.myPid()) }
    override fun onDestroy() {
        main.removeCallbacksAndMessages(null)
        super.onDestroy()
        Process.killProcess(Process.myPid())
    }
    private fun ParcelFileDescriptor.closeQuietly() { try { close() } catch (_: Exception) {} }

    companion object {
        const val RUN = 11
        const val STARTED = 12
        const val RESULT = 13
        const val STOP = 14
    }
}
