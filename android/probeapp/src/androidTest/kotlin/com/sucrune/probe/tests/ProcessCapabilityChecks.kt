package com.sucrune.probe.tests

import android.app.Activity
import android.app.Instrumentation
import android.content.ComponentName
import android.content.Context
import android.content.Intent
import android.content.ServiceConnection
import android.content.pm.ApplicationInfo
import android.os.Build
import android.os.Bundle
import android.os.Handler
import android.os.IBinder
import android.os.Looper
import android.os.Message
import android.os.Messenger
import android.os.Process
import android.os.SystemClock
import com.sucrune.probe.ProcessProbeService
import org.json.JSONObject
import java.util.UUID
import java.util.concurrent.CountDownLatch
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicBoolean
import java.util.concurrent.atomic.AtomicReference

/** Passing means reliable capability evidence; denied operations remain denied. */
internal fun processCapabilityCases(context: Context): List<Pair<String, () -> String>> = listOf(
    "isolated_runner_process_mechanisms" to { measureProcessCapabilities(context).toString() }
)

internal class ProcessCapabilityChecks(
    private val instrumentation: Instrumentation,
    private val context: Context,
    private val arguments: Bundle
) {
    fun run() {
        var passed = 0
        var failed = 0
        val summary = StringBuilder()
        for ((name, body) in processCapabilityCases(context)) {
            fun publish(code: Int, text: String) = instrumentation.sendStatus(code, Bundle().apply {
                putString("id", "SucruneProcessCapability"); putString("class", ProcessCapabilityChecks::class.java.name)
                putString("test", name); putInt("current", 1); putInt("numtests", 1); putString("stream", "\n$name: $text\n")
            })
            publish(1, "Measuring packaged runner process mechanisms in an isolated UID")
            try {
                arguments.getString("expect_debuggable")?.let {
                    check(it == "true" || it == "false")
                    check((context.applicationInfo.flags and ApplicationInfo.FLAG_DEBUGGABLE != 0) == it.toBoolean())
                }
                val detail = body(); passed++; summary.append("$name: MEASURED $detail\n"); publish(0, detail)
            } catch (failure: Throwable) {
                failed++; summary.append("$name: FAILED $failure\n"); publish(-2, failure.toString())
            }
        }
        instrumentation.finish(if (failed == 0) Activity.RESULT_OK else Activity.RESULT_CANCELED, Bundle().apply {
            putInt("passed", passed); putInt("failed", failed); putInt("expected_tests", 1)
            putString("probe", "process_capability"); putString("stream", "\n$summary\n")
        })
    }
}

private fun measureProcessCapabilities(context: Context): JSONObject {
    check(Looper.myLooper() != Looper.getMainLooper()) { "Process measurement cannot block the main looper" }
    check(Process.myUid() > 0 && Process.myUid() == context.applicationInfo.uid)
    val id = UUID.randomUUID().toString().replace("-", "")
    val main = Handler(Looper.getMainLooper())
    val resultReady = CountDownLatch(1)
    val death = CountDownLatch(1)
    val cleanupDone = CountDownLatch(1)
    val cleaning = AtomicBoolean(false)
    val bound = AtomicBoolean(false)
    val remote = AtomicReference<IBinder?>()
    val report = AtomicReference<JSONObject?>()
    val started = AtomicReference<JSONObject?>()
    val failure = AtomicReference<String?>()
    fun fail(value: String) { failure.compareAndSet(null, value); resultReady.countDown() }
    val recipient = IBinder.DeathRecipient { death.countDown() }
    val reply = Messenger(object : Handler(Looper.getMainLooper()) {
        override fun handleMessage(message: Message) {
            if (message.data.getString("request_id") != id) { fail("Wrong process probe request ID"); return }
            try {
                val value = JSONObject(message.data.getString("report") ?: error("Missing report"))
                when (message.what) {
                    ProcessProbeService.STARTED -> started.set(value)
                    ProcessProbeService.RESULT -> { report.set(value); resultReady.countDown() }
                    else -> fail("Unexpected process probe reply")
                }
            } catch (error: Throwable) { fail(error.toString()) }
        }
    })
    val connection = object : ServiceConnection {
        override fun onServiceConnected(name: ComponentName, binder: IBinder) {
            remote.set(binder)
            try {
                binder.linkToDeath(recipient, 0)
                Messenger(binder).send(Message.obtain(null, if (cleaning.get()) ProcessProbeService.STOP else ProcessProbeService.RUN).apply {
                    replyTo = reply
                    data = Bundle().apply { putString("request_id", id) }
                })
            } catch (error: Throwable) { fail("Process service start failed: $error") }
        }
        override fun onServiceDisconnected(name: ComponentName) { /* Only death recipient confirms process death. */ }
        override fun onBindingDied(name: ComponentName) { if (!cleaning.get()) fail("Process binding died") }
        override fun onNullBinding(name: ComponentName) { fail("Process service returned null binding") }
    }
    val deadline = SystemClock.elapsedRealtime() + 18_000
    main.post {
        try {
            bound.set(context.bindIsolatedService(Intent(context, ProcessProbeService::class.java), Context.BIND_AUTO_CREATE,
                "process_$id", context.mainExecutor, connection))
            if (!bound.get()) fail("bindIsolatedService returned false")
        } catch (error: Throwable) { fail("Process bind failed: $error") }
    }
    try {
        if (!resultReady.await(13_000, TimeUnit.MILLISECONDS)) fail("Process capability report timeout")
    } finally {
        cleaning.set(true)
        main.post {
            try {
                remote.get()?.takeIf { it.isBinderAlive }?.let {
                    try { Messenger(it).send(Message.obtain(null, ProcessProbeService.STOP).apply {
                        data = Bundle().apply { putString("request_id", id) }
                    }) } catch (_: android.os.RemoteException) { }
                }
                if (bound.compareAndSet(true, false)) context.unbindService(connection)
            } catch (error: Throwable) { fail("Process binding cleanup failed: $error") }
            finally { cleanupDone.countDown() }
        }
    }
    fun remaining() = (deadline - SystemClock.elapsedRealtime()).coerceAtLeast(0)
    val bindingClosed = cleanupDone.await(remaining(), TimeUnit.MILLISECONDS)
    val serviceDead = remote.get() != null && death.await(remaining(), TimeUnit.MILLISECONDS)
    if (serviceDead) try { remote.get()?.unlinkToDeath(recipient, 0) } catch (_: NoSuchElementException) { }
    check(bindingClosed && serviceDead && failure.get() == null && report.get() != null) {
        "Process measurement failed: ${failure.get()}; binding=$bindingClosed, death=$serviceDead, started=${started.get()}, report=${report.get()}"
    }
    val result = checkNotNull(report.get())
    try {
        check(result.getInt("schema_version") == 1 && result.getString("request_id") == id)
        check(result.getString("runner_source") == "installed_native_library_directory")
        val worker = result.getJSONObject("worker")
        val uid = worker.getInt("uid"); val pid = worker.getInt("pid")
        check(uid > 0 && uid != Process.myUid() && pid > 0 && pid != Process.myPid())
        check(worker.getString("identity") == "isolated_process_probe" && worker.getInt("api_level") == Build.VERSION.SDK_INT)
        val native = result.getJSONObject("native")
        check(native.getInt("schema_version") == 1 && native.getString("kind") == "process_capability")
        check(native.getInt("wrapper_uid") == uid && native.getInt("wrapper_pid") == pid)
        check(native.getBoolean("cleanup_verified") && !native.getBoolean("protocol_error"))
        check(native.getInt("deadline_ms") == 6_000 && native.getLong("elapsed_ms") in 0..10_000)
        val runner = native.getInt("runner_pid")
        if (runner > 0) {
            check(runner != pid && runner != Process.myPid())
            check(native.getBoolean("runner_waited") && native.getBoolean("lease_eof") && native.getBoolean("descendants_reaped"))
        }
        val operations = native.getJSONArray("operations")
        check(operations.length() in 1..40)
        for (index in 0 until operations.length()) {
            val operation = operations.getJSONObject(index)
            check(operation.getInt("uid") == uid && operation.getInt("pid") > 0 && operation.getBoolean("attempted"))
            check(operation.getBoolean("success") == (operation.getLong("rc") >= 0))
            check(operation.getInt("errno") == if (operation.getLong("rc") < 0) -operation.getLong("rc").toInt() else 0)
        }
        // A policy refusal is a measured limitation, never an affirmative claim.
        result.put("capability_result", if (native.getBoolean("mechanism_verified")) "mechanisms_verified" else "not_verified: inspect exact stages and errno")
    } catch (error: Throwable) { throw IllegalStateException("Invalid process capability evidence: $error; full_report=$result", error) }
    return result.put("manager_uid", Process.myUid()).put("manager_pid", Process.myPid())
        .put("binder_death_confirmed", true).put("binding_cleanup_confirmed", true)
        .put("general_linux_process_support", "not_implemented_by_this_probe")
}
