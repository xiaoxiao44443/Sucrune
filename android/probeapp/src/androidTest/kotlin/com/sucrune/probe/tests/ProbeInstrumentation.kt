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
import org.json.JSONObject
import java.util.concurrent.CountDownLatch
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicBoolean
import java.util.concurrent.atomic.AtomicReference
import java.util.UUID

/** Device tests run through the APK identity; ADB is only the test launcher. */
class ProbeInstrumentation : Instrumentation() {
    private var launchArguments = Bundle()
    private var selectedProbe = PROBE_SYSCALL

    override fun onCreate(arguments: Bundle?) {
        super.onCreate(arguments)
        launchArguments = if (arguments == null) Bundle() else Bundle(arguments)
        start()
    }

    override fun onStart() {
        // Binder callbacks and reply handling use the main looper. Never block it.
        Thread({
            try {
                val foreground = launchArguments.getString("keep_foreground")
                require(foreground == null || foreground == "true" || foreground == "false")
                if (foreground == "true") {
                    startActivitySync(Intent().setClassName(targetContext,
                        "${targetContext.packageName}.MainActivity").addFlags(
                            Intent.FLAG_ACTIVITY_NEW_TASK or Intent.FLAG_ACTIVITY_CLEAR_TOP))
                    waitForIdleSync()
                    sendStatus(2, Bundle().apply {
                        putString("stream", "\nForeground validation explicitly requested; background scheduling is not established.\n")
                        putString("foreground_validation", "true")
                    })
                }
            } catch (failure: Throwable) {
                finish(Activity.RESULT_CANCELED, Bundle().apply {
                    putInt("passed", 0); putInt("failed", 1)
                    putString("stream", "Foreground test setup failed: $failure")
                })
                return@Thread
            }
            when (launchArguments.getString("probe")) {
                "runtime" -> RuntimeChecks(this, targetContext, launchArguments).run()
                "program" -> ProgramChecks(this, targetContext, launchArguments).run()
                "tools" -> ToolsChecks(this, targetContext, launchArguments).run()
                "exec" -> ExecChecks(this, targetContext, launchArguments).run()
                "io" -> IOChecks(this, targetContext, launchArguments).run()
                "linux" -> LinuxChecks(this, targetContext, launchArguments).run()
                "landlock" -> landlockChecks(this)
                "shared_directory" -> sharedDirectoryChecks(this)
                "resident" -> residentExecutionChecks(this)
                "network_capability" -> NetworkCapabilityChecks(this, targetContext, launchArguments).run()
                "process_capability" -> ProcessCapabilityChecks(this, targetContext, launchArguments).run()
                "credential_bridge_synthetic" -> CredentialBridgeChecks(this).run()
                "pty_capability" -> PtyCapabilityChecks(this, targetContext).run()
                "linux_diagnostics" -> linuxDiagnostics(this, targetContext, launchArguments)
                "agent_last_outcome" -> agentLastOutcome(this, targetContext)
                "app_link_capability" -> appLinkCapability(this, targetContext)
                "import" -> ImportChecks(this, targetContext, launchArguments).run()
                "runtime_recovery" -> RuntimeRecoveryChecks(this, targetContext, launchArguments).run()
                else -> runSuite()
            }
        }, "sucrune-instrumentation").start()
    }

    private fun runSuite() {
        var passed = 0
        var failed = 0
        val summary = StringBuilder()
        try {
            val context = targetContext
            selectedProbe = launchArguments.getString("probe") ?: PROBE_SYSCALL
            require(selectedProbe == PROBE_SYSCALL || selectedProbe == PROBE_ELF) {
                "Unknown probe argument: $selectedProbe"
            }
            val expectedDebuggable = when (val expected = launchArguments.getString("expect_debuggable")) {
                null -> null
                "true" -> true
                "false" -> false
                else -> throw IllegalArgumentException("expect_debuggable must be true or false, got: $expected")
            }
            val appDebuggable = context.applicationInfo.flags and ApplicationInfo.FLAG_DEBUGGABLE != 0
            if (expectedDebuggable != null) {
                require(appDebuggable == expectedDebuggable) {
                    "Target APK debuggable=$appDebuggable, expected $expectedDebuggable"
                }
            }
            val endpoints = listOf(
                Endpoint("AppProbeService", "application"),
                Endpoint("IsolatedProbeService", "isolated_service"),
            )
            var request = 0
            for (endpoint in endpoints) {
                var previousProcessEnded = true
                for (iteration in 1..2) {
                    request++
                    val testName = if (selectedProbe == PROBE_SYSCALL) "${endpoint.identity}_$iteration"
                        else "${selectedProbe}_${endpoint.identity}_$iteration"
                    publish(1, request, testName, "Starting $testName")
                    val outcome = if (previousProcessEnded) {
                        Attempt(context, endpoint, request, selectedProbe, expectedDebuggable).execute()
                    } else {
                        Outcome(false, false, null,
                            "Previous process death was not confirmed; refusing to reuse this service")
                    }
                    previousProcessEnded = outcome.processEnded
                    if (outcome.passed) passed++ else failed++
                    val description = "$testName: ${if (outcome.passed) "PASS" else "FAIL"} ${outcome.detail}"
                    summary.append(description).append('\n')
                    publish(if (outcome.passed) 0 else -2, request, testName,
                        description, outcome.report)
                }
            }
        } catch (failure: Throwable) {
            failed++
            summary.append("Runner failed: ").append(describe(failure)).append('\n')
        } finally {
            val result = Bundle().apply {
                putInt("passed", passed)
                putInt("failed", failed)
                putInt("expected_tests", TOTAL_TESTS)
                putString("probe", selectedProbe)
                putString("stream", "\n$summary\nPassed: $passed; failed: $failed\n")
            }
            finish(if (failed == 0 && passed == TOTAL_TESTS) Activity.RESULT_OK
                else Activity.RESULT_CANCELED, result)
        }
    }

    private fun publish(code: Int, current: Int, testName: String, detail: String,
                        report: String? = null) {
        sendStatus(code, Bundle().apply {
            putString("id", "SucruneProbe")
            putString("class", ProbeInstrumentation::class.java.name)
            putString("test", testName)
            putInt("current", current)
            putInt("numtests", TOTAL_TESTS)
            putString("stream", "\n$detail\n")
            if (report != null) putString("report", report)
        })
    }

    private data class Endpoint(val service: String, val identity: String)
    private data class Outcome(val passed: Boolean, val processEnded: Boolean,
                               val report: String?, val detail: String)

    private class Attempt(private val context: Context, private val endpoint: Endpoint,
                          private val request: Int, private val probe: String,
                          private val expectedDebuggable: Boolean?) {
        private val main = Handler(Looper.getMainLooper())
        private val requestId = UUID.randomUUID().toString()
        private val response = CountDownLatch(1)
        private val death = CountDownLatch(1)
        private val cleanupDone = CountDownLatch(1)
        private val bound = AtomicBoolean(false)
        private val cleaningUp = AtomicBoolean(false)
        private val binder = AtomicReference<IBinder?>()
        private val report = AtomicReference<String?>()
        private val error = AtomicReference<String?>()
        private val recipient = IBinder.DeathRecipient {
            death.countDown()
            if (report.get() == null && !cleaningUp.get()) {
                fail("Probe process died before returning a report")
            }
        }
        private val reply = Messenger(Handler(Looper.getMainLooper()) { message ->
            if (message.what != RESULT) {
                fail("Unexpected reply message ${message.what}")
            } else if (message.arg1 != request) {
                fail("Reply request ID ${message.arg1} does not match $request")
            } else {
                val value = message.data.getString("report")
                if (value.isNullOrBlank()) fail("Probe returned no JSON report")
                else if (report.compareAndSet(null, value)) response.countDown()
                else fail("Probe returned more than one report")
            }
            true
        })

        private val connection = object : ServiceConnection {
            override fun onServiceConnected(name: ComponentName, service: IBinder) {
                binder.set(service)
                try {
                    service.linkToDeath(recipient, 0)
                    if (cleaningUp.get()) {
                        Messenger(service).send(Message.obtain(null, STOP))
                    } else {
                        Messenger(service).send(Message.obtain(null, RUN).apply {
                            arg1 = request
                            replyTo = reply
                            data = Bundle().apply {
                                putString("request_id", requestId)
                                // Keep first default-syscall cases exercising the
                                // original protocol, which omitted the probe name.
                                if (probe != PROBE_SYSCALL || request % 2 == 0) putString("probe", probe)
                            }
                        })
                    }
                } catch (failure: Throwable) {
                    fail("Cannot start probe: ${describe(failure)}")
                }
            }

            override fun onServiceDisconnected(name: ComponentName) {
                if (report.get() == null && !cleaningUp.get()) {
                    fail("Service disconnected before returning a report")
                }
                // Disconnection alone is not proof of process death.
            }

            override fun onBindingDied(name: ComponentName) {
                if (!cleaningUp.get()) fail("Service binding died")
            }

            override fun onNullBinding(name: ComponentName) {
                fail("Service returned a null binding")
            }
        }

        fun execute(): Outcome {
            val deadline = SystemClock.elapsedRealtime() + CASE_TIMEOUT_MS
            main.post {
                try {
                    val intent = Intent().setComponent(ComponentName(
                        context.packageName, "${context.packageName}.${endpoint.service}"))
                    bound.set(context.bindService(intent, connection, Context.BIND_AUTO_CREATE))
                    if (!bound.get()) fail("bindService returned false")
                } catch (failure: Throwable) {
                    fail("Cannot bind service: ${describe(failure)}")
                }
            }
            try {
                if (!await(response, deadline)) fail("Timed out waiting for the probe report")
                if (error.get() == null) {
                    try {
                        validate(JSONObject(requireNotNull(report.get())), context,
                            endpoint.identity, requestId, probe, expectedDebuggable)
                    } catch (failure: Throwable) {
                        fail("Invalid probe evidence: ${describe(failure)}")
                    }
                }
            } catch (failure: InterruptedException) {
                fail("Instrumentation interrupted while waiting for the probe")
                Thread.currentThread().interrupt()
            } finally {
                cleaningUp.set(true)
                main.post {
                    try {
                        val remote = binder.get()
                        if (remote != null && remote.isBinderAlive) {
                            try {
                                Messenger(remote).send(Message.obtain(null, STOP))
                            } catch (_: android.os.RemoteException) {
                                // A concurrent process exit is confirmed separately via linkToDeath.
                            }
                        }
                    } finally {
                        if (bound.compareAndSet(true, false)) {
                            try { context.unbindService(connection) }
                            catch (failure: IllegalArgumentException) {
                                fail("Unbind failed: ${describe(failure)}")
                            }
                        }
                        cleanupDone.countDown()
                    }
                }
            }

            var processEnded = false
            try {
                if (!await(cleanupDone, deadline)) fail("Timed out cleaning up the service binding")
                processEnded = binder.get() != null && await(death, deadline)
                if (!processEnded) fail("Binder death was not confirmed before the case deadline")
            } catch (failure: InterruptedException) {
                fail("Instrumentation interrupted during cleanup")
                Thread.currentThread().interrupt()
            }
            if (processEnded) {
                try { binder.get()?.unlinkToDeath(recipient, 0) }
                catch (_: java.util.NoSuchElementException) {
                    // The binder may already have removed registrations when it died.
                }
            }
            val problem = error.get()
            return Outcome(problem == null && processEnded, processEnded, report.get(),
                problem ?: "All evidence matched; disposable process death confirmed")
        }

        private fun fail(message: String) {
            error.compareAndSet(null, message)
            response.countDown()
        }
    }

    companion object {
        private const val RUN = 1
        private const val RESULT = 2
        private const val STOP = 3
        private const val TOTAL_TESTS = 4
        private const val CASE_TIMEOUT_MS = 15_000L
        private const val SYNTHETIC_PID = 424242L
        private const val PROBE_SYSCALL = "seccomp_sigsys_return"
        private const val PROBE_ELF = "arm64_elf"
        private const val ELF_STDOUT = "Hello from Sucrune ELF!\n"

        private fun await(latch: CountDownLatch, deadline: Long): Boolean =
            latch.await((deadline - SystemClock.elapsedRealtime()).coerceAtLeast(0),
                TimeUnit.MILLISECONDS)

        private fun describe(failure: Throwable): String =
            "${failure.javaClass.simpleName}: ${failure.message ?: "no detail"}"

        private fun validate(report: JSONObject, context: Context, identity: String,
                             requestId: String, probe: String, expectedDebuggable: Boolean?) {
            require(report.getInt("schema_version") == 1) { "Unsupported report schema" }
            require(report.getString("request_id") == requestId) { "Wrong request UUID" }
            require(report.getString("status") == "passed") {
                "status=${report.optString("status")}, stage=${report.optString("stage")}, " +
                    "message=${report.optString("message")}"
            }
            require(report.getString("probe") == probe) { "Wrong probe type" }
            val host = report.getJSONObject("host")
            val evidence = report.getJSONObject("evidence")
            val android = report.getJSONObject("android")
            val abi = host.getString("abi")
            require(abi in setOf("arm64-v8a", "x86_64") && abi in Build.SUPPORTED_ABIS) {
                "Unexpected native ABI: $abi"
            }
            val pid = host.getLong("pid")
            val uid = host.getInt("uid")
            require(pid > 0 && pid != Process.myPid().toLong()) { "Probe did not use a separate process" }
            require(android.getLong("process_pid") == pid) { "Java and native process IDs differ" }
            require(uid > 0 && android.getInt("process_uid") == uid) { "Invalid or root process UID" }
            require(android.getString("identity") == identity) { "Wrong execution identity" }
            val applicationUid = context.applicationInfo.uid
            if (identity == "application") {
                require(uid == applicationUid) { "Application probe UID differs from the APK UID" }
            } else {
                require(uid != applicationUid) { "Isolated probe reused the APK UID" }
            }
            require(android.getInt("api_level") == Build.VERSION.SDK_INT) { "Wrong Android API level" }
            require(android.getInt("target_sdk") == context.applicationInfo.targetSdkVersion) {
                "Wrong targetSdk in report"
            }
            val appDebuggable = context.applicationInfo.flags and ApplicationInfo.FLAG_DEBUGGABLE != 0
            require(android.getBoolean("debuggable") == appDebuggable) {
                "Service debuggable flag differs from the target ApplicationInfo"
            }
            if (expectedDebuggable != null) {
                require(android.getBoolean("debuggable") == expectedDebuggable) {
                    "Service debuggable flag differs from expect_debuggable"
                }
            }
            if (probe == PROBE_ELF) {
                validateElf(evidence, abi)
            } else {
                validateSyscall(evidence, pid)
            }
        }

        private fun validateSyscall(evidence: JSONObject, pid: Long) {
            require(evidence.getInt("trap_count") == 1) { "Expected exactly one SIGSYS trap" }
            require(evidence.getLong("expected_return") == SYNTHETIC_PID &&
                evidence.getLong("observed_return") == SYNTHETIC_PID) { "Synthetic return value mismatch" }
            for (field in listOf("filter_installed", "on_alt_stack", "handler_restored", "thread_joined")) {
                require(evidence.getBoolean(field)) { "$field was false" }
            }
            require(evidence.getInt("worker_no_new_privs") == 1) { "Worker did not enable no_new_privs" }
            require(evidence.getLong("baseline_pid") == pid && evidence.getLong("control_pid") == pid) {
                "Untrapped getpid control did not return the real process ID"
            }
            val before = evidence.getLong("control_tid_before")
            require(before > 0 && evidence.getLong("control_tid_after") == before) {
                "Untrapped gettid control changed across the trap"
            }
            require(evidence.getInt("signal_syscall") == evidence.getInt("syscall_number")) {
                "SIGSYS reported a different syscall"
            }
        }

        private fun validateElf(evidence: JSONObject, abi: String) {
            require(abi == "arm64-v8a") { "The controlled ELF requires native ARM64 execution" }
            require(evidence.getInt("elf_machine") == 183) { "ELF machine is not EM_AARCH64" }
            require(evidence.getInt("elf_type") == 3) { "ELF type is not ET_DYN" }
            require(evidence.getBoolean("entry_executed")) { "ELF entry was not executed" }
            require(evidence.getString("stdout") == ELF_STDOUT) { "ELF stdout differs from the fixture" }
            require(evidence.getInt("exit_code") == 42) { "ELF exit code was not 42" }
            require(evidence.getInt("write_calls") == 1) { "Expected exactly one guest write" }
            require(evidence.getInt("exit_calls") == 1) { "Expected exactly one guest exit" }
            require(evidence.getInt("guest_argc") == 1) { "Guest initial argc was not one" }
            require(evidence.getInt("stack_alignment") == 16) { "Guest stack did not satisfy 16-byte alignment" }
            require(evidence.getInt("loaded_segments") >= 2) { "Expected at least two loaded ELF segments" }
            for (field in listOf("bss_zeroed", "thread_joined", "handler_restored",
                "filter_installed", "on_alt_stack", "returned_to_host")) {
                require(evidence.getBoolean(field)) { "$field was false" }
            }
            require(evidence.getInt("trap_count") == 2) { "Expected exactly write and exit traps" }
            require(evidence.getInt("validator_negative_tests") == 26) {
                "ELF validator rejection tests did not all pass"
            }
        }
    }
}
