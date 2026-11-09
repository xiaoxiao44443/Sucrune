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
import android.os.ParcelFileDescriptor
import android.os.Process
import android.os.SystemClock
import android.system.Os
import android.system.OsConstants
import com.sucrune.probe.NativeProbe
import com.sucrune.probe.NetworkProbeService
import org.json.JSONArray
import org.json.JSONObject
import java.io.Closeable
import java.net.InetAddress
import java.net.InetSocketAddress
import java.net.ServerSocket
import java.net.Socket
import java.util.UUID
import java.util.concurrent.CountDownLatch
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicBoolean
import java.util.concurrent.atomic.AtomicReference

/** A successful case means reliable measurement, not permission to use all networking. */
internal class NetworkCapabilityChecks(
    private val instrumentation: Instrumentation,
    private val context: Context,
    private val arguments: Bundle
) {
    private val loopback = InetAddress.getByAddress(byteArrayOf(127, 0, 0, 1))
    private var baseline = false
    private var verifiedEchoCapabilities = 0
    private var passed = 0
    private var failed = 0
    private var current = 0
    private val summary = StringBuilder()

    fun run() {
        case("network_manager_loopback_baseline") {
            check(Looper.myLooper() != Looper.getMainLooper()) { "Network capability checks must not block the main looper" }
            check(Process.myUid() == context.applicationInfo.uid && Process.myUid() != 0)
            arguments.getString("expect_debuggable")?.let {
                check(it == "true" || it == "false")
                check((context.applicationInfo.flags and ApplicationInfo.FLAG_DEBUGGABLE != 0) == it.toBoolean())
            }
            val direct = JSONObject(NativeProbe.runNetworkProbe(0, -1, 0, 3_000))
            validateNative(direct, Process.myUid(), Process.myPid(), 0)
            ServerSocket(0, 1, loopback).use { server ->
                EchoPeer(server = server).use { peer ->
                    Socket().use { socket ->
                        socket.connect(InetSocketAddress(loopback, server.localPort), 2_000)
                        ParcelFileDescriptor.fromSocket(socket).use { canonical ->
                            val native = JSONObject(NativeProbe.runNetworkProbe(1, canonical.fd, 0, 3_000))
                            validateNative(native, Process.myUid(), Process.myPid(), 1)
                            val echo = peer.finish()
                            check(native.getBoolean("echo_match") && echo.getBoolean("echo_match")) { "Manager baseline failed: $native; peer=$echo" }
                            baseline = true
                            JSONObject().put("manager_direct", direct).put("manager_connected", native)
                                .put("manager_peer", echo).put("loopback_only", true).put("api_level", Build.VERSION.SDK_INT).toString()
                        }
                    }
                }
            }
        }
        case("network_isolated_direct_socket") {
            requireBaseline()
            isolated(0, null, 0).put("interpretation", "Direct socket rc/errno are capabilities; refusal is not full network success").toString()
        }
        case("network_isolated_connected_fd") {
            requireBaseline()
            ServerSocket(0, 1, loopback).use { server ->
                EchoPeer(server = server).use { peer ->
                    Socket().use { socket ->
                        socket.connect(InetSocketAddress(loopback, server.localPort), 2_000)
                        ParcelFileDescriptor.fromSocket(socket).use { canonical ->
                            val report = isolated(1, canonical, 0)
                            interpretEcho(report, peer.finish()).toString()
                        }
                    }
                }
            }
        }
        case("network_isolated_connect_received_fd") {
            requireBaseline()
            ServerSocket(0, 1, loopback).use { server ->
                EchoPeer(server = server).use { peer ->
                    tcpDescriptor(false).first.use { canonical ->
                        val report = isolated(2, canonical, server.localPort)
                        val native = report.getJSONObject("native")
                        // If policy refused connect before a connection existed,
                        // measure the manager's operation on the same kernel OFD.
                        if (operationDenied(native, "connect_loopback")) {
                            val fallback = JSONObject(NativeProbe.runNetworkProbe(2, canonical.fd, server.localPort, 3_000))
                            validateNative(fallback, Process.myUid(), Process.myPid(), 2)
                            report.put("manager_same_description_fallback", fallback)
                        } else report.put("manager_same_description_fallback", "not_tested: isolated connect was not denied by policy")
                        interpretEcho(report, peer.finish()).toString()
                    }
                }
            }
        }
        case("network_isolated_accept_received_listener") {
            requireBaseline()
            val (descriptor, port) = tcpDescriptor(true)
            descriptor.use { canonical ->
                EchoPeer(connectPort = port).use { peer ->
                    val report = isolated(3, canonical, port)
                    val native = report.getJSONObject("native")
                    if (operationDenied(native, "accept4_received")) {
                        val fallback = JSONObject(NativeProbe.runNetworkProbe(3, canonical.fd, port, 3_000))
                        validateNative(fallback, Process.myUid(), Process.myPid(), 3)
                        report.put("manager_same_description_fallback", fallback)
                    } else report.put("manager_same_description_fallback", "not_tested: isolated accept was not denied by policy")
                    interpretEcho(report, peer.finish()).toString()
                }
            }
        }
        val conclusion = JSONObject().put("schema_version", 1).put("probe_integrity_passed", passed == 5 && failed == 0)
            .put("isolated_echo_capabilities_verified", verifiedEchoCapabilities).put("full_network_support", "not_established")
            .put("not_tested", JSONArray(listOf("UDP", "DNS", "external access", "SCM_RIGHTS ancillary parsing",
                "fresh native runner identity", "project network isolation")))
        instrumentation.finish(if (passed == 5 && failed == 0) Activity.RESULT_OK else Activity.RESULT_CANCELED, Bundle().apply {
            putInt("passed", passed); putInt("failed", failed); putInt("expected_tests", 5)
            putString("probe", "network_capability"); putString("network_capability", conclusion.toString())
            putString("stream", "\n$summary\n$conclusion\n")
        })
    }

    private fun requireBaseline() {
        check(baseline) { "SKIPPED-AS-FAIL: ordinary app loopback baseline failed; isolated networking was not evaluated" }
    }

    private fun tcpDescriptor(listening: Boolean): Pair<ParcelFileDescriptor, Int> {
        val fd = Os.socket(OsConstants.AF_INET,
            OsConstants.SOCK_STREAM or OsConstants.SOCK_CLOEXEC or OsConstants.SOCK_NONBLOCK, 0)
        try {
            var port = 0
            if (listening) {
                Os.bind(fd, loopback, 0)
                Os.listen(fd, 8)
                port = (Os.getsockname(fd) as InetSocketAddress).port
                check(port in 1..65_535)
            }
            return ParcelFileDescriptor.dup(fd) to port
        } finally { Os.close(fd) }
    }

    private fun operationDenied(native: JSONObject, name: String): Boolean {
        val operations = native.getJSONArray("operations")
        return (0 until operations.length()).any {
            val operation = operations.getJSONObject(it)
            operation.getString("name") == name && operation.getBoolean("attempted") &&
                operation.getInt("errno") in setOf(OsConstants.EACCES, OsConstants.EPERM)
        }
    }

    private fun interpretEcho(report: JSONObject, peer: JSONObject): JSONObject {
        val native = report.getJSONObject("native")
        val nativeEcho = native.getBoolean("echo_match")
        val operations = native.getJSONArray("operations")
        val echoAttempted = (0 until operations.length()).any {
            val operation = operations.getJSONObject(it)
            operation.getString("name") in setOf("send_echo", "recv_echo") && operation.getBoolean("attempted")
        }
        if (nativeEcho) {
            check(peer.getBoolean("echo_match") && native.getInt("echo_sent_bytes") == 4 &&
                native.getInt("echo_received_bytes") == 4) { "Native/manager echo evidence disagrees: $report; peer=$peer" }
            verifiedEchoCapabilities++
        }
        val fallback = report.optJSONObject("manager_same_description_fallback")
        if (fallback?.optBoolean("echo_match") == true) check(peer.getBoolean("echo_match")) { "Manager fallback echo mismatch: $report; peer=$peer" }
        return report.put("manager_peer", peer).put("isolated_echo_verified", nativeEcho).put("echo_attempted", echoAttempted)
            .put("capability_result", if (nativeEcho) "echo_verified" else if (echoAttempted)
                "attempted_not_verified: inspect operation rc/errno" else "not_tested: an earlier operation was denied or failed")
            .put("full_network_support", "not_established")
    }

    private fun validateNative(native: JSONObject, uid: Int, pid: Int, mode: Int) {
        check(native.getInt("schema_version") == 1 && native.getString("kind") == "network_capability" &&
            native.getInt("mode") == mode && native.getInt("uid") == uid && native.getInt("pid") == pid) { native.toString() }
        check(native.getBoolean("owned_fds_closed") && native.getInt("owned_fd_count") == native.getInt("owned_close_count")) { native.toString() }
        check(native.getInt("deadline_ms") in 1..3_000 && native.getLong("elapsed_ms") in 0..5_000) { native.toString() }
        val operations = native.getJSONArray("operations")
        check(operations.length() in 1..40)
        for (index in 0 until operations.length()) {
            val operation = operations.getJSONObject(index)
            val attempted = operation.getBoolean("attempted")
            val rc = operation.getLong("rc")
            check(operation.getBoolean("success") == (attempted && rc >= 0)) { operation.toString() }
            check(operation.getInt("errno") >= 0)
        }
    }

    /** Binder PFD transfer is deliberately named accurately; no SCM cmsg claim. */
    private fun isolated(mode: Int, canonical: ParcelFileDescriptor?, port: Int): JSONObject {
        val id = UUID.randomUUID().toString().replace("-", "")
        val main = Handler(Looper.getMainLooper())
        val resultReady = CountDownLatch(1)
        val death = CountDownLatch(1)
        val cleanupDone = CountDownLatch(1)
        val cleaning = AtomicBoolean(false)
        val bound = AtomicBoolean(false)
        val binder = AtomicReference<IBinder?>()
        val result = AtomicReference<JSONObject?>()
        val started = AtomicReference<JSONObject?>()
        val failure = AtomicReference<String?>()
        val transferred = canonical?.let { ParcelFileDescriptor.dup(it.fileDescriptor) }
        val recipient = IBinder.DeathRecipient { death.countDown() }
        fun fail(message: String) { failure.compareAndSet(null, message); resultReady.countDown() }
        val reply = Messenger(object : Handler(Looper.getMainLooper()) {
            override fun handleMessage(message: Message) {
                if (message.data.getString("request_id") != id) { fail("Wrong network probe request ID"); return }
                try {
                    val report = JSONObject(message.data.getString("report") ?: error("Missing network report"))
                    when (message.what) {
                        NetworkProbeService.STARTED -> started.set(report)
                        NetworkProbeService.RESULT -> { result.set(report); resultReady.countDown() }
                        else -> fail("Unexpected network probe message")
                    }
                } catch (error: Throwable) { fail(error.toString()) }
            }
        })
        val connection = object : ServiceConnection {
            override fun onServiceConnected(name: ComponentName, remote: IBinder) {
                binder.set(remote)
                try {
                    remote.linkToDeath(recipient, 0)
                    Messenger(remote).send(Message.obtain(null, if (cleaning.get()) NetworkProbeService.STOP else NetworkProbeService.RUN).apply {
                        replyTo = reply
                        data = Bundle().apply {
                            putString("request_id", id); putInt("mode", mode); putInt("port", port); putInt("timeout_ms", 3_000)
                            if (!cleaning.get()) putParcelable("socket", transferred)
                        }
                    })
                } catch (error: Throwable) { fail("Network service start failed: $error") }
                finally { try { transferred?.close() } catch (error: Exception) { fail("Transfer alias close failed: $error") } }
            }
            override fun onServiceDisconnected(name: ComponentName) { /* Death requires the registered Binder recipient. */ }
            override fun onBindingDied(name: ComponentName) { if (!cleaning.get()) fail("Network binding died") }
            override fun onNullBinding(name: ComponentName) { fail("Network service returned null binding") }
        }
        val deadline = SystemClock.elapsedRealtime() + 15_000
        main.post {
            try {
                bound.set(context.bindIsolatedService(Intent(context, NetworkProbeService::class.java), Context.BIND_AUTO_CREATE,
                    "network_$id", context.mainExecutor, connection))
                if (!bound.get()) fail("bindIsolatedService returned false")
            } catch (error: Throwable) { fail("Network service bind failed: $error") }
        }
        try {
            if (!resultReady.await(10_000, TimeUnit.MILLISECONDS)) fail("Network service report timeout")
        } finally {
            cleaning.set(true)
            main.post {
                try {
                    val remote = binder.get()
                    if (remote != null && remote.isBinderAlive) {
                        try { Messenger(remote).send(Message.obtain(null, NetworkProbeService.STOP).apply {
                            data = Bundle().apply { putString("request_id", id) }
                        }) } catch (_: android.os.RemoteException) { }
                    }
                    if (bound.compareAndSet(true, false)) context.unbindService(connection)
                } catch (error: Throwable) { fail("Network service cleanup failed: $error") }
                finally {
                    try { transferred?.close() } catch (error: Exception) { fail("Transfer alias cleanup failed: $error") }
                    cleanupDone.countDown()
                }
            }
        }
        fun remaining() = (deadline - SystemClock.elapsedRealtime()).coerceAtLeast(0)
        val cleanup = cleanupDone.await(remaining(), TimeUnit.MILLISECONDS)
        val dead = binder.get() != null && death.await(remaining(), TimeUnit.MILLISECONDS)
        if (dead) try { binder.get()?.unlinkToDeath(recipient, 0) } catch (_: NoSuchElementException) { }
        check(cleanup && dead && failure.get() == null && result.get() != null) {
            "Network probe failed: ${failure.get()}; binding_cleanup=$cleanup, binder_death=$dead, started=${started.get()}, full_report=${result.get()}"
        }
        val report = checkNotNull(result.get())
        try {
            check(report.getString("request_id") == id && report.getInt("mode") == mode && report.getInt("schema_version") == 1)
            val worker = report.getJSONObject("worker")
            val uid = worker.getInt("uid"); val pid = worker.getInt("pid")
            check(worker.getString("identity") == "isolated_network_probe" && worker.getInt("api_level") == Build.VERSION.SDK_INT)
            check(uid > 0 && uid != Process.myUid() && uid != context.applicationInfo.uid && pid > 0 && pid != Process.myPid())
            check(report.getString("transport") == "binder_parcel_file_descriptor" && report.getInt("received_fd_count") == if (canonical == null) 0 else 1)
            check(report.getBoolean("received_descriptor_closed"))
            validateNative(report.getJSONObject("native"), uid, pid, mode)
        } catch (error: Throwable) { throw IllegalStateException("Invalid isolated capability evidence: $error; full_report=$report", error) }
        return report.put("binder_death_confirmed", true).put("binding_cleanup_confirmed", true)
            .put("manager_uid", Process.myUid()).put("manager_pid", Process.myPid()).put("scm_rights_ancillary", "not_tested")
    }

    /** The Java peer provides independent byte evidence for the native socket. */
    private inner class EchoPeer(private val server: ServerSocket? = null, private val connectPort: Int = 0) : Closeable {
        private val socket = AtomicReference<Socket?>()
        private val closing = AtomicBoolean(false)
        private val done = CountDownLatch(1)
        private val report = AtomicReference(JSONObject().put("echo_match", false).put("status", "not_finished"))
        private val thread = Thread({
            val result = JSONObject().put("echo_match", false).put("received_bytes", 0).put("sent_bytes", 0)
            try {
                server?.soTimeout = 12_000
                val peer = if (server != null) server.accept() else Socket().also {
                    socket.set(it); it.connect(InetSocketAddress(loopback, connectPort), 2_000)
                }
                socket.set(peer)
                check(!closing.get()) { "Manager cancelled the echo peer" }
                peer.soTimeout = 9_000
                result.put("connected", true)
                val outgoing = (if (server != null) "PONG" else "PING").toByteArray(Charsets.US_ASCII)
                val expected = (if (server != null) "PING" else "PONG").toByteArray(Charsets.US_ASCII)
                if (server == null) { peer.getOutputStream().write(outgoing); peer.getOutputStream().flush(); result.put("sent_bytes", 4) }
                val incoming = ByteArray(4)
                var offset = 0
                while (offset < incoming.size) {
                    val count = peer.getInputStream().read(incoming, offset, incoming.size - offset)
                    check(count > 0) { "Peer ended before four echo bytes" }
                    offset += count; result.put("received_bytes", offset)
                }
                check(incoming.contentEquals(expected)) { "Unexpected echo bytes" }
                if (server != null) { peer.getOutputStream().write(outgoing); peer.getOutputStream().flush(); result.put("sent_bytes", 4) }
                result.put("echo_match", true).put("received_ascii", String(incoming, Charsets.US_ASCII))
                    .put("sent_ascii", String(outgoing, Charsets.US_ASCII)).put("status", "verified")
            } catch (error: Throwable) { result.put("status", "not_verified").put("error", error.toString()) }
            finally {
                try { socket.get()?.close() } catch (error: Exception) { result.put("close_error", error.toString()) }
                report.set(result); done.countDown()
            }
        }, "sucrune-network-echo").apply { isDaemon = true; start() }

        fun finish(): JSONObject {
            if (!done.await(250, TimeUnit.MILLISECONDS)) closeEndpoints()
            check(done.await(2_000, TimeUnit.MILLISECONDS)) { "Manager echo peer did not terminate after closing its sockets" }
            thread.join(2_000)
            check(!thread.isAlive) { "Manager echo peer thread did not join" }
            return report.get().put("thread_joined", true)
        }
        private fun closeEndpoints() {
            closing.set(true)
            try { server?.close() } finally { socket.get()?.close() }
        }
        override fun close() { closeEndpoints(); finish() }
    }

    private fun case(name: String, body: () -> String) {
        current++
        publish(1, name, "Starting bounded localhost capability measurement")
        try {
            val detail = body(); passed++; summary.append("$name: MEASURED $detail\n"); publish(0, name, detail)
        } catch (error: Throwable) {
            failed++; summary.append("$name: FAILED $error\n"); publish(-2, name, error.toString())
        }
    }
    private fun publish(code: Int, name: String, detail: String) = instrumentation.sendStatus(code, Bundle().apply {
        putString("id", "SucruneNetworkCapability"); putString("class", NetworkCapabilityChecks::class.java.name)
        putString("test", name); putInt("current", current); putInt("numtests", 5); putString("stream", "\n$name: $detail\n")
    })
}
