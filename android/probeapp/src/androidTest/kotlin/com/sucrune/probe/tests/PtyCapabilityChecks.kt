package com.sucrune.probe.tests

import android.app.Activity
import android.app.Instrumentation
import android.content.ComponentName
import android.content.Context
import android.content.Intent
import android.content.ServiceConnection
import android.os.Binder
import android.os.Build
import android.os.Bundle
import android.os.IBinder
import android.os.Looper
import android.os.Parcel
import android.os.ParcelFileDescriptor
import android.os.Process
import com.sucrune.probe.PtyNative
import com.sucrune.probe.PtyProbeService
import java.security.SecureRandom
import java.util.UUID
import java.util.concurrent.CountDownLatch
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicReference
import org.json.JSONObject

/** Distinguishes a measured access denial from a verified kernel capability.
 * All PTYs and Binder descriptors are owned by this probe. */
internal class PtyCapabilityChecks(private val instrumentation: Instrumentation, private val context: Context) {
    private var index = 0
    private var passed = 0
    private var failed = 0
    private val summary = StringBuilder()
    private val verified = JSONObject()

    fun run() {
        measure("pty_manager_direct") {
            check(Looper.myLooper() != Looper.getMainLooper())
            check(Process.myUid() > 0 && Process.myUid() == context.applicationInfo.uid)
            val direct = JSONObject(PtyNative.direct())
            validateDirect(direct, Process.myUid(), Process.myPid())
            verified.put("manager_pair", direct.getBoolean("exchange_verified"))
            direct
        }
        measure("pty_isolated_direct") {
            val report = isolated(PtyProbeService.DIRECT, null, 0)
            val direct = report.getJSONObject("native")
            validateDirect(direct, report.getInt("uid"), report.getInt("pid"))
            verified.put("isolated_pair", direct.getBoolean("exchange_verified"))
            report
        }
        measure("pty_manager_slave_to_isolated") { transferred(slave = true, control = false) }
        measure("pty_manager_master_to_isolated") { transferred(slave = false, control = false) }
        measure("pty_manager_slave_controlling_session") { transferred(slave = true, control = true) }
        measure("pty_scm_slave_to_isolated") { transferred(slave = true, control = false, scm = true) }
        measure("pty_scm_master_to_isolated") { transferred(slave = false, control = false, scm = true) }
        measure("pty_scm_slave_controlling_session") { transferred(slave = true, control = true, scm = true) }
        measure("pty_scm_master_controlling_alias") { transferred(slave = false, control = true, scm = true) }
        val conclusion = JSONObject().put("schema_version", 2).put("verified", verified)
            .put("measurement_integrity", passed == TOTAL && failed == 0)
        instrumentation.finish(if (passed == TOTAL && failed == 0) Activity.RESULT_OK else Activity.RESULT_CANCELED, Bundle().apply {
            putInt("passed", passed); putInt("failed", failed); putInt("expected_tests", TOTAL)
            putString("probe", "pty_capability"); putString("pty_capability", conclusion.toString())
            putString("stream", "\n$summary\n$conclusion\n")
        })
    }

    private fun validateControl(control: JSONObject) {
        val pid = control.getInt("child_pid")
        if (pid > 0) check(control.getBoolean("waited")) { "PTY control child was not reaped: $control" }
        else check(control.getInt("error") > 0)
        if (control.getBoolean("ok")) {
            check(pid > 0 && control.getInt("error") == 0 && control.getBoolean("session_matches") &&
                control.getBoolean("group_matches") && control.getInt("open_dev_tty_errno") == 0)
        }
    }

    private fun validateDirect(direct: JSONObject, uid: Int, pid: Int) {
        check(direct.getInt("uid") == uid && direct.getInt("pid") == pid && direct.getInt("close_errno") == 0)
        if (direct.getInt("prepare_errno") == 0) {
            val endpoint = direct.getJSONObject("endpoint")
            check(endpoint.getBoolean("ok") == direct.getBoolean("exchange_verified"))
            if (endpoint.getBoolean("ok")) check(endpoint.getInt("rows") == 37 && endpoint.getInt("columns") == 113 &&
                endpoint.getBoolean("raw") && endpoint.getInt("nonblock") == 1 && endpoint.getInt("cloexec") == 1)
            else check(endpoint.getInt("errno") > 0)
            validateControl(direct.getJSONObject("controlling"))
        } else check(!direct.getBoolean("exchange_verified"))
    }

    private fun transferred(slave: Boolean, control: Boolean, scm: Boolean = false): JSONObject {
        val masterControl = !slave && control
        val key = (if (scm) "scm_" else "") + (if (masterControl) "received_master_ctty" else if (control) "received_slave_ctty" else if (slave) "received_slave_io" else "received_master_io")
        check(verified.optBoolean("manager_pair")) { "Manager PTY pair baseline unavailable; transfer not evaluated" }
        val fds = PtyNative.openPair()
        check(fds.size == 3 && fds[0] == 0 && fds[1] >= 0 && fds[2] >= 0 && fds[1] != fds[2]) { "Fresh manager PTY allocation failed" }
        val report = ParcelFileDescriptor.adoptFd(fds[1]).use { master ->
            ParcelFileDescriptor.adoptFd(fds[2]).use { terminal ->
                val toWorker = if (slave) terminal else master
                val manager = if (slave) master else terminal
                val nonce = SecureRandom().nextInt()
                if (!control) {
                    val written = JSONObject(PtyNative.endpoint(manager.fd, 0, nonce))
                    check(written.getBoolean("ok")) { "Manager challenge write failed: $written" }
                }
                if (masterControl) check(JSONObject(PtyNative.endpoint(master.fd, 0, nonce)).getBoolean("ok"))
                val result = if (scm) {
                    val sockets = ParcelFileDescriptor.createSocketPair()
                    sockets[0].use { sender -> sockets[1].use { receiver ->
                        val err = PtyNative.sendRight(sender.fd, toWorker.fd)
                        check(err == 0) { "SCM_RIGHTS sender failed with errno=$err" }
                        isolated(if (masterControl) PtyProbeService.RIGHT_MASTER_CONTROL else if (control) PtyProbeService.RIGHT_CONTROLLING else PtyProbeService.RIGHT_EXCHANGE, receiver, nonce)
                            .put("scm_send_errno", err)
                    } }
                } else isolated(if (control) PtyProbeService.CONTROLLING else PtyProbeService.EXCHANGE, toWorker, nonce)
                val native = result.getJSONObject("native")
                val stage = native.optString("stage")
                if (stage == "binder_handoff" || stage == "receive_right") {
                    check(!native.getBoolean("ok"))
                    if (stage == "binder_handoff") check(result.getBoolean("same_remote_alive_after_rejection"))
                    else check(result.getInt("scm_local_error") != 0 && result.getInt("scm_rights_count") == 0)
                } else if (control) {
                    validateControl(native)
                    if (masterControl && native.getBoolean("alias_verified")) {
                        val reply = JSONObject(PtyNative.endpoint(master.fd, 2, nonce))
                        check(reply.getBoolean("ok"))
                        result.put("manager_verified_alias_reply", reply)
                    }
                    if (masterControl) verified.put("isolated_dev_tty_alias_io", native.getBoolean("alias_verified"))
                }
                else if (native.getBoolean("ok")) {
                    val reply = JSONObject(PtyNative.endpoint(manager.fd, 2, nonce))
                    check(reply.getBoolean("ok")) { "Manager saw no verified PTY reply/resize: $reply" }
                    result.put("manager_verified_reply", reply)
                } else check(native.getInt("errno") > 0) { "Unclassified transferred PTY failure: $native" }
                verified.put(key, native.getBoolean("ok"))
                result.put("received_endpoint", if (slave) "slave" else "master").put("verified", native.getBoolean("ok"))
            }
        }
        return report.put("manager_descriptors_closed", true)
    }

    private fun isolated(mode: Int, fd: ParcelFileDescriptor?, nonce: Int): JSONObject {
        val connected = CountDownLatch(1)
        val dead = CountDownLatch(1)
        val binder = AtomicReference<IBinder?>()
        val death = IBinder.DeathRecipient { dead.countDown() }
        val connection = object : ServiceConnection {
            override fun onServiceConnected(name: ComponentName, service: IBinder) {
                try { service.linkToDeath(death, 0); binder.set(service) }
                catch (_: android.os.RemoteException) { }
                finally { connected.countDown() }
            }
            override fun onServiceDisconnected(name: ComponentName) {}
            override fun onBindingDied(name: ComponentName) { connected.countDown() }
            override fun onNullBinding(name: ComponentName) { connected.countDown() }
        }
        val bound = context.bindIsolatedService(Intent(context, PtyProbeService::class.java), Context.BIND_AUTO_CREATE,
            "pty_" + UUID.randomUUID().toString().replace("-", ""), context.mainExecutor, connection)
        check(bound) { "PTY isolated service binding refused" }
        var result: JSONObject
        var cleanupError: Throwable? = null
        try {
            check(connected.await(5, TimeUnit.SECONDS)) { "PTY isolated binding timed out" }
            val remote = checkNotNull(binder.get()) { "PTY isolated binder unavailable" }
            val identity = identity(remote)
            val request = Parcel.obtain()
            val response = Parcel.obtain()
            try {
                request.writeInterfaceToken(PtyProbeService.INTERFACE)
                request.writeStrongBinder(Binder()); request.writeInt(mode); request.writeInt(nonce)
                request.writeInt(if (fd == null) 0 else 1)
                fd?.writeToParcel(request, 0)
                result = try {
                    check(remote.transact(PtyProbeService.RUN, request, response, 0)) { "PTY transaction declined" }
                    response.readException()
                    JSONObject(checkNotNull(response.readString()))
                } catch (rejected: android.os.DeadObjectException) {
                    if (fd == null || identity(remote) != identity) throw rejected
                    JSONObject().put("schema_version", 1).put("uid", identity.first).put("pid", identity.second)
                        .put("api_level", Build.VERSION.SDK_INT).put("mode", mode).put("received_fds", 0)
                        .put("binder_exception", rejected.javaClass.simpleName).put("same_remote_alive_after_rejection", true)
                        .put("native", JSONObject().put("ok", false).put("stage", "binder_handoff"))
                }
            } finally { request.recycle(); response.recycle() }
        } finally {
            val remote = binder.get()
            if (remote != null && remote.isBinderAlive) {
                val stop = Parcel.obtain()
                try {
                    stop.writeInterfaceToken(PtyProbeService.INTERFACE)
                    remote.transact(PtyProbeService.STOP, stop, null, IBinder.FLAG_ONEWAY)
                } catch (_: android.os.DeadObjectException) { }
                catch (failure: Exception) { cleanupError = failure }
                finally { stop.recycle() }
            }
            try { context.unbindService(connection) } catch (failure: Exception) { cleanupError = failure }
            if (remote != null) {
                check(dead.await(5, TimeUnit.SECONDS)) { "PTY isolated service death unconfirmed" }
                try { remote.unlinkToDeath(death, 0) } catch (_: NoSuchElementException) {}
            }
            check(cleanupError == null) { "PTY binding cleanup failed: $cleanupError" }
        }
        check(result.getInt("schema_version") == 1 && result.getInt("mode") == mode && !result.has("entry_error"))
        check(result.getInt("uid") > 0 && result.getInt("uid") != Process.myUid() &&
            result.getInt("pid") > 0 && result.getInt("pid") != Process.myPid() && result.getInt("api_level") == Build.VERSION.SDK_INT)
        if (result.optBoolean("same_remote_alive_after_rejection")) check(result.getInt("received_fds") == 0)
        else check(result.getInt("received_fds") == (if (fd == null) 0 else 1) && result.getBoolean("descriptor_closed"))
        return result.put("binder_death_confirmed", true).put("binding_cleanup_confirmed", true)
            .put("manager_uid", Process.myUid()).put("manager_pid", Process.myPid())
    }

    private fun identity(remote: IBinder): Pair<Int, Int> {
        val request = Parcel.obtain()
        val response = Parcel.obtain()
        try {
            request.writeInterfaceToken(PtyProbeService.INTERFACE)
            check(remote.transact(PtyProbeService.IDENTITY, request, response, 0))
            response.readException()
            return response.readInt() to response.readInt()
        } finally { request.recycle(); response.recycle() }
    }

    private fun measure(name: String, body: () -> JSONObject) {
        index++
        fun publish(code: Int, detail: String) = instrumentation.sendStatus(code, Bundle().apply {
            putString("id", "SucrunePtyCapability"); putString("class", PtyCapabilityChecks::class.java.name)
            putString("test", name); putInt("current", index); putInt("numtests", TOTAL); putString("stream", "\n$name: $detail\n")
        })
        publish(1, "Starting PTY measurement")
        try {
            val report = body()
            passed++; summary.append("$name: MEASURED $report\n"); publish(0, report.toString())
        } catch (failure: Exception) {
            failed++; summary.append("$name: FAILED $failure\n"); publish(-2, failure.toString())
        }
    }
    private companion object { const val TOTAL = 9 }
}
