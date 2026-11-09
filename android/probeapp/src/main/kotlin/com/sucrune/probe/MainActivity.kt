package com.sucrune.probe

import android.app.Activity
import android.content.ClipData
import android.content.ClipboardManager
import android.content.ComponentName
import android.content.Context
import android.content.Intent
import android.content.ServiceConnection
import android.graphics.Color
import android.graphics.Typeface
import android.os.Build
import android.os.Bundle
import android.os.Handler
import android.os.IBinder
import android.os.Looper
import android.os.Message
import android.os.Messenger
import android.os.RemoteException
import android.view.View
import android.widget.Button
import android.widget.LinearLayout
import android.widget.ScrollView
import android.widget.TextView
import android.widget.Toast
import java.io.IOException
import java.util.UUID
import org.json.JSONObject

class MainActivity : Activity() {
    private val main = Handler(Looper.getMainLooper())
    private lateinit var status: TextView
    private lateinit var output: TextView
    private lateinit var appButton: Button
    private lateinit var isolatedButton: Button
    private lateinit var elfAppButton: Button
    private lateinit var elfIsolatedButton: Button
    private var active: ProbeConnection? = null
    private var retiring: ProbeConnection? = null
    private var nextRequest = 0
    private var destroyed = false
    private var lastReport = ""
    private var exportSnapshot = ""
    private var terminalStatus = "就绪"
    private val timeout = Runnable {
        fail("timeout", "探针未在 15 秒内返回，结果未知。查看设备日志定位原因。")
    }
    private val replyHandler = object : Handler(Looper.getMainLooper()) {
        override fun handleMessage(message: Message) {
            val connection = active ?: return
            if (destroyed || message.what != ProbeService.RESULT || message.arg1 != connection.request) return
            try {
                val report = JSONObject(message.data.getString("report") ?: "")
                check(report.getString("request_id") == connection.requestId) { "Mismatched request identity" }
                check(report.getInt("schema_version") == 1) { "Unsupported report schema" }
                check(report.getString("probe") == connection.probe) { "Mismatched probe type" }
                val state = report.getString("status")
                check(state in setOf("passed", "failed", "unsupported")) { "Unknown probe status" }
                addRequestEvidence(report, connection)
                showReport(report)
                terminalStatus = if (state == "passed") {
                    if (connection.probe == ProbeService.PROBE_ELF) {
                        "通过 · 受控 ARM64 ELF 已执行"
                    } else {
                        "通过 · 仅证明本次探针机制成立"
                    }
                } else {
                    "未通过 · $state"
                }
                status.text = terminalStatus
            } catch (badReport: Exception) {
                fail("invalid_report", "返回的报告格式无效：${badReport.message}")
                return
            }
            closeConnection()
        }
    }
    private val replies = Messenger(replyHandler)

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        val content = LinearLayout(this).apply {
            orientation = LinearLayout.VERTICAL
            setPadding(dp(22), dp(18), dp(22), dp(22))
            setBackgroundColor(Color.rgb(245, 247, 251))
            setOnApplyWindowInsetsListener { view, insets ->
                val bars = insets.systemWindowInsets
                view.setPadding(dp(22) + bars.left, dp(18) + bars.top, dp(22) + bars.right, dp(22) + bars.bottom)
                insets
            }
        }
        content.addView(text("Sucrune", 30f).apply { setTypeface(Typeface.DEFAULT, Typeface.BOLD) })
        content.addView(button("打开项目终端") { startActivity(Intent(this, RuntimeActivity::class.java)) })
        content.addView(text("Android 10+ · 系统调用与 ELF 探针", 16f))
        content.addView(text("在独立进程中验证系统调用处理和内嵌 ARM64 ELF 的加载执行。仅运行受控样例，尚不支持任意 Linux 程序或不可信代码隔离。", 14f))
        appButton = button("系统调用 · 普通进程") { runProbe(false, ProbeService.PROBE_SYSCALL) }
        isolatedButton = button("系统调用 · 隔离进程") { runProbe(true, ProbeService.PROBE_SYSCALL) }
        content.addView(LinearLayout(this).apply {
            addView(appButton, LinearLayout.LayoutParams(0, -2, 1f))
            addView(isolatedButton, LinearLayout.LayoutParams(0, -2, 1f))
        })
        elfAppButton = button("ARM64 ELF · 普通进程") { runProbe(false, ProbeService.PROBE_ELF) }
        elfIsolatedButton = button("ARM64 ELF · 隔离进程") { runProbe(true, ProbeService.PROBE_ELF) }
        content.addView(LinearLayout(this).apply {
            addView(elfAppButton, LinearLayout.LayoutParams(0, -2, 1f))
            addView(elfIsolatedButton, LinearLayout.LayoutParams(0, -2, 1f))
        })
        status = text("就绪", 15f)
        content.addView(status)
        val actions = LinearLayout(this).apply {
            addView(button("复制报告") { copyReport() }, LinearLayout.LayoutParams(0, -2, 1f))
            addView(button("导出 JSON") { exportReport() }, LinearLayout.LayoutParams(0, -2, 1f))
        }
        content.addView(actions)
        output = text("尚未运行。这里会显示实际设备的探针结果。", 12f).apply {
            typeface = Typeface.MONOSPACE
            setTextIsSelectable(true)
        }
        val scroll = ScrollView(this).apply {
            isFillViewport = true
            addView(output)
        }
        content.addView(scroll, LinearLayout.LayoutParams(-1, 0, 1f))
        setContentView(content)
        lastReport = getPreferences(MODE_PRIVATE).getString("last_report", "") ?: ""
        exportSnapshot = savedInstanceState?.getString("export_snapshot") ?: ""
        if (lastReport.isNotEmpty()) {
            output.text = lastReport
            status.text = "上次报告 · 请重新运行验证当前环境"
        }
    }

    private fun runProbe(isolated: Boolean, probe: String) {
        if (active != null || retiring != null || destroyed) return
        val connection = ProbeConnection(++nextRequest,
            if (isolated) "isolated_service" else "application", probe)
        active = connection
        updateButtons()
        lastReport = ""
        output.text = "正在等待本次探针报告。"
        status.text = when {
            probe == ProbeService.PROBE_ELF && isolated -> "ARM64 ELF · 隔离进程 · 运行中"
            probe == ProbeService.PROBE_ELF -> "ARM64 ELF · 普通进程 · 运行中"
            isolated -> "系统调用 · 隔离进程 · 运行中"
            else -> "系统调用 · 普通进程 · 运行中"
        }
        val intent = Intent(this, if (isolated) IsolatedProbeService::class.java else AppProbeService::class.java)
        try {
            connection.bound = bindService(intent, connection, Context.BIND_AUTO_CREATE)
            if (!connection.bound) {
                fail("bind_failed", "系统未能绑定探针服务。")
                return
            }
            main.postDelayed(timeout, 15_000)
        } catch (failure: RuntimeException) {
            fail("bind_exception", failure.toString())
        }
    }

    private inner class ProbeConnection(val request: Int, val identity: String,
                                       val probe: String) : ServiceConnection {
        val requestId: String = UUID.randomUUID().toString()
        val startedAt: Long = System.currentTimeMillis()
        var bound = false
        var remote: Messenger? = null
        var binder: IBinder? = null
        var deathRecipient: IBinder.DeathRecipient? = null
        var dead = false
        val cleanupDeadline = Runnable {
            if (retiring !== this || destroyed) return@Runnable
            if (binder?.isBinderAlive != true) {
                handleBinderDeath(this)
            } else {
                // Never allow the next probe into a process whose death is not
                // established. The service also owns an independent watchdog.
                status.text = getString(R.string.probe_cleanup_delayed, terminalStatus)
                sendStop(this)
            }
        }

        override fun onServiceConnected(name: ComponentName, service: IBinder) {
            if (active !== this || destroyed) return
            binder = service
            remote = Messenger(service)
            val recipient = IBinder.DeathRecipient { main.post { handleBinderDeath(this) } }
            deathRecipient = recipient
            try {
                service.linkToDeath(recipient, 0)
                val start = Message.obtain(null, ProbeService.RUN).apply {
                    arg1 = request
                    replyTo = replies
                    data = Bundle().apply {
                        putString("request_id", requestId)
                        putString("probe", probe)
                    }
                }
                remote?.send(start)
            } catch (failure: RemoteException) {
                dead = !service.isBinderAlive
                fail("ipc_failed", failure.toString())
            }
        }

        override fun onServiceDisconnected(name: ComponentName) {
            if (binder?.isBinderAlive != true) {
                handleBinderDeath(this)
            } else if (active === this) {
                fail("service_disconnected", "探针服务连接丢失，结果未知。")
            }
        }

        override fun onBindingDied(name: ComponentName) {
            if (active === this) fail("binding_died", "服务绑定失效，结果未知。")
        }

        override fun onNullBinding(name: ComponentName) {
            if (active === this) fail("null_binding", "服务没有返回可用接口。")
        }
    }

    private fun handleBinderDeath(connection: ProbeConnection) {
        connection.dead = true
        detachDeathRecipient(connection)
        if (destroyed) return
        if (active === connection) {
            fail("process_lost", "探针进程在返回结果前退出，不能判定通过。请检查 logcat 或崩溃记录。")
        } else if (retiring === connection) {
            finishRetiring(connection)
        }
    }

    private fun addRequestEvidence(report: JSONObject, connection: ProbeConnection) {
        report.put("request_id", connection.requestId)
        report.put("requested_identity", connection.identity)
        report.put("started_at_unix_ms", connection.startedAt)
        report.put("reported_at_unix_ms", System.currentTimeMillis())
    }

    private fun fail(stage: String, description: String) {
        val connection = active ?: return
        val report = JSONObject()
            .put("schema_version", 1)
            .put("probe", connection.probe)
            .put("status", "unknown")
            .put("stage", stage)
            .put("message", description)
            .put("client_android_api", Build.VERSION.SDK_INT)
            .put("client_target_sdk", applicationInfo.targetSdkVersion)
        addRequestEvidence(report, connection)
        showReport(report)
        terminalStatus = "未完成 · $stage"
        status.text = terminalStatus
        closeConnection()
    }

    private fun showReport(report: JSONObject) {
        lastReport = report.toString(2)
        output.text = lastReport
        getPreferences(MODE_PRIVATE).edit().putString("last_report", lastReport).apply()
    }

    private fun closeConnection() {
        main.removeCallbacks(timeout)
        val connection = active
        active = null
        if (connection == null) {
            updateButtons()
            return
        }
        // Register the retiring state before STOP: Binder death can happen as
        // soon as the service processes that message.
        retiring = connection
        sendStop(connection)
        if (connection.bound) {
            unbindService(connection)
            connection.bound = false
        }
        if (connection.dead || connection.binder?.isBinderAlive != true) {
            finishRetiring(connection)
        } else {
            if (!destroyed) status.text = getString(R.string.probe_cleanup_waiting, terminalStatus)
            main.postDelayed(connection.cleanupDeadline, 25_000)
            updateButtons()
        }
    }

    private fun sendStop(connection: ProbeConnection) {
        try {
            connection.remote?.send(Message.obtain(null, ProbeService.STOP))
        } catch (_: RemoteException) {
            if (connection.binder?.isBinderAlive != true) connection.dead = true
        }
    }

    private fun finishRetiring(connection: ProbeConnection) {
        main.removeCallbacks(connection.cleanupDeadline)
        detachDeathRecipient(connection)
        if (retiring === connection) retiring = null
        if (!destroyed) {
            status.text = terminalStatus
            updateButtons()
        }
    }

    private fun detachDeathRecipient(connection: ProbeConnection) {
        val recipient = connection.deathRecipient ?: return
        connection.deathRecipient = null
        try {
            connection.binder?.unlinkToDeath(recipient, 0)
        } catch (_: NoSuchElementException) {
            // It may already have been removed after the process died.
        }
    }

    private fun updateButtons() {
        if (!::appButton.isInitialized || destroyed) return
        val ready = active == null && retiring == null
        appButton.isEnabled = ready
        isolatedButton.isEnabled = ready
        elfAppButton.isEnabled = ready
        elfIsolatedButton.isEnabled = ready
    }

    private fun copyReport() {
        if (lastReport.isEmpty()) return
        val clipboard = getSystemService(CLIPBOARD_SERVICE) as ClipboardManager
        clipboard.setPrimaryClip(ClipData.newPlainText("Sucrune probe", lastReport))
        Toast.makeText(this, "报告已复制", Toast.LENGTH_SHORT).show()
    }

    private fun exportReport() {
        if (lastReport.isEmpty()) return
        exportSnapshot = lastReport
        val intent = Intent(Intent.ACTION_CREATE_DOCUMENT).apply {
            addCategory(Intent.CATEGORY_OPENABLE)
            type = "application/json"
            putExtra(Intent.EXTRA_TITLE, "sucrune-probe.json")
        }
        startActivityForResult(intent, EXPORT)
    }

    override fun onActivityResult(requestCode: Int, resultCode: Int, data: Intent?) {
        super.onActivityResult(requestCode, resultCode, data)
        val destination = data?.data ?: return
        if (requestCode != EXPORT || resultCode != RESULT_OK || exportSnapshot.isEmpty()) return
        try {
            (contentResolver.openOutputStream(destination) ?: throw IOException("Cannot open output")).use {
                it.write(exportSnapshot.toByteArray(Charsets.UTF_8))
            }
            Toast.makeText(this, "报告已导出", Toast.LENGTH_SHORT).show()
        } catch (failure: IOException) {
            Toast.makeText(this, "导出失败：${failure.message}", Toast.LENGTH_LONG).show()
        }
    }

    override fun onSaveInstanceState(outState: Bundle) {
        outState.putString("export_snapshot", exportSnapshot)
        super.onSaveInstanceState(outState)
    }

    override fun onDestroy() {
        destroyed = true
        closeConnection()
        retiring?.let { detachDeathRecipient(it) }
        main.removeCallbacksAndMessages(null)
        replyHandler.removeCallbacksAndMessages(null)
        super.onDestroy()
    }

    private fun dp(value: Int): Int = (value * resources.displayMetrics.density + 0.5f).toInt()

    private fun text(value: String, size: Float): TextView = TextView(this).apply {
        text = value
        textSize = size
        setTextColor(Color.rgb(26, 43, 64))
        setPadding(0, dp(8), 0, dp(8))
    }

    private fun button(label: String, action: (View) -> Unit): Button = Button(this).apply {
        text = label
        isAllCaps = false
        setOnClickListener { action(it) }
    }

    companion object { private const val EXPORT = 7 }
}
