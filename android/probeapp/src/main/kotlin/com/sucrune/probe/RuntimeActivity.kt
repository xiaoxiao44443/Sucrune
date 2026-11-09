package com.sucrune.probe

import android.app.Activity
import android.graphics.Typeface
import android.os.Bundle
import android.os.Handler
import android.os.Looper
import android.text.InputType
import android.view.View
import android.widget.AdapterView
import android.widget.ArrayAdapter
import android.widget.Button
import android.widget.EditText
import android.widget.LinearLayout
import android.widget.ScrollView
import android.widget.Spinner
import android.widget.TextView
import org.json.JSONObject
import java.util.concurrent.Executors

/** Small real client of the same manager API intended for later Agent integration. */
class RuntimeActivity : Activity() {
    private val main = Handler(Looper.getMainLooper())
    private val tasks = Executors.newSingleThreadExecutor()
    private lateinit var client: RuntimeClient
    private lateinit var environments: Spinner
    private lateinit var executionMode: Spinner
    private lateinit var programEnvironment: EditText
    private lateinit var programInput: EditText
    private lateinit var script: EditText
    private lateinit var cwd: EditText
    private lateinit var timeout: EditText
    private lateinit var status: TextView
    private lateinit var output: TextView
    private lateinit var runButton: Button
    private lateinit var stopButton: Button
    private var choices = emptyList<Pair<String, String>>()
    private var selectedEnv: String? = null
    private var executionId: String? = null
    private var destroyed = false
    private var refreshing = false
    private var pendingRun = false
    private var restoreEnv: String? = null
    private var programMode = false
    private var selectedProgramId = ""
    private var programChoices = emptyList<Pair<String, String>>()
    private val argumentTexts = linkedMapOf("musl-smoke" to "selftest\n参数中文🙂", "lua" to "-")
    private val inputTexts = linkedMapOf("musl-smoke" to "", "lua" to "print('Hello from Lua')\n")
    private var shellText = "pwd\nhelp"
    private val poll = Runnable { refreshExecution() }

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        client = RuntimeClient.get(this)
        restoreEnv = savedInstanceState?.getString("environment")
            ?: getPreferences(MODE_PRIVATE).getString("environment", null)
        val content = LinearLayout(this).apply {
            orientation = LinearLayout.VERTICAL
            val pad = (16 * resources.displayMetrics.density).toInt()
            setPadding(pad, pad, pad, pad)
            setOnApplyWindowInsetsListener { view, insets ->
                val bars = insets.systemWindowInsets
                view.setPadding(pad + bars.left, pad + bars.top, pad + bars.right, pad + bars.bottom)
                insets
            }
        }
        content.addView(label("Sucrune · 项目终端", 24f))
        content.addView(label("项目文件持久保存；运行可取消、有时限。选择 Shell 或内置 Linux 工具，参数与标准输入分别填写。", 13f))
        environments = Spinner(this)
        content.addView(environments)
        val name = EditText(this).apply { hint = "新项目名称"; isSingleLine = true }
        content.addView(LinearLayout(this).apply {
            addView(name, LinearLayout.LayoutParams(0, -2, 1f))
            addView(button("新建") {
                val requestedName = name.text.toString().trim()
                perform {
                    val environment = client.createEnvironment(requestedName)
                    main.post {
                        if (!destroyed) { name.setText(""); loadEnvironments(environment.getString("id")) }
                    }
                }
            })
        })
        cwd = EditText(this).apply { hint = "工作目录"; isSingleLine = true; setText(savedInstanceState?.getString("cwd") ?: "/") }
        timeout = EditText(this).apply {
            hint = "超时秒数"; isSingleLine = true; inputType = InputType.TYPE_CLASS_NUMBER
            setText(savedInstanceState?.getString("timeout") ?: (RuntimeClient.DEFAULT_TIMEOUT_MS / 1_000).toString())
        }
        content.addView(LinearLayout(this).apply {
            addView(cwd, LinearLayout.LayoutParams(0, -2, 2f))
            addView(timeout, LinearLayout.LayoutParams(0, -2, 1f))
        })
        val catalog = client.listPrograms()
        programChoices = (0 until catalog.length()).map {
            val item = catalog.getJSONObject(it)
            val id = item.getString("program_id")
            id to "Linux 程序 · ${item.getString("name")} ${item.optString("version")}".trim()
        }
        programChoices.forEach { (id, _) ->
            argumentTexts[id] = getPreferences(MODE_PRIVATE).getString("args_$id", argumentTexts[id] ?: "") ?: ""
        }
        val restoredProgram = savedInstanceState?.getString("program_id") ?: ""
        if (restoredProgram.isNotEmpty()) {
            argumentTexts[restoredProgram] = savedInstanceState?.getString("program_arguments") ?: argumentTexts[restoredProgram] ?: ""
        }
        executionMode = Spinner(this).apply {
            adapter = ArrayAdapter(this@RuntimeActivity, android.R.layout.simple_spinner_dropdown_item,
                listOf("Shell 脚本") + programChoices.map { it.second })
        }
        content.addView(executionMode)
        shellText = savedInstanceState?.getString("shell_text")
            ?: getPreferences(MODE_PRIVATE).getString("script", "pwd\nhelp") ?: "pwd\nhelp"
        script = EditText(this).apply {
            hint = "输入 Shell 脚本，例如 echo hello > note.txt; cat note.txt"
            minLines = 3; maxLines = 5; typeface = Typeface.MONOSPACE
            inputType = InputType.TYPE_CLASS_TEXT or InputType.TYPE_TEXT_FLAG_MULTI_LINE or InputType.TYPE_TEXT_FLAG_NO_SUGGESTIONS
            setText(shellText)
        }
        content.addView(script)
        programEnvironment = EditText(this).apply {
            hint = "环境变量：每行 NAME=value"
            minLines = 1; maxLines = 2; typeface = Typeface.MONOSPACE
            inputType = InputType.TYPE_CLASS_TEXT or InputType.TYPE_TEXT_FLAG_MULTI_LINE or InputType.TYPE_TEXT_FLAG_NO_SUGGESTIONS
            setText(savedInstanceState?.getString("program_environment")
                ?: getPreferences(MODE_PRIVATE).getString("program_environment", "SUCRUNE_TEST=环境中文🙂"))
            visibility = View.GONE
        }
        content.addView(programEnvironment)
        programInput = EditText(this).apply {
            hint = "标准输入（UTF-8 文本；结束后自动发送 EOF）"
            isSaveEnabled = false // Input contents stay in memory, never in saved-state Bundles.
            minLines = 2; maxLines = 3; typeface = Typeface.MONOSPACE
            inputType = InputType.TYPE_CLASS_TEXT or InputType.TYPE_TEXT_FLAG_MULTI_LINE or InputType.TYPE_TEXT_FLAG_NO_SUGGESTIONS
            visibility = View.GONE
        }
        content.addView(programInput)
        executionMode.onItemSelectedListener = object : AdapterView.OnItemSelectedListener {
            override fun onItemSelected(parent: AdapterView<*>?, view: View?, position: Int, id: Long) {
                val nextProgram = programChoices.getOrNull(position - 1)?.first ?: ""
                if (nextProgram != selectedProgramId) {
                    if (programMode) {
                        argumentTexts[selectedProgramId] = script.text.toString()
                        inputTexts[selectedProgramId] = programInput.text.toString()
                    } else shellText = script.text.toString()
                    selectedProgramId = nextProgram
                    programMode = nextProgram.isNotEmpty()
                    script.setText(if (programMode) argumentTexts[nextProgram] ?: "" else shellText)
                    programInput.setText(inputTexts[nextProgram] ?: "")
                }
                script.hint = if (programMode) "参数每行一个（不含程序名）；Lua 使用 - 从标准输入读取脚本"
                    else "输入 Shell 脚本，help 查看命令"
                programEnvironment.visibility = if (programMode) View.VISIBLE else View.GONE
                programInput.visibility = if (programMode) View.VISIBLE else View.GONE
            }
            override fun onNothingSelected(parent: AdapterView<*>?) {}
        }
        executionMode.setSelection(programChoices.indexOfFirst { it.first == restoredProgram } + 1)
        runButton = button("运行") { runScript() }
        stopButton = button("取消") {
            executionId?.let { client.cancel(it); status.text = "正在等待工作进程退出…" }
        }
        content.addView(LinearLayout(this).apply {
            addView(runButton, LinearLayout.LayoutParams(0, -2, 1f))
            addView(stopButton, LinearLayout.LayoutParams(0, -2, 1f))
            addView(button("刷新项目") { loadEnvironments(selectedEnv) }, LinearLayout.LayoutParams(0, -2, 1f))
        })
        status = label("正在读取项目…", 14f)
        content.addView(status)
        output = label("", 12f).apply { typeface = Typeface.MONOSPACE; setTextIsSelectable(true) }
        content.addView(ScrollView(this).apply { addView(output) }, LinearLayout.LayoutParams(-1, 0, 1f))
        setContentView(content)
        environments.onItemSelectedListener = object : AdapterView.OnItemSelectedListener {
            override fun onItemSelected(parent: AdapterView<*>?, view: View?, position: Int, id: Long) {
                choices.getOrNull(position)?.first?.let { selected ->
                    if (selected != selectedEnv) {
                        selectedEnv = selected
                        getPreferences(MODE_PRIVATE).edit().putString("environment", selected).apply()
                        attachLatest(selected)
                    }
                }
            }
            override fun onNothingSelected(parent: AdapterView<*>?) {}
        }
        buttons(false)
        loadEnvironments(restoreEnv)
    }

    private fun loadEnvironments(preferred: String?) {
        perform {
            val records = client.listEnvironments()
            val loaded = (0 until records.length()).map {
                val record = records.getJSONObject(it)
                record.getString("id") to record.getString("name")
            }
            main.post {
                if (destroyed) return@post
                choices = loaded
                environments.adapter = ArrayAdapter(this, android.R.layout.simple_spinner_dropdown_item,
                    loaded.map { it.second })
                val index = loaded.indexOfFirst { it.first == preferred }.coerceAtLeast(0)
                if (loaded.isNotEmpty()) {
                    environments.setSelection(index)
                    selectedEnv = loaded[index].first
                    attachLatest(loaded[index].first)
                } else {
                    selectedEnv = null; executionId = null
                    status.text = "请先新建项目"; output.text = ""; buttons(false)
                }
            }
        }
    }

    private fun attachLatest(envId: String) {
        main.removeCallbacks(poll)
        executionId = null
        output.text = ""
        perform {
            val records = client.listExecutions(envId)
            val latest = (0 until records.length()).map { records.getJSONObject(it) }
                .maxByOrNull { it.getString("created_at") }
            main.post {
                if (destroyed || selectedEnv != envId) return@post
                executionId = latest?.getString("execution_id")
                if (latest == null) { status.text = "项目就绪"; buttons(false) }
                else refreshExecution()
            }
        }
    }

    private fun runScript() {
        val envId = selectedEnv ?: return
        val text = script.text.toString()
        val runProgram = programMode
        val programId = selectedProgramId
        val inputText = programInput.text.toString()
        val environmentText = programEnvironment.text.toString()
        val directory = cwd.text.toString()
        val seconds = timeout.text.toString().toLongOrNull()
        val maxSeconds = RuntimeClient.DEFAULT_TIMEOUT_MS / 1_000
        if (seconds == null || seconds !in 1..maxSeconds) { status.text = "超时须为 1 至 ${maxSeconds} 秒"; return }
        pendingRun = true; buttons(true)
        if (runProgram) { argumentTexts[programId] = text; inputTexts[programId] = inputText } else shellText = text
        getPreferences(MODE_PRIVATE).edit().putString("script", shellText)
            .putString("args_$programId", text)
            .putString("program_environment", environmentText).apply()
        perform {
            val id = if (runProgram) client.executeProgram(envId, programId,
                if (text.isEmpty()) emptyList() else text.lines(),
                environmentText.lines().filter { it.isNotEmpty() }, directory, seconds * 1_000,
                inputText.toByteArray(Charsets.UTF_8))
            else client.execute(envId, text, directory, seconds * 1_000)
            main.post {
                if (destroyed) return@post
                pendingRun = false
                if (selectedEnv == envId) { executionId = id; refreshExecution() }
                else buttons(false)
            }
        }
    }

    private fun refreshExecution() {
        if (destroyed || refreshing) return
        val id = executionId ?: return
        refreshing = true
        tasks.execute {
            try {
                val report = client.getExecution(id)
                main.post {
                    refreshing = false
                    if (destroyed) return@post
                    if (executionId != id) { refreshExecution(); return@post }
                    show(report)
                    if (report.getString("state") == "running") main.postDelayed(poll, 250)
                }
            } catch (failure: Exception) { main.post { refreshing = false; showError(failure) } }
        }
    }

    private fun show(record: JSONObject) {
        val state = record.getString("state")
        val phase = record.optJSONObject("runtime")?.optString("phase", "") ?: ""
        val exit = if (record.has("exit_code")) " · exit ${record.getInt("exit_code")}" else ""
        status.text = getString(R.string.runtime_status, state, phase, exit)
        val error = record.optJSONObject("runtime")?.optString("failure", "")
            ?: record.optJSONObject("result")?.optString("failure", "") ?: ""
        val native = record.optJSONObject("result")?.optJSONObject("native")
        val detail = native?.optString("message", "") ?: ""
        output.text = buildString {
            append(record.optString("stdout"))
            val stderr = record.optString("stderr")
            if (stderr.isNotEmpty()) append("\n[stderr]\n").append(stderr)
            if (record.optBoolean("truncated")) append("\n[输出已截断：每流最多保留 64 KiB]\n")
            if (error.isNotEmpty()) append("\n[管理器] ").append(error)
            if (state == "lost" && detail.isNotEmpty()) append("\n[运行时] ").append(detail)
            append("\n\n").append(record.getString("execution_id"))
        }
        buttons(state == "running")
    }

    private fun perform(action: () -> Unit) {
        tasks.execute { try { action() } catch (failure: Throwable) { main.post { showError(failure) } } }
    }
    private fun showError(failure: Throwable) {
        if (destroyed) return
        pendingRun = false
        status.text = getString(R.string.runtime_error, failure.message ?: failure.toString())
        buttons(false)
    }
    private fun buttons(running: Boolean) {
        runButton.isEnabled = selectedEnv != null && !running && !pendingRun
        stopButton.isEnabled = executionId != null && running
    }
    private fun label(value: String, size: Float) = TextView(this).apply { text = value; textSize = size }
    private fun button(value: String, action: () -> Unit) = Button(this).apply {
        text = value; isAllCaps = false; setOnClickListener { action() }
    }
    override fun onSaveInstanceState(outState: Bundle) {
        if (programMode) argumentTexts[selectedProgramId] = script.text.toString() else shellText = script.text.toString()
        outState.putString("environment", selectedEnv); outState.putString("shell_text", shellText)
        outState.putString("program_id", selectedProgramId); outState.putString("program_arguments", script.text.toString())
        outState.putString("program_environment", programEnvironment.text.toString())
        outState.putString("cwd", cwd.text.toString()); outState.putString("timeout", timeout.text.toString())
        super.onSaveInstanceState(outState)
    }
    override fun onDestroy() {
        destroyed = true
        main.removeCallbacksAndMessages(null)
        tasks.shutdown()
        // Manager and drainers intentionally survive closing this Activity.
        super.onDestroy()
    }
}
