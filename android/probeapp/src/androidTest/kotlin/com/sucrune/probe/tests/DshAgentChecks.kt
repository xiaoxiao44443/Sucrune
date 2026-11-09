package com.sucrune.probe.tests

import android.os.Process
import android.os.SystemClock
import android.util.JsonReader
import android.util.JsonToken
import com.sucrune.probe.RuntimeClient
import com.sucrune.probe.ExecutionStdout
import com.sucrune.probe.RuntimeExceptionWithCode
import org.json.JSONArray
import org.json.JSONObject
import java.io.StringReader
import java.io.ByteArrayOutputStream
import java.nio.ByteBuffer
import java.nio.charset.CodingErrorAction
import java.util.UUID

/** Public route selectors only: credentials must never enter this value or ordinary execution env. */
internal data class DshAgentTarget(val provider: String, val model: String, val maxTokens: Int = 2048)

internal enum class DshAgentStage {
    PREREQUISITE, PREPARE, CREDENTIAL_WAIT, CREDENTIAL_RECEIVED, LAUNCH, INITIALIZE, RESUME, PROMPT, WAIT,
    MODEL_STREAM, TOOL_WRITE, TOOL_READ, TOOL_BASH, TOOL_OTHER, TOOL_RESULT, TURN_END, TURN_EVIDENCE, SHUTDOWN,
    TERMINAL_EVIDENCE, ARTIFACTS, JSONL, CANCEL_OBSERVE, CANCEL, REUSE
}
internal enum class DshAgentReason {
    PROGRESS, RPC_ERROR, TURN_ERROR, CAPTURE_LIMIT, PARTIAL_FRAME, EXIT_BEFORE_REPLY, DEADLINE, TOOL_ERROR,
    ASSERTION, RUNTIME_ERROR, INVALID_SCHEMA, PROTOCOL_IO, CLEANUP, UNEXPECTED,
    HISTORY_SELECTION, HISTORY_SIZE, HISTORY_READ, HISTORY_FRAMING, HISTORY_IDENTITY,
    HISTORY_PATH, HISTORY_PREFIX, HISTORY_APPEND, HISTORY_MESSAGE
}
internal enum class DshProviderError {
    NONE, AUTH, QUOTA, RATE_LIMIT, SERVER, TRANSPORT, MISSING_CREDENTIAL, INVALID_CREDENTIAL,
    INVALID_REQUEST, CONTEXT_WINDOW_EXCEEDED, EMPTY_RESPONSE, TOOL_ACTIVATION_FAILED, UNKNOWN, OTHER
}
/** Only enums and bounded counters cross the instrumentation boundary. */
internal data class DshAgentDiagnostic(
    val stage: DshAgentStage, val reason: DshAgentReason = DshAgentReason.PROGRESS,
    val error: DshProviderError = DshProviderError.NONE, val eventCount: Int = 0, val toolCount: Int = 0,
    val httpStatus: Int = 0, val rpcCode: Int = 0
) {
    init {
        require(eventCount in 0..2048 && toolCount in 0..8 && (httpStatus == 0 || httpStatus in 100..599))
        require(rpcCode in setOf(0, -32700, -32600, -32601, -32602, -32603, -32000))
    }
}
private class DshObservationFailure(val reason: DshAgentReason) : IllegalStateException()

private inline fun <T> historyCheck(reason: DshAgentReason, block: () -> T): T = try {
    block()
} catch (_: Exception) {
    throw DshObservationFailure(reason)
}

/** The original SDK exposes the tool identity and optional reason, not its arguments, in an approval request. */
internal data class DshAgentApproval(
    val sessionId: String,
    val toolName: String,
    val callId: String,
    val arguments: JSONObject,
    val reason: String?
)

internal enum class DshAgentApprovalOutcome(val wire: String) {
    ALLOWED_ONCE("allowed-once"), REJECTED("rejected"), CANCELLED("cancelled")
}

/**
 * Four opt-in checks, deliberately not wired into LinuxChecks until the caller
 * supplies the real model route, private non-persisted credential channel,
 * network, original Bash/PTY/process support and the verified SDK fixture.
 * No credentials are read here. No mock or desktop Harness execution is used.
 * environment() returns an installed, idle, caller-owned test environment;
 * startInteractive owns execution tracking and must launch original Linux Node
 * with linux-jit, the rootfs library path and the supplied harmless environment.
 * The caller owns project cleanup. A real endpoint must be independently bound
 * to this run before claiming real-model acceptance: protocol tags alone do not
 * distinguish a mock endpoint. Approval is opt-in, never automatic; absent an
 * answerer requests are rejected. The stock profile normally requests none.
 */
internal fun dshAgentCases(
    client: RuntimeClient,
    environment: () -> String,
    startInteractive: (String, List<String>, Long, String, List<String>, ExecutionStdout) -> String,
    target: DshAgentTarget,
    proveReuse: (String) -> Unit,
    approve: ((DshAgentApproval) -> DshAgentApprovalOutcome)? = null,
    diagnostic: (String, DshAgentDiagnostic) -> Unit = { _, _ -> }
): List<Pair<String, () -> String>> {
    require(target.provider.isNotBlank() && target.model.isNotBlank() && target.maxTokens in 256..4096)
    val suffix = UUID.randomUUID().toString().replace("-", "")
    val sessionId = "sucrune-$suffix"
    val marker = "sucrune_agent_${UUID.randomUUID().toString().replace("-", "")}"
    val cwd = "/workspace/dsh-agent-$suffix"
    val home = "$cwd/home"
    val work = "$cwd/work"
    val patch = "$cwd/agent.patch.yml"
    val entrypoint = "/opt/dsh/node_modules/@deepseek-ai/dsh/lib/bin.js"
    val inputFile = "$work/agent-input.txt"
    val outputFile = "$work/agent-shell.txt"
    // Only Bash builtins are needed for this specific shell command. This still
    // exercises the unchanged persistent-bash/node-pty/forkpty implementation.
    val shellCommand = "IFS= read -r sucrune_line < agent-input.txt && printf '%s\\n' \"\$sucrune_line\" > agent-shell.txt && printf 'SUCRUNE_SHELL_OK\\n'"
    val env = listOf("HOME=$home", "DSH_HOME=$home/.dsh", "TMPDIR=$cwd/tmp",
        "SHELL=/bin/bash", "PATH=/usr/bin:/bin",
        "NARB_NATIVE_CACHE_DIR=$cwd/native-cache", "DSH_TELEMETRY_DISABLED=1")
    val argv = listOf(entrypoint, "--profile", "sdk-minimal", "--patch", patch)
    var project: String? = null
    var firstSucceeded = false
    var firstPid = -1
    var firstWorker = -1
    var resumedWorker = -1
    var resumeSucceeded = false
    var activeCase = ""
    var evidenceStage = DshAgentStage.PREREQUISITE
    var observedEvents = 0
    var observedTools = 0
    val emitted = HashSet<DshAgentStage>()
    fun progress(stage: DshAgentStage, events: Int = observedEvents, tools: Int = observedTools) {
        evidenceStage = stage
        observedEvents = maxOf(observedEvents, events.coerceIn(0, 2048))
        observedTools = maxOf(observedTools, tools.coerceIn(0, 8))
        if (emitted.add(stage)) diagnostic(activeCase, DshAgentDiagnostic(stage, eventCount = observedEvents, toolCount = observedTools))
    }
    var durablePath: String? = null
    var durableBefore = ByteArray(0)
    var firstMessageId = ""
    var firstCalls = emptySet<String>()

    fun checkArtifacts(id: String) {
        progress(DshAgentStage.ARTIFACTS)
        val expected = "$marker\n".toByteArray(Charsets.UTF_8)
        check(client.readFile(id, inputFile).contentEquals(expected)) { "Agent write artifact differs from the requested marker" }
        check(client.readFile(id, outputFile).contentEquals(expected)) { "Bash artifact differs from the file tool artifact" }
    }

    fun sessionLog(id: String): Pair<String, ByteArray> {
        progress(DshAgentStage.JSONL)
        val directory = "$home/.dsh/sessions/--workspace-dsh-agent-$suffix-work--/$sessionId"
        val candidate = historyCheck(DshAgentReason.HISTORY_SELECTION) {
            val entries = client.listFiles(id, directory).getJSONArray("entries")
            (0 until entries.length()).map { entries.getJSONObject(it) }.single {
                it.getString("kind") == "file" && it.getString("name").matches(Regex("session(?:\\.v[1-9][0-9]*)?\\.jsonl"))
            }
        }
        val size = historyCheck(DshAgentReason.HISTORY_SIZE) {
            candidate.getLong("size").also { check(it in 1..1_048_576) }
        }
        val path = "$directory/${candidate.getString("name")}"
        val bytes = historyCheck(DshAgentReason.HISTORY_READ) { client.readFile(id, path) }
        historyCheck(DshAgentReason.HISTORY_SIZE) { check(bytes.size.toLong() == size) }
        val text = historyCheck(DshAgentReason.HISTORY_FRAMING) {
            check(bytes.isNotEmpty() && bytes.last() == 10.toByte())
            val decoded = Charsets.UTF_8.newDecoder().onMalformedInput(CodingErrorAction.REPORT)
                .onUnmappableCharacter(CodingErrorAction.REPORT).decode(ByteBuffer.wrap(bytes)).toString()
            val lines = decoded.dropLast(1).split('\n')
            check(lines.isNotEmpty() && lines.size <= 16_384)
            lines.forEach { check(it.isNotEmpty()); agentJsonObject(it) }
            decoded
        }
        historyCheck(DshAgentReason.HISTORY_IDENTITY) {
            check(text.contains(sessionId) && text.contains(marker) && text.contains(firstMessageId))
            check(firstCalls.all(text::contains))
        }
        return path to bytes
    }

    fun checkPrefix(path: String, bytes: ByteArray) {
        historyCheck(DshAgentReason.HISTORY_PATH) { check(path == durablePath) }
        historyCheck(DshAgentReason.HISTORY_PREFIX) {
            check(bytes.size >= durableBefore.size && durableBefore.indices.all { bytes[it] == durableBefore[it] })
        }
    }

    fun runAgent(id: String, resume: Boolean): DshAgentRun {
        val deadline = SystemClock.elapsedRealtime() + 240_000L
        val wire = DshAgentWire(client, sessionId, target, deadline, approve, ::progress)
        var primary: Throwable? = null
        try {
            progress(DshAgentStage.LAUNCH)
            wire.executionId = startInteractive(id, argv, 230_000L, work, env, wire.stdout)
            wire.request("initialize", JSONObject().put("cwd", work).put("provider", target.provider)
                .put("model", target.model).put("maxTokens", target.maxTokens).put("approvalRequests", true))
                .getJSONObject("serverInfo").also {
                    check(it.getString("name") == "deepseek-harness-sdk-runtime" && it.getString("version") == "0.0.1")
                }
            if (resume) check(wire.request("session/resume", JSONObject().put("sessionId", sessionId)).length() == 0)
            val prompt = if (resume) {
                "This is a continuation after restarting the process. Do not call any tool. " +
                    "Reply with only the exact random sucrune_agent_ marker from my previous message in this session."
            } else {
                "Perform exactly this small validation in $work. Do not inspect credentials, the environment, or any other directory. " +
                    "Use the write tool (not shell) to create $inputFile with exactly one line: $marker followed by a newline. " +
                    "Use the read tool to read that file. Then use the bash tool exactly once with the exact command between these delimiters:\n" +
                    "BEGIN_COMMAND\n$shellCommand\nEND_COMMAND\n" +
                    "Do not use any other tools or commands. Wait for each successful result. " +
                    "Finally reply only SUCRUNE_AGENT_OK and the marker. Remember the marker for the next turn."
            }
            val receipt = wire.request("session/prompt", JSONObject().put("sessionId", sessionId)
                .put("contentBlocks", JSONArray().put(JSONObject().put("type", "text").put("text", prompt))))
            val messageId = receipt.getString("messageId")
            check(messageId.isNotEmpty()) { "Original prompt returned no durable message identity" }
            check(wire.request("session/wait", JSONObject().put("sessionId", sessionId)).length() == 0)
            progress(DshAgentStage.TURN_EVIDENCE)
            val proof = wire.assertTurn(messageId, marker, resume, inputFile, shellCommand)
            check(wire.request("shutdown", JSONObject()).length() == 0)
            val record = wire.awaitExit()
            progress(DshAgentStage.TERMINAL_EVIDENCE)
            val pid = checkDshAgentCompletion(record)
            check(record.getJSONObject("result").getInt("stdin_bytes_accepted") == wire.acceptedBytes &&
                record.getJSONObject("result").getInt("stdin_bytes_written") == wire.acceptedBytes)
            return DshAgentRun(pid, record.getJSONObject("result").getJSONObject("worker").getInt("pid"), messageId, proof, wire.approvalCount)
        } catch (failure: Throwable) {
            primary = failure
            throw failure
        } finally {
            try { wire.closeAndReap() } catch (cleanup: Throwable) {
                if (primary == null) throw cleanup else primary.addSuppressed(cleanup)
            }
        }
    }

    val cases: List<Pair<String, () -> String>> = listOf(
        "linux_dsh_agent_prepare" to {
            progress(DshAgentStage.PREPARE)
            val id = environment()
            listOf(cwd, work, home, "$home/.dsh", "$cwd/tmp", "$cwd/native-cache").forEach { client.makeDirectory(id, it) }
            check(client.listFiles(id, work).getJSONArray("entries").length() == 0)
            check(client.listFiles(id, "$home/.dsh").getJSONArray("entries").length() == 0)
            // A documented invocation overlay, not a mutation of any original
            // package. Stock sdk-minimal already uses danger-full-access; this
            // check does not change that mode or claim an inner security fence.
            val overlay = "- id: tool-fs\n  config:\n    read: true\n    write: true\n    edit: true\n"
            client.writeFile(id, patch, overlay.toByteArray(Charsets.UTF_8))
            check(client.readFile(id, patch).toString(Charsets.UTF_8) == overlay)
            project = id
            "Prepared original sdk-minimal with a documented file-tools overlay and fresh private HOME/workspace; no model call yet"
        },
        "linux_dsh_agent_model_file_shell" to {
            val id = checkNotNull(project) { "Agent preparation prerequisite failed; workflow not evaluated" }
            val run = runAgent(id, resume = false)
            firstMessageId = run.messageId
            firstCalls = run.calls
            checkArtifacts(id)
            val (path, bytes) = sessionLog(id)
            durablePath = path
            durableBefore = bytes
            firstPid = run.pid
            firstWorker = run.workerPid
            firstSucceeded = true
            "Original Agent completed a model turn with paired write/read/bash results, independently verified two artifacts and durable JSONL; " +
                "runner=${run.pid}, session=$sessionId, calls=${run.calls.size}, approvals=${run.approvals}, history_bytes=${bytes.size}; " +
                "zero approval requests does not establish an approval workflow"
        },
        "linux_dsh_agent_restart_resume" to {
            check(firstSucceeded) { "Agent workflow prerequisite failed; restart/resume not evaluated" }
            val id = checkNotNull(project)
            val run = runAgent(id, resume = true)
            check(run.pid != firstPid) { "Session resume did not use a new native runner process" }
            checkArtifacts(id)
            val (path, bytes) = sessionLog(id)
            checkPrefix(path, bytes)
            historyCheck(DshAgentReason.HISTORY_APPEND) { check(bytes.size > durableBefore.size) }
            historyCheck(DshAgentReason.HISTORY_MESSAGE) {
                val appended = String(bytes, durableBefore.size, bytes.size - durableBefore.size, Charsets.UTF_8)
                check(appended.lineSequence().filter { it.isNotEmpty() }.map(::agentJsonObject).any {
                    it.optString("type") == "user/message" && it.optJSONObject("data")?.optString("id") == run.messageId
                })
            }
            durableBefore = bytes
            resumedWorker = run.workerPid
            resumeSucceeded = true
            "A new original SDK process resumed the same session and model recalled the prior random marker without tools; " +
                "original JSONL prefix and both artifacts survived, exit0/four barriers; history_bytes=${bytes.size}"
        },
        "linux_dsh_agent_cancel_active_turn" to {
            check(resumeSucceeded) { "A completed resumed turn is required before testing cancellation" }
            val id = checkNotNull(project)
            val deadline = SystemClock.elapsedRealtime() + 120_000L
            val wire = DshAgentWire(client, sessionId, target, deadline, null, ::progress)
            var primary: Throwable? = null
            try {
                progress(DshAgentStage.LAUNCH)
                wire.executionId = startInteractive(id, argv, 110_000L, work, env, wire.stdout)
                val execution = checkNotNull(wire.executionId)
                val server = wire.request("initialize", JSONObject().put("cwd", work).put("provider", target.provider)
                    .put("model", target.model).put("maxTokens", minOf(target.maxTokens, 512)).put("approvalRequests", true))
                    .getJSONObject("serverInfo")
                check(server.getString("name") == "deepseek-harness-sdk-runtime" && server.getString("version") == "0.0.1")
                check(wire.request("session/resume", JSONObject().put("sessionId", sessionId)).length() == 0)
                val mark = wire.markActivity()
                val prompt = "Please write about 250 words on how to verify that a project remains usable after cancellation. Do not call tools or inspect any files or environment variables."
                val receipt = wire.request("session/prompt", JSONObject().put("sessionId", sessionId)
                    .put("contentBlocks", JSONArray().put(JSONObject().put("type", "text").put("text", prompt))))
                val messageId = receipt.getString("messageId")
                check(messageId.isNotEmpty())
                progress(DshAgentStage.CANCEL_OBSERVE)
                val activity = wire.awaitActiveTurn(mark, messageId)
                check(activity.workerPid != firstWorker && activity.workerPid != resumedWorker && activity.workerPid != Process.myPid())
                progress(DshAgentStage.CANCEL)
                check(client.cancel(execution)) { "Runtime did not accept cancellation of the observed active Agent" }
                // A hard stop may cut a stdout frame. Do not synthesize a final
                // JSON-RPC response; durable JSONL integrity is checked below.
                val ended = client.waitFor(execution, (deadline - SystemClock.elapsedRealtime()).coerceAtLeast(0L))
                check(ended.getString("state") == "cancelled")
                checkAgentBarriers(ended, requireRun = true)
                val result = ended.getJSONObject("result")
                // Live stdout was consumed up to the observed active turn. A bounded
                // durable stdout preview can be truncated even when the drain completed.
                check(!result.getBoolean("stderr_truncated"))
                check(result.getBoolean("input_closed") && result.getBoolean("input_ended"))
                check(result.getJSONObject("worker").getInt("pid") == activity.workerPid)
                checkArtifacts(id)
                val (path, bytes) = sessionLog(id)
                checkPrefix(path, bytes)
                progress(DshAgentStage.REUSE)
                proveReuse(id)
                "Runtime cancelled an observed active original Agent turn in a new worker; four cleanup barriers, independent project reuse, both artifacts and complete JSONL records verified; " +
                    "worker=${activity.workerPid}, provider_stream_observed=${activity.providerStream}, additional_history_bytes=${bytes.size - durableBefore.size}. No SDK cancel RPC or PTY descendant-cleanup claim"
            } catch (failure: Throwable) {
                primary = failure
                throw failure
            } finally {
                try { wire.closeAndReap() } catch (cleanup: Throwable) {
                    if (primary == null) throw cleanup else primary.addSuppressed(cleanup)
                }
            }
        }
    )
    // JSON parser errors and provider/guest messages can contain entire frames.
    // Keep failures loud but export only known stage/classification and numeric
    // RPC code. Do not attach the original Throwable as cause or suppressed text.
    return cases.map { (case, body) -> case to {
        activeCase = case
        emitted.clear()
        observedEvents = 0
        observedTools = 0
        progress(DshAgentStage.PREREQUISITE)
        try { body() } catch (failure: Throwable) {
            val category = when (failure) {
                is DshObservationFailure -> failure.reason
                is DshAgentRpcFailure -> DshAgentReason.RPC_ERROR
                is DshAgentTurnFailure -> DshAgentReason.TURN_ERROR
                is RuntimeExceptionWithCode -> DshAgentReason.RUNTIME_ERROR
                is org.json.JSONException, is java.io.IOException -> DshAgentReason.PROTOCOL_IO
                is IllegalArgumentException -> DshAgentReason.INVALID_SCHEMA
                is IllegalStateException -> DshAgentReason.ASSERTION
                else -> DshAgentReason.UNEXPECTED
            }
            val turn = failure as? DshAgentTurnFailure
            val kind = if (turn == null) DshProviderError.NONE else DshProviderError.entries.firstOrNull {
                it.name == turn.providerCode
            } ?: DshProviderError.OTHER
            val rpc = (failure as? DshAgentRpcFailure)?.code?.takeIf { it in setOf(-32700,-32600,-32601,-32602,-32603,-32000) } ?: 0
            diagnostic(case, DshAgentDiagnostic(evidenceStage, category, kind, observedEvents, observedTools, turn?.status ?: 0, rpc))
            throw IllegalStateException("Original Agent acceptance failed at ${evidenceStage.name} (${category.name})")
        }
    } }
}

private data class DshAgentRun(val pid: Int, val workerPid: Int, val messageId: String, val calls: Set<String>, val approvals: Int)
private data class DshAgentActivityMark(val events: Int, val runningTransitions: Int)
private data class DshAgentActivity(val workerPid: Int, val providerStream: Boolean)
private class DshAgentRpcFailure(val code: Int?) : IllegalStateException("Original SDK JSON-RPC failure")
private class DshAgentTurnFailure(val kind: String, val providerCode: String, val status: Int?) : IllegalStateException("Original Agent turn failure")

/** Bounded, response-ordered original protocol client. Captures are not silently filtered. */
private class DshAgentWire(
    val client: RuntimeClient,
    val sessionId: String,
    val target: DshAgentTarget,
    val deadline: Long,
    val approve: ((DshAgentApproval) -> DshAgentApprovalOutcome)?,
    val stage: (DshAgentStage, Int, Int) -> Unit
) {
    var executionId: String? = null
    var acceptedBytes = 0
    var approvalCount = 0
    private var nextId = 0
    val stdout = ExecutionStdout()
    private val partial = ByteArrayOutputStream()
    private var receivedBytes = 0L
    private var lastSeq = -1L
    private val pending = HashSet<Int>()
    private val replies = HashMap<Int, JSONObject>()
    private val serverRequests = HashSet<String>()
    private val events = ArrayList<JSONObject>()
    private val calls = HashMap<String, JSONObject>()
    private var lastStatus: String? = null
    private var runningTransitions = 0

    private fun send(frame: JSONObject) {
        check(SystemClock.elapsedRealtime() < deadline - 10_000L) { "Agent protocol work deadline exceeded" }
        val bytes = (frame.toString() + "\n").toByteArray(Charsets.UTF_8)
        check(client.writeInput(checkNotNull(executionId), bytes) == bytes.size) { "Agent input was not atomically accepted" }
        acceptedBytes += bytes.size
    }

    fun request(method: String, params: JSONObject): JSONObject {
        // method comes only from the helper's fixed outgoing calls.
        val phase = when (method) {
            "initialize" -> DshAgentStage.INITIALIZE
            "session/resume" -> DshAgentStage.RESUME
            "session/prompt" -> DshAgentStage.PROMPT
            "session/wait" -> DshAgentStage.WAIT
            "shutdown" -> DshAgentStage.SHUTDOWN
            else -> throw DshObservationFailure(DshAgentReason.INVALID_SCHEMA)
        }
        stage(phase, events.size, calls.size)
        val id = ++nextId
        pending.add(id)
        send(JSONObject().put("jsonrpc", "2.0").put("id", id).put("method", method).put("params", params))
        while (true) {
            val record = observe()
            replies.remove(id)?.let { return it }
            if (record.getString("state") != "running") throw DshObservationFailure(DshAgentReason.EXIT_BEFORE_REPLY)
            if (SystemClock.elapsedRealtime() >= deadline - 10_000L) throw DshObservationFailure(DshAgentReason.DEADLINE)
            SystemClock.sleep(25)
        }
    }

    private fun observe(): JSONObject {
        val record = client.getExecution(checkNotNull(executionId))
        if (record.getString("stderr").toByteArray(Charsets.UTF_8).size >= 65_536)
            throw DshObservationFailure(DshAgentReason.CAPTURE_LIMIT)
        // Durable stdout is deliberately a bounded preview. Parse the separately redacted live
        // stream byte-for-byte: a JSON frame or a UTF-8 scalar may cross any number of pipe reads.
        while (true) {
            val read = try { stdout.read() } catch (failure: RuntimeExceptionWithCode) {
                if (failure.code == "output_overflow") throw DshObservationFailure(DshAgentReason.CAPTURE_LIMIT)
                throw failure
            }
            receivedBytes += read.bytes.size
            if (receivedBytes > 8L * 1_048_576) throw DshObservationFailure(DshAgentReason.CAPTURE_LIMIT)
            var offset = 0
            for (idx in read.bytes.indices) if (read.bytes[idx] == 10.toByte()) {
                partial.write(read.bytes, offset, idx-offset)
                if (partial.size() > 1_048_576) throw DshObservationFailure(DshAgentReason.CAPTURE_LIMIT)
                val line = Charsets.UTF_8.newDecoder().onMalformedInput(CodingErrorAction.REPORT)
                    .decode(ByteBuffer.wrap(partial.toByteArray())).toString()
                partial.reset()
                frame(agentJsonObject(line))
                offset = idx+1
            }
            partial.write(read.bytes, offset, read.bytes.size-offset)
            if (partial.size() > 1_048_576) throw DshObservationFailure(DshAgentReason.CAPTURE_LIMIT)
            if (read.eof) {
                if (partial.size() != 0) throw DshObservationFailure(DshAgentReason.PARTIAL_FRAME)
                break
            }
            if (read.bytes.isEmpty()) {
                if (record.getString("state") != "running") throw DshObservationFailure(DshAgentReason.PARTIAL_FRAME)
                break
            }
        }
        return record
    }

    private fun frame(frame: JSONObject) {
        check(frame.opt("jsonrpc") == "2.0") { "Invalid Agent protocol version" }
        if (frame.has("error")) {
            val problem = frame.getJSONObject("error")
            val code = problem.opt("code")
            throw DshAgentRpcFailure(if (code is Int) code else if (code is Long && code in Int.MIN_VALUE.toLong()..Int.MAX_VALUE.toLong()) code.toInt() else null)
        }
        val method = frame.opt("method")
        if (frame.has("id") && method is String) {
            val id = frame.get("id")
            check(id is String && id.startsWith("req_") && serverRequests.add(id)) { "Invalid/duplicate original SDK server request" }
            check(method == "approval/request") { "Unexpected Agent server request; user questions are not enabled" }
            val params = frame.getJSONObject("params")
            check(params.getString("sessionId") == sessionId)
            val callId = params.getString("callId")
            val call = checkNotNull(calls[callId]) { "Approval has no prior matching tool/call event" }
            check(call.getString("name") == params.getString("toolName"))
            val outcome = approve?.invoke(DshAgentApproval(sessionId, params.getString("toolName"), callId,
                agentJsonObject(call.getString("arguments")), params.optString("reason").ifEmpty { null }))
                ?: DshAgentApprovalOutcome.REJECTED
            approvalCount++
            send(JSONObject().put("jsonrpc", "2.0").put("id", id).put("result", JSONObject().put("outcome", outcome.wire)))
        } else if (frame.has("id")) {
            val id = frame.get("id")
            check(id is Int || id is Long) { "Agent response id is not an integer" }
            val number = (id as Number).toLong()
            check(number in 1..Int.MAX_VALUE.toLong() && pending.remove(number.toInt()) && !replies.containsKey(number.toInt())) {
                "Unexpected or duplicate Agent response"
            }
            replies[number.toInt()] = frame.getJSONObject("result")
        } else {
            check(method is String && !frame.has("result")) { "Malformed Agent notification" }
            val params = frame.getJSONObject("params")
            when (method) {
                "session.event" -> {
                    check(params.getString("sessionId") == sessionId) { "Unexpected other-session notification" }
                    val event = params.getJSONObject("event")
                    val seq = event.getLong("seq")
                    check(seq >= 0 && (lastSeq < 0 || seq == lastSeq + 1)) { "Original Agent event sequence gap/duplicate" }
                    lastSeq = seq
                    events.add(event)
                    check(events.size <= 2048) { "Agent event limit exceeded" }
                    if (event.getString("type") == "assistant/message") {
                        val data = event.optJSONObject("data")
                        val source = data?.optJSONObject("message")?.optJSONObject("source")
                        if (source?.optString("kind") == "model" && source.optString("provider") == target.provider &&
                            source.optString("model") == target.model && (data.optJSONArray("stream")?.length() ?: 0) > 0)
                            stage(DshAgentStage.MODEL_STREAM, events.size, calls.size)
                    }
                    if (event.getString("type") == "turn/end") {
                        stage(DshAgentStage.TURN_END, events.size, calls.size)
                        val reason = event.getJSONObject("data").getJSONObject("reason")
                        val kind = reason.getString("kind")
                        if (kind != "completed") {
                            val error = reason.optJSONObject("error")
                            val safeKind = kind.takeIf { it in setOf("aborted", "blocked", "error", "max-tokens", "interrupted", "forked") } ?: "other"
                            val safeCode = error?.optString("code")?.takeIf { it in setOf("AUTH", "QUOTA", "RATE_LIMIT", "SERVER", "TRANSPORT",
                                "MISSING_CREDENTIAL", "INVALID_CREDENTIAL", "INVALID_REQUEST", "CONTEXT_WINDOW_EXCEEDED", "EMPTY_RESPONSE",
                                "TOOL_ACTIVATION_FAILED", "UNKNOWN") } ?: "none_or_other"
                            val status = (error?.opt("status") as? Int)?.takeIf { it in 100..599 }
                            throw DshAgentTurnFailure(safeKind, safeCode, status)
                        }
                    }
                    if (event.getString("type") == "tool/call") {
                        val call = event.getJSONObject("data")
                        check(calls.put(call.getString("callId"), call) == null) { "Duplicate tool call identity" }
                        check(calls.size <= 8) { "Agent exceeded the bounded validation tool-call budget" }
                        val phase = when (call.optString("name")) {
                            "write" -> DshAgentStage.TOOL_WRITE
                            "read" -> DshAgentStage.TOOL_READ
                            "bash" -> DshAgentStage.TOOL_BASH
                            else -> DshAgentStage.TOOL_OTHER
                        }
                        stage(phase, events.size, calls.size)
                    }
                    if (event.getString("type") == "tool/result") {
                        stage(DshAgentStage.TOOL_RESULT, events.size, calls.size)
                        if (event.optJSONObject("data")?.optJSONObject("message")?.optBoolean("isError") == true)
                            throw DshObservationFailure(DshAgentReason.TOOL_ERROR)
                    }
                }
                "session.status" -> {
                    check(params.getString("sessionId") == sessionId)
                    val status = params.getString("status")
                    check(status == "running" || status == "idle")
                    lastStatus = status
                    if (status == "running") runningTransitions++
                }
                else -> error("Unexpected Agent notification method")
            }
        }
    }

    fun markActivity() = DshAgentActivityMark(events.size, runningTransitions)

    fun awaitActiveTurn(mark: DshAgentActivityMark, messageId: String): DshAgentActivity {
        while (true) {
            val live = observe()
            check(live.getString("state") == "running")
            val fresh = events.subList(mark.events, events.size)
            check(fresh.none { it.getString("type") == "turn/end" }) { "Agent turn ended before runtime cancellation" }
            check(fresh.none { it.getString("type") == "tool/call" }) { "Cancellation prompt unexpectedly invoked a tool" }
            val accepted = fresh.any { it.getString("type") == "user/message" && it.getJSONObject("data").optString("id") == messageId }
            val started = fresh.any { it.getString("type") == "turn/start" }
            if (accepted && started && lastStatus == "running" && runningTransitions > mark.runningTransitions) {
                val workerPid = live.getJSONObject("runtime").getJSONObject("worker").getInt("pid")
                check(workerPid > 0)
                val stream = fresh.any { event ->
                    if (event.getString("type") != "assistant/message") false else {
                        val data = event.getJSONObject("data")
                        val source = data.getJSONObject("message").getJSONObject("source")
                        source.getString("kind") == "model" && source.getString("provider") == target.provider &&
                            source.getString("model") == target.model && data.getJSONArray("stream").length() > 0
                    }
                }
                return DshAgentActivity(workerPid, stream)
            }
            check(SystemClock.elapsedRealtime() < deadline - 10_000L) { "No observable active Agent turn before deadline" }
            SystemClock.sleep(15)
        }
    }

    fun assertTurn(messageId: String, marker: String, resume: Boolean, inputFile: String, shellCommand: String): Set<String> {
        check(events.any { it.getString("type") == "user/message" && it.getJSONObject("data").optString("id") == messageId })
        val endings = events.filter { it.getString("type") == "turn/end" }
        check(endings.size == 1 && endings.single().getJSONObject("data").getJSONObject("reason").getString("kind") == "completed") {
            "Original Agent turn did not complete successfully; idle/wait alone is insufficient"
        }
        val assistant = events.filter { it.getString("type") == "assistant/message" }
        check(assistant.isNotEmpty()) { "No original model-generated assistant message" }
        assistant.forEach {
            val data = it.getJSONObject("data")
            check(!data.optBoolean("interrupted", false))
            val source = data.getJSONObject("message").getJSONObject("source")
            check(source.getString("kind") == "model" && source.getString("provider") == target.provider && source.getString("model") == target.model)
            check(data.getJSONArray("stream").length() > 0) { "No recorded provider stream for model output" }
        }
        val content = assistant.last().getJSONObject("data").getJSONObject("message").getJSONArray("content")
        val finalText = (0 until content.length()).map { content.getJSONObject(it) }
            .filter { it.optString("type") == "text" }.joinToString("") { it.getString("text") }.trim()
        check(finalText.contains(marker) && (resume || finalText.contains("SUCRUNE_AGENT_OK"))) { "Model did not return the required prior-history marker" }
        if (resume) {
            check(calls.isEmpty() && finalText == marker) { "Resume must recall only the prior marker without tools" }
        } else {
            check(calls.size == 3 && calls.values.map { it.getString("name") }.toSet() == setOf("write", "read", "bash")) {
                "Required original write/read/bash calls were not executed exactly once"
            }
            val ordered = events.filter { it.getString("type") == "tool/call" }.map { it.getJSONObject("data").getString("name") }
            check(ordered == listOf("write", "read", "bash")) { "Agent file/shell calls were out of order" }
            // The stock file tools resolve relative paths against the owning Agent's
            // working directory. All three spellings here identify the very same file.
            val leaf = inputFile.substringAfterLast('/')
            val inputPaths = setOf(inputFile, leaf, "./$leaf")
            for (call in calls.values) {
                val args = agentJsonObject(call.getString("arguments"))
                when (call.getString("name")) {
                    "write" -> check(args.getString("file_path") in inputPaths && args.getString("content") == "$marker\n")
                    "read" -> check(args.getString("file_path") in inputPaths)
                    "bash" -> check(args.getString("command") == shellCommand)
                }
            }
            val results = events.filter { it.getString("type") == "tool/result" }.map { it.getJSONObject("data").getJSONObject("message") }
            check(results.size == calls.size && results.map { it.getString("toolCallId") }.toSet() == calls.keys)
            check(results.all { !it.optBoolean("isError", false) }) { "Original Agent tool reported failure" }
            for (message in results) {
                val blocks = message.getJSONArray("content")
                val text = (0 until blocks.length()).map { blocks.getJSONObject(it) }
                    .filter { it.optString("type") == "text" }.joinToString("\n") { it.getString("text") }
                when (calls.getValue(message.getString("toolCallId")).getString("name")) {
                    "write" -> check(text.contains("<path>$inputFile</path>") && text.lineSequence().any { it == "Created file" })
                    "read" -> check(text.contains("<path>$inputFile</path>") && text.lineSequence().any { it == "1: $marker" })
                    "bash" -> check(text == "SUCRUNE_SHELL_OK\n[Command finished with exit code 0]")
                }
            }
        }
        return calls.keys.toSet()
    }

    fun awaitExit(): JSONObject {
        while (true) {
            val record = observe()
            if (record.getString("state") != "running") return record
            check(SystemClock.elapsedRealtime() < deadline - 10_000L) { "Agent did not exit after shutdown" }
            SystemClock.sleep(25)
        }
    }

    fun closeAndReap() {
        stdout.close()
        val id = executionId ?: return
        var failure: Throwable? = null
        try { client.closeInput(id) } catch (problem: RuntimeExceptionWithCode) {
            if (problem.code != "not_found") failure = problem
        } catch (problem: Throwable) { failure = problem }
        try {
            if (client.getExecution(id).getString("state") == "running") {
                client.cancel(id)
                val ended = client.waitFor(id, (deadline - SystemClock.elapsedRealtime()).coerceAtLeast(0L))
                check(ended.getString("state") != "running") { "Agent failure cleanup did not reach terminal state" }
                checkAgentBarriers(ended, requireRun = false)
            }
        } catch (problem: Throwable) {
            if (failure == null) failure = problem else failure.addSuppressed(problem)
        }
        failure?.let { throw it }
    }
}

private fun checkDshAgentCompletion(record: JSONObject): Int {
    // observe() independently drained and parsed live stdout through EOF, including all bytes
    // beyond durable retention; stderr must still fit its preview for startup checks.
    check(record.getString("state") == "exited" && record.getInt("exit_code") == 0)
    val result = record.getJSONObject("result")
    val native = result.getJSONObject("native")
    val worker = result.getJSONObject("worker")
    check(native.getString("kind") == "linux" && native.getString("status") == "exited" && native.getString("memory_policy") == "linux-jit")
    check(worker.getString("identity") == "isolated_runtime" && !worker.getBoolean("debuggable") && worker.getString("abi") == "arm64-v8a")
    check(worker.getInt("uid") != Process.myUid() && worker.getInt("uid") != 0 && worker.getInt("pid") != Process.myPid())
    val pid = native.getInt("runner_pid")
    check(pid > 0 && pid != Process.myPid() && pid != worker.getInt("pid") && native.getInt("pid") == pid)
    check(native.getInt("uid") == worker.getInt("uid") && native.getInt("runner_parent_pid") == worker.getInt("pid"))
    check(native.getBoolean("runner_waited") && native.getInt("runner_exit_code") == 0)
    check(native.getBoolean("on_alt_stack"))
    if (native.getString("cleanup_mode") == "process_exit_group") {
        check(native.getBoolean("report_on_host_tls") && !native.getBoolean("thread_joined") && !native.getBoolean("handler_restored"))
    } else {
        check(native.getBoolean("host_tls_restored") && native.getBoolean("thread_joined") && native.getBoolean("handler_restored"))
        check(native.getInt("fds_live") == 0 && native.getInt("resources_live") == 0)
    }
    checkAgentBarriers(record, requireRun = true)
    check(result.getBoolean("input_closed") && result.getBoolean("input_ended"))
    val output = record.getString("stdout") + "\n" + record.getString("stderr")
    listOf("MODULE_NOT_FOUND", "ERR_DLOPEN_FAILED", "Cannot find module", "Cannot find package", "No native build was found",
        "Failed to load native binding", "error while loading shared libraries", "FATAL ERROR:", "dsh: fatal load failure:",
        "dsh: fatal uncaught exception:", "dsh: startup failed:", "dsh: disabling profile plugin").forEach {
        check(!output.contains(it, ignoreCase = true)) { "Original Agent startup/module failure marker: $it" }
    }
    check(!Regex("dsh: warning: [0-9]+ entr(?:y|ies) did not activate", RegexOption.IGNORE_CASE).containsMatchIn(output))
    return pid
}

private fun checkAgentBarriers(record: JSONObject, requireRun: Boolean) {
    val result = record.getJSONObject("result")
    check(result.getBoolean("binder_death_confirmed") || (!requireRun && result.getBoolean("worker_never_started")))
    if (requireRun) check(result.getBoolean("run_sent"))
    check(result.getBoolean("output_drained") && result.getBoolean("broker_cleanup_confirmed") && result.getBoolean("stdin_feeder_completed"))
}

/** Strict wire grammar before JSONObject's permissive parser; no duplicate keys or non-JSON numbers. */
private fun agentJsonObject(line: String): JSONObject {
    JsonReader(StringReader(line)).use { reader ->
        reader.isLenient = false
        fun value(depth: Int) {
            check(depth <= 32) { "Agent JSON nesting limit exceeded" }
            when (reader.peek()) {
                JsonToken.BEGIN_OBJECT -> {
                    reader.beginObject()
                    val names = HashSet<String>()
                    while (reader.hasNext()) { check(names.add(reader.nextName())); value(depth + 1) }
                    reader.endObject()
                }
                JsonToken.BEGIN_ARRAY -> { reader.beginArray(); while (reader.hasNext()) value(depth + 1); reader.endArray() }
                JsonToken.STRING -> reader.nextString()
                JsonToken.NUMBER -> check(reader.nextString().matches(Regex("-?(?:0|[1-9][0-9]*)(?:\\.[0-9]+)?(?:[eE][+-]?[0-9]+)?")))
                JsonToken.BOOLEAN -> reader.nextBoolean()
                JsonToken.NULL -> reader.nextNull()
                else -> error("Invalid Agent JSON value")
            }
        }
        check(reader.peek() == JsonToken.BEGIN_OBJECT)
        value(0)
        check(reader.peek() == JsonToken.END_DOCUMENT)
    }
    return JSONObject(line)
}
