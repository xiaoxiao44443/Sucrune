package com.sucrune.probe

import android.app.Application
import android.content.ComponentName
import android.content.Context
import android.content.Intent
import android.content.ServiceConnection
import android.net.ConnectivityManager
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
import android.system.ErrnoException
import android.system.Os
import android.system.OsConstants
import android.system.StructPollfd
import android.util.Base64
import org.json.JSONArray
import org.json.JSONObject
import java.io.ByteArrayOutputStream
import java.io.File
import java.io.InputStream
import java.nio.file.Files
import java.security.MessageDigest
import java.util.UUID
import java.util.concurrent.CountDownLatch
import java.util.concurrent.Executors
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicLong

class RuntimeExceptionWithCode(val code: String, message: String) : IllegalStateException(message)

/** A static ARM64 Linux executable selected by the embedding app for an exact exec path. */
class TrustedExecutable(val guestPath: String, image: ByteArray) {
    init {
        RuntimeClient.validateLinuxPath(guestPath)
        require(guestPath.drop(1).split('/').none { it.isEmpty() || it == "." || it == ".." })
        require(image.size in 64..16 * 1024 * 1024)
    }
    internal val bytes = image.copyOf()
}

/** Application-lifetime manager. Activity/Agent disconnection does not stop pipe draining. */
class RuntimeClient private constructor(private val context: Context) {
    private val dataDir = File(context.filesDir, "sucrune").absolutePath
    private val main = Handler(Looper.getMainLooper())
    private val io = Executors.newCachedThreadPool()
    private val coreLock = Any()
    private val sessionsLock = Any()
    private val sessions = LinkedHashMap<String, Execution>()
    private val deletingProjects = HashSet<String>()
    private val replies = Messenger(object : Handler(Looper.getMainLooper()) {
        override fun handleMessage(message: Message) {
            val id = message.data.getString("execution_id") ?: return
            val execution = synchronized(sessionsLock) { sessions[id] } ?: return
            if (execution.dead || execution.finishing) return
            try {
                val report = JSONObject(message.data.getString("report") ?: "")
                when (message.what) {
                    RuntimeWorkerService.STARTED -> {
                        execution.worker = validatedWorker(report.getJSONObject("worker"))
                        execution.phase = "executing"
                        execution.event("started", execution.worker!!)
                    }
                    RuntimeWorkerService.RESULT -> {
                        check(report.getInt("schema_version") == 1 && report.getString("kind") == execution.kind)
                        check(report.getString("status") in setOf("exited", "failed", "unsupported"))
                        if (report.getString("status") == "exited") check(report.getInt("exit_code") in 0..255)
                        execution.worker = validatedWorker(report.getJSONObject("worker"))
                        report.put("worker", execution.worker)
                        execution.nativeResult = execution.sanitizeReport(report)
                        execution.input.abort("execution_completed")
                        execution.phase = "stopping"
                        stopWorker(execution)
                    }
                }
            } catch (failure: Exception) {
                execution.failure = "invalid_worker_report: $failure"
                execution.phase = "stopping"
                stopWorker(execution)
            }
        }
    })

    init {
        check(Application.getProcessName() == context.packageName &&
            Process.myUid() == context.applicationInfo.uid) { "Runtime manager must run in the application process" }
    }

    fun createEnvironment(name: String): JSONObject = core("env.create", JSONObject().put("name", name)) as JSONObject
    fun listEnvironments(): JSONArray = core("env.list") as JSONArray
    fun getEnvironment(id: String): JSONObject = core("env.get", JSONObject().put("env_id", id)) as JSONObject
    /** Legacy low-level deletion rejects active executions. Apps use deleteProject for project removal. */
    fun deleteEnvironment(id: String): JSONObject = synchronized(sessionsLock) {
        requireProjectOpen(id)
        core("env.delete", JSONObject().put("env_id", id)) as JSONObject
    }

    /** Stops every execution owned by this project before deleting its files.
     * Returns after worker, streams, broker and execution metadata are settled.
     * If cleanup fails or takes too long, files are retained and deletion may be retried. */
    fun deleteProject(id: String): JSONObject = deleteProject(id, false)

    /** Diagnostic projects may discard their execution transcripts after all workers have stopped. */
    fun deleteProject(id: String, purgeExecutionHistory: Boolean): JSONObject {
        check(Looper.myLooper() != Looper.getMainLooper()) { "deleteProject cannot block the main looper" }
        val active = synchronized(sessionsLock) {
            requireProjectOpen(id)
            deletingProjects.add(id)
            sessions.values.filter { it.envId == id }
        }
        try {
            active.forEach { cancel(it.id) }
            val deadline = SystemClock.elapsedRealtime() + 30_000L
            active.forEach {
                val remaining = (deadline - SystemClock.elapsedRealtime()).coerceAtLeast(0L)
                if (!it.finished.await(remaining, TimeUnit.MILLISECONDS)) {
                    throw RuntimeExceptionWithCode("cleanup_pending", "Project cleanup is still pending; retry deletion")
                }
            }
            val request = JSONObject().put("env_id", id)
            if (purgeExecutionHistory) request.put("purge_execution_history", true)
            return core("env.delete", request) as JSONObject
        } finally {
            synchronized(sessionsLock) { deletingProjects.remove(id) }
        }
    }

    /** sessionsLock must be held for the whole admission decision. */
    private fun requireProjectOpen(id: String) {
        if (id in deletingProjects) throw RuntimeExceptionWithCode("conflict", "Project deletion is in progress")
    }

    fun writeFile(id: String, path: String, content: ByteArray): JSONObject = core("file.write",
        JSONObject().put("env_id", id).put("path", path)
            .put("content_base64", Base64.encodeToString(content, Base64.NO_WRAP))) as JSONObject
    fun readFile(id: String, path: String): ByteArray = Base64.decode((core("file.read",
        JSONObject().put("env_id", id).put("path", path)) as JSONObject).getString("content_base64"), Base64.DEFAULT)
    /** Streams a bounded file into the project. The caller retains ownership of input. */
    fun importFile(envId: String, path: String, input: InputStream, expectedSize: Long, sha256: String,
                   executable: Boolean = false): JSONObject {
        check(Looper.myLooper() != Looper.getMainLooper()) { "importFile cannot block the main looper" }
        require(expectedSize in 0L..268_435_456L) { "Import size must be between 0 and 256 MiB" }
        require(sha256.matches(Regex("[0-9a-fA-F]{64}"))) { "SHA-256 must contain 64 hexadecimal characters" }
        // Initializes the core-owned private root/imports directory before staging.
        if (getEnvironment(envId).getString("state") == "running") {
            throw RuntimeExceptionWithCode("conflict", "Cannot import into an active environment")
        }
        val imports = File(dataDir, "imports")
        check(OsConstants.S_ISDIR(Os.lstat(imports.absolutePath).st_mode)) { "Import directory must be a real directory" }
        val importId = UUID.randomUUID().toString()
        val temporary = File(imports, "$importId.bin")
        val digest = MessageDigest.getInstance("SHA-256")
        var total = 0L
        var created = false
        try {
            val descriptor = Os.open(temporary.absolutePath,
                OsConstants.O_WRONLY or OsConstants.O_CREAT or OsConstants.O_EXCL or OsConstants.O_CLOEXEC or OsConstants.O_NOFOLLOW, 0x180)
            created = true
            try {
                val buffer = ByteArray(65_536)
                while (true) {
                    var count = input.read(buffer)
                    if (count < 0) break
                    if (count == 0) {
                        val single = input.read()
                        if (single < 0) break
                        buffer[0] = single.toByte(); count = 1
                    }
                    total += count
                    if (total > expectedSize) throw RuntimeExceptionWithCode("integrity_mismatch", "Import stream exceeds declared size")
                    var offset = 0
                    while (offset < count) {
                        val written = try { Os.write(descriptor, buffer, offset, count - offset) }
                        catch (failure: ErrnoException) {
                            if (failure.errno == OsConstants.EINTR) continue
                            throw failure
                        }
                        check(written > 0) { "Import write made no progress" }
                        offset += written
                    }
                    digest.update(buffer, 0, count)
                }
                if (total != expectedSize) throw RuntimeExceptionWithCode("integrity_mismatch", "Import stream is shorter than declared size")
                val observedHash = digest.digest().joinToString("") { "%02x".format(it.toInt() and 255) }
                if (!observedHash.equals(sha256, ignoreCase = true)) {
                    throw RuntimeExceptionWithCode("integrity_mismatch", "Import stream SHA-256 differs from expected digest")
                }
                Os.fsync(descriptor)
            } finally {
                Os.close(descriptor)
            }
            return core("file.import", JSONObject().put("env_id", envId).put("path", path)
                .put("import_id", importId).put("size", expectedSize).put("sha256", sha256)
                .put("executable", executable)) as JSONObject
        } finally {
            if (created) Files.deleteIfExists(temporary.toPath())
        }
    }
    fun listFiles(id: String, path: String = "/"): JSONObject = core("file.list",
        JSONObject().put("env_id", id).put("path", path)) as JSONObject
    fun makeDirectory(id: String, path: String): JSONObject = core("file.mkdir",
        JSONObject().put("env_id", id).put("path", path)) as JSONObject
    fun listExecutions(envId: String? = null): JSONArray = core("exec.list",
        JSONObject().apply { if (envId != null) put("env_id", envId) }) as JSONArray
    fun listPrograms(): JSONArray = JSONArray(NativeProbe.listPrograms())

    /** Returns after reserving the environment; execution and startup are asynchronous. */
    fun execute(envId: String, script: String, cwd: String = "/", timeoutMs: Long = DEFAULT_TIMEOUT_MS): String {
        require(script.toByteArray(Charsets.UTF_8).size <= 65_536) { "Script exceeds 64 KiB" }
        require('\u0000' !in script) { "NUL is not supported" }
        return enqueue(envId, "shell", script, "", "", emptyList(), emptyList(), cwd, timeoutMs, byteArrayOf())
    }

    /** argv excludes argv[0]; env entries are NAME=value. Only bundled trusted programs are accepted. */
    fun executeProgram(envId: String, programId: String, argv: List<String> = emptyList(),
                       env: List<String> = emptyList(), cwd: String = "/", timeoutMs: Long = DEFAULT_TIMEOUT_MS,
                       stdin: ByteArray = byteArrayOf()): String {
        if (!isBundledProgram(programId)) throw RuntimeExceptionWithCode("unsupported_program", "Unknown bundled program: $programId")
        require(stdin.size <= 1_048_576) { "Standard input exceeds 1 MiB" }
        // Copy caller-owned lists before validation or asynchronous execution.
        val arguments = argv.toList()
        val environment = env.toList()
        val input = stdin.copyOf()
        validateProgramArguments(arguments, environment)
        return enqueue(envId, "program", "", programId, "", arguments, environment, cwd, timeoutMs, input)
    }

    /** Executes an absolute Linux path inside this project's filesystem; argv excludes argv[0].
     * A foreground service can opt into resident execution without a wall-clock deadline.
     * It still stops on cancel, project deletion or manager death.
     * secretEnv values are copied for this launch and omitted from durable requests.
     * Known values are filtered from captured output; arbitrary guest encodings/files are not covered. */
    fun executePath(envId: String, path: String, argv: List<String> = emptyList(),
                    env: List<String> = emptyList(), cwd: String = "/", timeoutMs: Long? = null,
                    stdin: ByteArray = byteArrayOf(), secretEnv: Map<String, CharArray> = emptyMap(),
                    resident: Boolean = false): String =
        executePath(envId, path, argv, env, cwd, timeoutMs, stdin, secretEnv, resident, null)

    /** This program and its descendants use a sealed image for exec of the configured absolute path. */
    fun executePath(envId: String, path: String, argv: List<String> = emptyList(),
                    env: List<String> = emptyList(), cwd: String = "/", timeoutMs: Long? = null,
                    stdin: ByteArray = byteArrayOf(), secretEnv: Map<String, CharArray> = emptyMap(),
                    resident: Boolean = false, trustedExecutable: TrustedExecutable?): String =
        executePath(envId, path, argv, env, cwd, timeoutMs, stdin, secretEnv, resident, trustedExecutable, null)

    /** Mount an explicitly authorized host directory as this execution's project workspace. */
    fun executePath(envId: String, path: String, argv: List<String> = emptyList(),
                    env: List<String> = emptyList(), cwd: String = "/", timeoutMs: Long? = null,
                    stdin: ByteArray = byteArrayOf(), secretEnv: Map<String, CharArray> = emptyMap(),
                    resident: Boolean = false, trustedExecutable: TrustedExecutable? = null, workspaceDirectory: GuestDirectory?): String {
        validateLinuxPath(path)
        require(stdin.size <= 1_048_576) { "Standard input exceeds 1 MiB" }
        val arguments = argv.toList()
        val environment = env.toList()
        val input = stdin.copyOf()
        validateProgramArguments(arguments, environment)
        return enqueue(envId, "linux", "", "", path, arguments, environment, cwd, timeoutMs, input,
            secretEnv = secretEnv, resident = resident, trustedExecutable = trustedExecutable, workspaceDirectory = workspaceDirectory)
    }

    /** Keeps stdin open until closeInput, peer closure, cancellation or execution completion.
     * Live input is process-local and cannot be resumed after manager death. */
    fun executePathInteractive(envId: String, path: String, argv: List<String> = emptyList(),
                               env: List<String> = emptyList(), cwd: String = "/",
                               timeoutMs: Long? = null, secretEnv: Map<String, CharArray> = emptyMap(),
                               resident: Boolean = false): String {
        validateLinuxPath(path)
        val arguments = argv.toList()
        val environment = env.toList()
        validateProgramArguments(arguments, environment)
        return enqueue(envId, "linux", "", "", path, arguments, environment, cwd, timeoutMs,
            byteArrayOf(), interactive = true, secretEnv = secretEnv, resident = resident)
    }

    /** Attaches the caller's single-use stdout reader before the guest can
     * produce bytes. The aggregate capture and session cleanup are independent. */
    fun executePathInteractiveStreaming(envId: String, path: String, stdout: ExecutionStdout,
                                        argv: List<String> = emptyList(), env: List<String> = emptyList(),
                                        cwd: String = "/", timeoutMs: Long? = null,
                                        secretEnv: Map<String, CharArray> = emptyMap(), resident: Boolean = false): String {
        stdout.attach()
        try {
            validateLinuxPath(path)
            val arguments = argv.toList()
            val environment = env.toList()
            validateProgramArguments(arguments, environment)
            return enqueue(envId, "linux", "", "", path, arguments, environment, cwd, timeoutMs,
                byteArrayOf(), interactive = true, secretEnv = secretEnv, stdoutReader = stdout, resident = resident)
        } catch (failure: Throwable) {
            stdout.finish(false)
            throw failure
        }
    }

    /** Atomically copies and queues the whole chunk. Success does not acknowledge guest consumption. */
    fun writeInput(id: String, bytes: ByteArray): Int {
        val execution = interactiveExecution(id)
        inputStopReason(execution)?.let { abortStoppedInput(execution, it) }
        return inputOperation { execution.input.accept(bytes) }
    }

    /** First close returns true. Previously accepted bytes drain before EOF; no later writes are accepted. */
    fun closeInput(id: String): Boolean {
        val execution = interactiveExecution(id)
        inputStopReason(execution)?.let { abortStoppedInput(execution, it) }
        return inputOperation { execution.input.close() }
    }

    private fun interactiveExecution(id: String): Execution {
        val execution = synchronized(sessionsLock) { sessions[id] }
            ?: throw RuntimeExceptionWithCode("not_found", "No live execution: $id")
        if (!execution.input.interactive) throw RuntimeExceptionWithCode("input_mode", "Execution has finite standard input")
        return execution
    }

    private fun <T> inputOperation(operation: () -> T): T = try { operation() }
    catch (failure: ExecutionInput.Failure) { throw RuntimeExceptionWithCode(failure.code, failure.message ?: failure.code) }

    private fun enqueue(envId: String, kind: String, script: String, programId: String, path: String,
                        argv: List<String>, env: List<String>, cwd: String, timeoutMs: Long?, stdin: ByteArray,
                        interactive: Boolean = false, secretEnv: Map<String, CharArray> = emptyMap(),
                        stdoutReader: ExecutionStdout? = null, resident: Boolean = false,
                        trustedExecutable: TrustedExecutable? = null, workspaceDirectory: GuestDirectory? = null): String {
        require('\u0000' !in cwd && cwd.startsWith('/') && cwd.toByteArray(Charsets.UTF_8).size < 1_024) {
            "cwd must be an absolute guest path shorter than 1024 UTF-8 bytes"
        }
        require(!resident || (kind == "linux" && timeoutMs == null)) { "Resident Linux executions must omit timeoutMs" }
        val duration = if (resident) null else timeoutMs ?: DEFAULT_TIMEOUT_MS
        require(duration == null || duration in 1_000L..DEFAULT_TIMEOUT_MS) {
            "Timeout must be between 1000 and $DEFAULT_TIMEOUT_MS milliseconds"
        }
        val fdProfile = env.filter { it.startsWith("SUCRUNE_FD_PROFILE=") }.map { it.substringAfter('=') }
        require(fdProfile.isEmpty() || (kind == "linux" && fdProfile.singleOrNull() in listOf("default", "build"))) {
            "Linux FD profile must be default or build and appear once"
        }
        val writeScope = writeScope(kind, env)
        val slot = executionSlot(envId, path, argv, env, cwd, resident, writeScope)
        val networkPolicy = networkPolicy(kind, env)
        val routes = env.filter { it.startsWith("SUCRUNE_NETWORK_ROUTE=") }
        require(routes.isEmpty() || (networkPolicy == 2 && routes.singleOrNull() == "SUCRUNE_NETWORK_ROUTE=system")) {
            "The system network route requires outbound Linux networking and must appear once"
        }
        val followDefaultNetwork = routes.isNotEmpty()
        val networkHandle = if (networkPolicy == 2 && !followDefaultNetwork) {
            context.getSystemService(ConnectivityManager::class.java).activeNetwork?.networkHandle
                ?: throw RuntimeExceptionWithCode("network_unavailable", "No active Android network is available")
        } else 0L
        val secrets = if (secretEnv.isEmpty()) null else ExecutionSecrets.capture(argv, env, secretEnv)
        try {
            val request = JSONObject().put("kind", kind).put("cwd", cwd).put("timeout_ms", duration ?: 0L)
            if (resident) request.put("resident", true)
            if (secrets != null) request.put("secret_env_names", JSONArray(secrets.names))
            if (kind == "linux") request.put("network_policy", when (networkPolicy) { 1 -> "loopback"; 2 -> "outbound"; else -> "none" })
            if (fdProfile.singleOrNull() == "build") request.put("fd_profile", "build")
            if (networkPolicy == 2) request.put("network_binding", if (followDefaultNetwork) "system_default" else "active_network_snapshot")
            if (kind == "shell") request.put("script", script)
            else {
                if (kind == "program") request.put("program_id", programId)
                else request.put("path", path)
                request.put("argv", JSONArray(argv)).put("env", JSONArray(env))
                if (interactive) request.put("stdin_mode", "interactive").put("stdin_limit_bytes", ExecutionInput.LIMIT)
                else request.put("stdin_bytes", stdin.size).put("stdin_sha256", MessageDigest.getInstance("SHA-256")
                    .digest(stdin).joinToString("") { "%02x".format(it.toInt() and 255) })
            }
            val execution: Execution
            synchronized(sessionsLock) {
                requireProjectOpen(envId)
                val occupied = sessions.values.map { it.slot } + slot
                if (executionSlotCount(occupied) > 4) {
                    throw RuntimeExceptionWithCode("conflict", "Four execution slots are already active")
                }
                val record = core("exec.create", JSONObject().put("env_id", envId).put("request",
                    request)) as JSONObject
                execution = Execution(record.getString("execution_id"), envId, kind, script, programId, path, argv, env, cwd, duration,
                    if (interactive) ExecutionInput.interactive() else ExecutionInput.finite(stdin), networkPolicy, networkHandle, slot, secrets, stdoutReader, trustedExecutable, workspaceDirectory)
                sessions[execution.id] = execution
            }
            main.post {
                execution.expiresAt?.let { main.postDelayed(execution.deadline, it - SystemClock.elapsedRealtime()) }
                io.execute { prepare(execution) }
            }
            return execution.id
        } catch (failure: Throwable) {
            secrets?.close()
            throw failure
        }
    }

    fun getExecution(id: String): JSONObject {
        val persisted = core("exec.get", JSONObject().put("execution_id", id)) as JSONObject
        if (persisted.getString("state") != "running") return persisted
        val execution = synchronized(sessionsLock) { sessions[id] }
            // Durable completion can race the earlier read and remove the live
            // session. Do not return a stale running record without runtime.
            ?: return core("exec.get", JSONObject().put("execution_id", id)) as JSONObject
        return persisted.put("stdout", execution.stdout.text()).put("stderr", execution.stderr.text())
            .put("truncated", execution.stdout.truncated || execution.stderr.truncated)
            .put("runtime", JSONObject().put("phase", execution.phase)
                .put("worker", execution.worker).put("failure", execution.failure)
                .put("stop_reason", execution.stopReason).put("binder_death_confirmed", execution.dead)
                .put("stdin_feeder_completed", execution.stdinDone.count == 0L)
                .apply { inputStatus(execution, this) })
    }

    /** Aggregate output is persisted; cursors are live-session byte events, not process resumption. */
    fun poll(id: String, afterCursor: Long = 0): JSONObject {
        require(afterCursor >= 0)
        val record = getExecution(id)
        val execution = synchronized(sessionsLock) { sessions[id] }
        if (execution == null) return JSONObject().put("execution", record).put("events", JSONArray())
            .put("next_cursor", afterCursor).put("event_history_available", false)
        synchronized(execution.events) {
            val result = JSONArray()
            execution.events.filter { it.getLong("cursor") > afterCursor }.forEach { result.put(JSONObject(it.toString())) }
            return JSONObject().put("execution", record).put("events", result)
                .put("next_cursor", execution.cursor).put("event_history_available", true)
                .put("event_history_truncated", execution.events.firstOrNull()?.optLong("cursor", 1)?.let { afterCursor < it - 1 } ?: false)
                .put("output_truncated", execution.stdout.truncated || execution.stderr.truncated)
        }
    }

    /** Cancellation is requested immediately; running state remains until death is established. */
    fun cancel(id: String): Boolean {
        val execution = synchronized(sessionsLock) { sessions[id] } ?: return false
        main.post { requestStop(execution, "cancelled") }
        // Closing stdin may make the guest exit immediately. Enqueue the stop
        // decision before waking its feeder so that an EOF-induced RESULT cannot
        // overtake cancellation on the same main Handler.
        execution.input.abort("cancelled")
        return true
    }

    fun waitFor(id: String, timeoutMs: Long = DEFAULT_TIMEOUT_MS + 5_000L): JSONObject {
        check(Looper.myLooper() != Looper.getMainLooper()) { "waitFor cannot block the main looper" }
        require(timeoutMs >= 0)
        val execution = synchronized(sessionsLock) { sessions[id] }
        if (execution != null && !execution.finished.await(timeoutMs, TimeUnit.MILLISECONDS)) {
            throw RuntimeExceptionWithCode("wait_timeout", "Execution is still active; wait timeout does not cancel it")
        }
        return getExecution(id)
    }

    private fun core(op: String, request: JSONObject = JSONObject()): Any {
        val response = synchronized(coreLock) {
            JSONObject(NativeProbe.coreCall(dataDir, request.put("op", op).toString()))
        }
        if (!response.getBoolean("ok")) {
            val error = response.getJSONObject("error")
            throw RuntimeExceptionWithCode(error.getString("code"), error.getString("message"))
        }
        return response.get("result")
    }

    private fun prepare(execution: Execution) {
        var broker: ParcelFileDescriptor? = null
        var stdout: Array<ParcelFileDescriptor>? = null
        var stderr: Array<ParcelFileDescriptor>? = null
        var stdin: Array<ParcelFileDescriptor>? = null
        var brokerExists = false
        var readersStarted = false
        var feederStarted = false
        try {
            if (execution.kind == "program" || execution.kind == "linux") {
                val inputPair = ParcelFileDescriptor.createSocketPair()
                stdin = inputPair
                execution.stdinRead = inputPair[0]
                io.execute { feedInput(execution, inputPair[1]) }
                feederStarted = true
            }
            val paths = core("env.paths", JSONObject().put("env_id", execution.envId)) as JSONObject
            val workspace = paths.getString("workspace")
            val fds = when {
                execution.kind != "linux" -> NativeProbe.openWorkspace(workspace)
                execution.workspaceDirectory != null -> NativeProbe.openWorkspaceWithDirectory(workspace, execution.networkPolicy,
                    execution.networkHandle, "SUCRUNE_FD_PROFILE=build" in execution.env, execution.slot.writeScope,
                    execution.trustedExecutable?.guestPath, execution.trustedExecutable?.bytes, execution.workspaceDirectory)
                execution.trustedExecutable != null -> NativeProbe.openWorkspaceWithImage(workspace, execution.networkPolicy,
                    execution.networkHandle, "SUCRUNE_FD_PROFILE=build" in execution.env, execution.slot.writeScope,
                    execution.trustedExecutable.guestPath, execution.trustedExecutable.bytes)
                execution.slot.writeScope != 0 -> NativeProbe.openScopedWorkspace(workspace, execution.networkPolicy,
                    execution.networkHandle, "SUCRUNE_FD_PROFILE=build" in execution.env, execution.slot.writeScope)
                "SUCRUNE_FD_PROFILE=build" in execution.env ->
                    NativeProbe.openBuildWorkspace(workspace, execution.networkPolicy, execution.networkHandle)
                else -> NativeProbe.openWorkspaceOnNetwork(workspace, execution.networkPolicy, execution.networkHandle)
            }
            check(fds.size == 2 && fds[0] >= 0 && fds[1] >= 0) {
                "Cannot create rooted file broker: ${fds.joinToString()}"
            }
            brokerExists = true
            broker = ParcelFileDescriptor.adoptFd(fds[0])
            val completion = ParcelFileDescriptor.adoptFd(fds[1])
            io.execute { awaitBrokerCompletion(execution, completion) }
            val outPipe = ParcelFileDescriptor.createPipe()
            stdout = outPipe
            val errPipe = ParcelFileDescriptor.createPipe()
            stderr = errPipe
            execution.broker = broker
            execution.stdoutWrite = stdout[1]
            execution.stderrWrite = stderr[1]
            execution.stdoutRead = stdout[0]
            execution.stderrRead = stderr[0]
            io.execute { drain(execution, "stdout", outPipe[0], execution.stdout) }
            io.execute { drain(execution, "stderr", errPipe[0], execution.stderr) }
            readersStarted = true
            main.post {
                if (execution.stopReason != null || execution.noWorker || execution.finishing) {
                    closeTransfers(execution)
                    execution.noWorker = true
                    finishWhenSafe(execution)
                } else bind(execution)
            }
        } catch (failure: Throwable) {
            broker.closeQuietly()
            stdin?.get(0).closeQuietly()
            if (!feederStarted) {
                stdin?.get(1).closeQuietly()
                execution.input.finish("startup_failed")
                execution.stdinDone.countDown()
            }
            stdout?.forEach { it.closeQuietly() }; stderr?.forEach { it.closeQuietly() }
            if (!readersStarted) { execution.stdoutReader?.finish(false); execution.drained.countDown(); execution.drained.countDown() }
            if (!brokerExists) execution.brokerDone.countDown()
            main.post {
                execution.failure = "startup: $failure"
                execution.noWorker = true
                finishWhenSafe(execution)
            }
        }
    }

    private fun bind(execution: Execution) {
        execution.phase = "binding"
        try {
            execution.bound = context.bindIsolatedService(Intent(context, RuntimeWorkerService::class.java),
                Context.BIND_AUTO_CREATE, execution.id, context.mainExecutor, execution.connection)
            if (!execution.bound) {
                execution.failure = "bindIsolatedService returned false"
                execution.noWorker = true
                closeTransfers(execution)
                finishWhenSafe(execution)
            }
        } catch (failure: RuntimeException) {
            execution.failure = "bind: $failure"
            execution.noWorker = true
            closeTransfers(execution)
            finishWhenSafe(execution)
        }
    }

    private fun connect(execution: Execution, binder: IBinder) {
        if (execution.binder != null || execution.finishing || execution.noWorker || execution.dead) {
            // BIND_AUTO_CREATE may reconnect after a crash. An execution is
            // never replayed into a replacement process.
            try {
                Messenger(binder).send(Message.obtain(null, RuntimeWorkerService.STOP).apply {
                    data = Bundle().apply { putString("execution_id", execution.id) }
                })
            } catch (_: RemoteException) {}
            if (execution.binder != null && execution.binder?.isBinderAlive != true) died(execution)
            return
        }
        execution.binder = binder
        execution.remote = Messenger(binder)
        val recipient = IBinder.DeathRecipient { main.post { died(execution) } }
        execution.deathRecipient = recipient
        var launchEnvironment: Array<String>? = null
        var launchData: Bundle? = null
        try {
            binder.linkToDeath(recipient, 0)
            if (execution.stopReason != null || execution.failure != null) {
                closeTransfers(execution)
                stopWorker(execution)
                return
            }
            val remaining = execution.expiresAt?.minus(SystemClock.elapsedRealtime())
            if (remaining != null && remaining <= 0L) {
                requestStop(execution, "timed_out")
                closeTransfers(execution)
                return
            }
            val launch = execution.secrets?.launchEnvironment() ?: execution.env.toTypedArray()
            launchEnvironment = launch
            execution.remote!!.send(Message.obtain(null, RuntimeWorkerService.RUN).apply {
                replyTo = replies
                data = Bundle().apply {
                    putString("execution_id", execution.id)
                    putString("kind", execution.kind)
                    putString("script", execution.script)
                    putString("program_id", execution.programId)
                    putString("path", execution.path)
                    putStringArray("argv", execution.argv.toTypedArray())
                    putStringArray("env", launch)
                    putString("cwd", execution.cwd)
                    putBoolean("resident", execution.expiresAt == null)
                    putLong("timeout_ms", remaining ?: 0L)
                    putParcelable("broker", execution.broker)
                    putParcelable("stdout", execution.stdoutWrite)
                    putParcelable("stderr", execution.stderrWrite)
                    putParcelable("stdin", execution.stdinRead)
                }.also { launchData = it }
            })
            execution.runSent = true
            execution.phase = "starting"
        } catch (failure: RemoteException) {
            execution.failure = "ipc: $failure"
            if (!binder.isBinderAlive) died(execution) else stopWorker(execution)
        } finally {
            launchData?.remove("env")
            launchEnvironment?.fill("")
            // Messenger marshals duplicate FDs into Binder. Retaining these ends
            // would hide EOF and keep the native broker alive after worker death.
            closeTransfers(execution)
        }
    }

    private fun requestStop(execution: Execution, reason: String) {
        if (execution.finishing || execution.dead || execution.nativeResult != null) return
        if (execution.stopReason == null) execution.stopReason = reason
        execution.input.abort(reason)
        execution.phase = "stopping"
        if (execution.binder != null) stopWorker(execution)
        else abandonBeforeRun(execution)
        // Once a Binder/RUN exists, unbinding is never treated as proof of death.
    }

    private fun abandonBeforeRun(execution: Execution) {
        check(execution.binder == null && !execution.runSent)
        // No RUN and no descriptors were sent. A late binding is stopped by
        // connect(), so there can be no guest access to this workspace.
        execution.noWorker = true
        closeTransfers(execution)
        unbind(execution)
        finishWhenSafe(execution)
    }

    private fun stopWorker(execution: Execution) {
        try {
            execution.remote?.send(Message.obtain(null, RuntimeWorkerService.STOP).apply {
                data = Bundle().apply {
                    putString("execution_id", execution.id)
                    putBoolean("result_ack", execution.nativeResult != null)
                }
            })
        } catch (_: RemoteException) {}
        if (execution.binder != null && execution.binder?.isBinderAlive != true) died(execution)
        // Keep the binding until death, avoiding a rebind to an unrelated process.
    }

    private fun died(execution: Execution) {
        if (execution.dead) return
        execution.dead = true
        execution.input.abort(if (execution.nativeResult != null) "exited" else "worker_died")
        execution.phase = "draining"
        closeTransfers(execution)
        unbind(execution)
        finishWhenSafe(execution)
    }

    private fun finishWhenSafe(execution: Execution) {
        if (execution.finishing || (!execution.dead && !execution.noWorker)) return
        execution.finishing = true
        execution.phase = "cleaning"
        main.removeCallbacks(execution.deadline)
        io.execute {
            val drained = execution.drained.await(3_000, TimeUnit.MILLISECONDS)
            val brokerCleaned = execution.brokerDone.await(3_000, TimeUnit.MILLISECONDS)
            val inputFinished = execution.stdinDone.await(3_000, TimeUnit.MILLISECONDS)
            if (!drained || !brokerCleaned || !inputFinished) {
                // A dead worker does not imply that an in-flight manager-side
                // filesystem operation has stopped. Preserve the reservation.
                main.post {
                    execution.finishing = false
                    execution.phase = "cleanup_pending"
                    if (execution.drained.count == 0L && execution.brokerDone.count == 0L &&
                        execution.stdinDone.count == 0L) finishWhenSafe(execution)
                }
                return@execute
            }
            val result = JSONObject().put("worker", execution.worker)
                .put("native", execution.nativeResult).put("failure", execution.failure)
                .put("binder_death_confirmed", execution.dead)
                .put("worker_never_started", execution.noWorker)
                .put("run_sent", execution.runSent).put("output_drained", drained)
                .put("broker_cleanup_confirmed", brokerCleaned)
                .put("stdin_feeder_completed", inputFinished)
                .apply { inputStatus(execution, this) }
                .put("stdout_truncated", execution.stdout.truncated)
                .put("stderr_truncated", execution.stderr.truncated)
                .put("secret_redactions", execution.redactions())
            val native = execution.nativeResult
            val state = execution.stopReason ?: if (native?.optString("status") == "exited" &&
                execution.failure == null && drained) "exited" else "lost"
            val finish = JSONObject().put("execution_id", execution.id).put("state", state)
                .put("stdout", execution.stdout.text()).put("stderr", execution.stderr.text())
                .put("truncated", execution.stdout.truncated || execution.stderr.truncated || !drained)
                .put("result", result)
            if (state == "exited") finish.put("exit_code", native!!.getInt("exit_code"))
            execution.releaseSecrets()
            persistFinish(execution, finish, 0)
        }
    }

    private fun persistFinish(execution: Execution, finish: JSONObject, attempt: Int) {
        try {
            core("exec.finish", finish)
            synchronized(sessionsLock) { sessions.remove(execution.id) }
            execution.finished.countDown()
        } catch (failure: Throwable) {
            if (failure is RuntimeExceptionWithCode && failure.code == "conflict") {
                try {
                    val existing = core("exec.get", JSONObject().put("execution_id", execution.id)) as JSONObject
                    val keys = listOf("state", "exit_code", "stdout", "stderr", "truncated", "result")
                    if (keys.all { sameJson(existing.opt(it), finish.opt(it)) }) {
                        synchronized(sessionsLock) { sessions.remove(execution.id) }
                        execution.finished.countDown()
                        return
                    }
                } catch (_: Throwable) {}
            }
            execution.failure = "persist_finish: $failure"
            execution.phase = "persistence_failed"
            // Retain the environment reservation if durable finalization fails.
            if (attempt < 2) main.postDelayed({ io.execute { persistFinish(execution, finish, attempt + 1) } }, 1_000)
        }
    }

    private fun drain(execution: Execution, stream: String, fd: ParcelFileDescriptor, capture: Capture) {
        var reachedEof = false
        var filteredEof = false
        val reader = if (stream == "stdout") execution.stdoutReader else null
        val filter = if (stream == "stdout") execution.stdoutFilter else execution.stderrFilter
        fun retain(bytes: ByteArray, count: Int) {
            reader?.publish(bytes, count)
            val retained = capture.append(bytes, count)
            if (retained > 0) execution.event(stream, JSONObject().put("content_base64",
                Base64.encodeToString(bytes.copyOf(retained), Base64.NO_WRAP)))
        }
        try {
            ParcelFileDescriptor.AutoCloseInputStream(fd).use { input ->
                val bytes = ByteArray(4_096)
                while (true) {
                    val count = input.read(bytes)
                    if (count < 0) { reachedEof = true; break }
                    if (filter == null) retain(bytes, count)
                    else {
                        val filtered = filter.feed(bytes, 0, count)
                        try { retain(filtered.bytes, filtered.bytes.size) }
                        finally { filtered.bytes.fill(0); bytes.fill(0) }
                    }
                }
                filter?.finish()?.let { tail ->
                    try { retain(tail.bytes, tail.bytes.size) } finally { tail.bytes.fill(0) }
                }
                filteredEof = true
            }
        } catch (failure: Exception) {
            execution.failure = "pipe_read: $failure"
        } finally {
            reader?.finish(filteredEof)
            filter?.close()
            if (reachedEof) execution.drained.countDown()
            main.post { finishWhenSafe(execution) }
        }
    }

    private fun inputStatus(execution: Execution, target: JSONObject) {
        val snapshot = execution.input.snapshot()
        target.put("stdin_bytes_accepted", snapshot.acceptedBytes)
            .put("stdin_bytes_written", snapshot.writtenBytes)
            .put("input_closed", snapshot.closed).put("input_ended", snapshot.ended)
            .put("input_end_reason", snapshot.endReason ?: JSONObject.NULL)
    }

    private fun inputStopReason(execution: Execution): String? = when {
        execution.stopReason != null -> execution.stopReason
        execution.dead -> "worker_died"
        execution.noWorker -> "worker_not_started"
        execution.nativeResult != null -> "execution_completed"
        execution.failure != null -> "failed"
        execution.expiresAt != null && SystemClock.elapsedRealtime() >= execution.expiresAt -> "timed_out"
        else -> null
    }

    private fun abortStoppedInput(execution: Execution, reason: String) {
        // Applies to API admission checks as well as the feeder's deadline.
        // The stop intent must precede the EOF that abort can expose to a guest.
        if (reason == "timed_out") main.post { requestStop(execution, "timed_out") }
        execution.input.abort(reason)
    }

    /** The sole owner of the writer. Idle waits and nonblocking sends are bounded;
     * closing the reader is detected even when no further chunks are queued. */
    private fun feedInput(execution: Execution, endpoint: ParcelFileDescriptor) {
        var endReason = "eof"
        try {
            val fd = endpoint.fileDescriptor
            val ready = StructPollfd().apply { this.fd = fd; events = OsConstants.POLLOUT.toShort() }
            val peer = StructPollfd().apply { this.fd = fd; events = 0 }
            fun stopped(): Boolean {
                val reason = inputStopReason(execution)
                if (reason != null) {
                    abortStoppedInput(execution, reason)
                }
                return execution.input.snapshot().aborted
            }
            feeding@ while (true) {
                if (stopped()) break
                val chunk = execution.input.awaitChunk(100)
                if (chunk == null) {
                    if (execution.input.snapshot().closed) break
                    try { Os.poll(arrayOf(peer), 0) }
                    catch (interrupted: ErrnoException) {
                        if (interrupted.errno == OsConstants.EINTR) continue else throw interrupted
                    }
                    if (peer.revents.toInt() and (OsConstants.POLLHUP or OsConstants.POLLERR) != 0) {
                        execution.input.abort("guest_closed")
                        break
                    }
                    if (peer.revents.toInt() and OsConstants.POLLNVAL != 0) error("stdin writer became invalid")
                    continue
                }
                var offset = 0
                while (offset < chunk.size) {
                    if (stopped()) break@feeding
                    try {
                        val count = Os.sendto(fd, chunk, offset, minOf(4_096, chunk.size - offset),
                            MSG_DONTWAIT or MSG_NOSIGNAL, null as java.net.InetAddress?, 0)
                        check(count > 0) { "stdin send made no progress" }
                        offset += count
                        execution.input.recordWritten(count)
                    } catch (failure: ErrnoException) {
                        when (failure.errno) {
                            OsConstants.EINTR -> continue
                            OsConstants.EPIPE, OsConstants.ECONNRESET -> {
                                execution.input.abort("guest_closed")
                                break@feeding
                            }
                            OsConstants.EAGAIN -> {
                                try { Os.poll(arrayOf(ready), 100) }
                                catch (interrupted: ErrnoException) { if (interrupted.errno != OsConstants.EINTR) throw interrupted }
                            }
                            else -> throw failure
                        }
                    }
                }
            }
        } catch (failure: Throwable) {
            endReason = "failed"
            main.post {
                if (!execution.dead && !execution.noWorker && execution.nativeResult == null) {
                    execution.failure = "stdin_write: $failure"
                    if (execution.binder != null) stopWorker(execution) else abandonBeforeRun(execution)
                }
            }
            execution.input.abort(endReason)
        } finally {
            endpoint.closeQuietly()
            execution.input.finish(endReason)
            execution.stdinDone.countDown()
            main.post { finishWhenSafe(execution) }
        }
    }

    private fun awaitBrokerCompletion(execution: Execution, completion: ParcelFileDescriptor) {
        try {
            ParcelFileDescriptor.AutoCloseInputStream(completion).use { input ->
                val buffer = ByteArray(64)
                while (input.read(buffer) >= 0) { /* Only EOF confirms root/file-FD cleanup. */ }
            }
            execution.brokerDone.countDown()
        } catch (failure: Exception) {
            execution.failure = "broker_completion_read: $failure"
        } finally { main.post { finishWhenSafe(execution) } }
    }

    private fun sameJson(left: Any?, right: Any?): Boolean {
        if (left == null || left === JSONObject.NULL) return right == null || right === JSONObject.NULL
        if (left is JSONObject && right is JSONObject) {
            val keys = left.keys().asSequence().toSet()
            return keys == right.keys().asSequence().toSet() && keys.all { sameJson(left.opt(it), right.opt(it)) }
        }
        if (left is JSONArray && right is JSONArray) return left.length() == right.length() &&
            (0 until left.length()).all { sameJson(left.opt(it), right.opt(it)) }
        if (left is Number && right is Number) return java.math.BigDecimal(left.toString())
            .compareTo(java.math.BigDecimal(right.toString())) == 0
        return left == right
    }

    private fun validatedWorker(worker: JSONObject): JSONObject {
        check(worker.getString("identity") == "isolated_runtime")
        check(worker.getInt("uid") > 0 && worker.getInt("uid") != context.applicationInfo.uid)
        check(worker.getInt("pid") > 0 && worker.getInt("pid") != Process.myPid())
        check(worker.getString("abi") in setOf("arm64-v8a", "x86_64"))
        check(worker.getInt("api_level") >= 29)
        return JSONObject().put("identity", "isolated_runtime")
            .put("uid", worker.getInt("uid")).put("pid", worker.getInt("pid"))
            .put("abi", worker.getString("abi")).put("api_level", worker.getInt("api_level"))
            .put("debuggable", worker.getBoolean("debuggable"))
    }

    private fun closeTransfers(execution: Execution) {
        execution.broker.closeQuietly(); execution.broker = null
        execution.stdinRead.closeQuietly(); execution.stdinRead = null
        execution.stdoutWrite.closeQuietly(); execution.stdoutWrite = null
        execution.stderrWrite.closeQuietly(); execution.stderrWrite = null
    }

    private fun unbind(execution: Execution) {
        if (execution.bound) {
            try { context.unbindService(execution.connection) } catch (_: IllegalArgumentException) {}
            execution.bound = false
        }
        execution.deathRecipient?.let {
            try { execution.binder?.unlinkToDeath(it, 0) } catch (_: NoSuchElementException) {}
        }
        execution.deathRecipient = null
    }

    private inner class Execution(val id: String, val envId: String, val kind: String, val script: String,
                                  val programId: String, val path: String, val argv: List<String>, val env: List<String>,
                                  val cwd: String, timeoutMs: Long?, val input: ExecutionInput, val networkPolicy: Int,
                                  val networkHandle: Long, val slot: ExecutionSlot, val secrets: ExecutionSecrets?, val stdoutReader: ExecutionStdout?,
                                  val trustedExecutable: TrustedExecutable?, val workspaceDirectory: GuestDirectory?) {
        val expiresAt: Long? = timeoutMs?.let { SystemClock.elapsedRealtime() + it }
        val stdout = Capture()
        val stderr = Capture()
        val stdoutFilter = secrets?.outputFilter()
        val stderrFilter = secrets?.outputFilter()
        private val diagnosticRedactions = AtomicLong()
        @Volatile private var secretsReleased = false
        val drained = CountDownLatch(2)
        val brokerDone = CountDownLatch(1)
        val stdinDone = CountDownLatch(if (kind == "program" || kind == "linux") 1 else 0)
        init { if (kind != "program" && kind != "linux") input.finish("not_applicable") }
        val finished = CountDownLatch(1)
        val events = ArrayList<JSONObject>()
        var cursor = 0L
        @Volatile var phase = "preparing"
        @Volatile var failure: String? = null
            set(value) { field = value?.let { diagnostic(it) } }
        @Volatile var worker: JSONObject? = null
        @Volatile var nativeResult: JSONObject? = null
        @Volatile var stopReason: String? = null
        @Volatile var dead = false
        var finishing = false
        @Volatile var noWorker = false
        var runSent = false
        var bound = false
        var binder: IBinder? = null
        var remote: Messenger? = null
        var deathRecipient: IBinder.DeathRecipient? = null
        var broker: ParcelFileDescriptor? = null
        var stdinRead: ParcelFileDescriptor? = null
        var stdoutWrite: ParcelFileDescriptor? = null
        var stderrWrite: ParcelFileDescriptor? = null
        var stdoutRead: ParcelFileDescriptor? = null
        var stderrRead: ParcelFileDescriptor? = null
        val deadline = Runnable { requestStop(this, "timed_out") }
        @Synchronized private fun diagnostic(value: String): String {
            val source = secrets ?: return value
            if (secretsReleased) {
                val stage = value.substringBefore(':').takeIf { it in setOf("persist_finish", "pipe_read",
                    "broker_completion_read", "ipc", "startup", "bind", "stdin_write", "invalid_worker_report") } ?: "execution"
                return "$stage: diagnostics unavailable after secret release"
            }
            val filtered = source.sanitizeDiagnostic(value)
            diagnosticRedactions.addAndGet(filtered.count)
            return filtered.text
        }
        fun sanitizeReport(value: JSONObject): JSONObject {
            if (secrets == null) return value
            fun clean(item: Any?, key: String = ""): Any? = when (item) {
                // Validated protocol constants must retain their meaning even
                // when a short secret happens to be a substring (e.g. "it").
                is String -> if ((key == "kind" && item in setOf("shell", "program", "linux")) ||
                    (key == "status" && item in setOf("exited", "failed", "unsupported")) ||
                    (key == "memory_policy" && item in setOf("wx", "linux-jit")) ||
                    (key == "cleanup_mode" && item in setOf("joined", "process_exit_group"))) item else diagnostic(item)
                is JSONObject -> if (key == "worker") validatedWorker(item) else JSONObject().apply {
                    item.keys().forEach { child -> put(child, clean(item.opt(child), child)) }
                }
                is JSONArray -> JSONArray().apply { for (index in 0 until item.length()) put(clean(item.opt(index))) }
                else -> item
            }
            return clean(value) as JSONObject
        }
        fun redactions(): Long = diagnosticRedactions.get() +
            (stdoutFilter?.redactionCount ?: 0L) + (stderrFilter?.redactionCount ?: 0L)
        @Synchronized fun releaseSecrets() {
            secretsReleased = true
            stdoutFilter?.close(); stderrFilter?.close(); secrets?.close()
        }
        fun event(type: String, data: JSONObject) = synchronized(events) {
            // Byte retention and event overhead are bounded independently.
            if (events.size == 256) events.removeAt(0)
            events.add(JSONObject().put("cursor", ++cursor).put("type", type).put("data", data))
        }
        val connection = object : ServiceConnection {
            override fun onServiceConnected(name: ComponentName, service: IBinder) { connect(this@Execution, service) }
            override fun onServiceDisconnected(name: ComponentName) {
                if (binder != null && binder?.isBinderAlive != true) died(this@Execution)
                else {
                    failure = "Service disconnected without confirmed death"
                    if (binder == null) abandonBeforeRun(this@Execution) else stopWorker(this@Execution)
                }
            }
            override fun onBindingDied(name: ComponentName) {
                failure = "Service binding died"
                if (binder != null && binder?.isBinderAlive != true) died(this@Execution)
                else if (binder == null) abandonBeforeRun(this@Execution) else stopWorker(this@Execution)
            }
            override fun onNullBinding(name: ComponentName) {
                // No RUN was possible, hence no native filesystem operation can exist.
                failure = "Service returned a null binding"
                noWorker = !runSent
                closeTransfers(this@Execution)
                unbind(this@Execution)
                finishWhenSafe(this@Execution)
            }
        }
    }

    private class Capture {
        private val bytes = ByteArrayOutputStream()
        @Volatile var truncated = false
        @Synchronized fun append(input: ByteArray, count: Int): Int {
            val retained = minOf(count, 65_536 - bytes.size())
            if (retained > 0) bytes.write(input, 0, retained)
            if (retained < count) truncated = true
            return retained
        }
        @Synchronized fun text(): String = bytes.toString("UTF-8")
    }

    private fun ParcelFileDescriptor?.closeQuietly() { try { this?.close() } catch (_: Exception) {} }

    internal data class ResidentEntry(val envId: String, val path: String, val argv: List<String>,
                                      val env: List<String>, val cwd: String)
    internal data class ExecutionSlot(val entry: ResidentEntry?, val writeScope: Int)

    companion object {
        internal const val DEFAULT_TIMEOUT_MS = 30L * 60L * 1_000L

        internal fun writeScope(kind: String, environment: List<String>): Int {
            val requested = environment.filter { it.startsWith("SUCRUNE_WRITE_SCOPE=") }
            if (requested.isEmpty()) return 0
            if (kind != "linux") throw RuntimeExceptionWithCode("unsupported_write_scope", "Write scopes require a Linux execution")
            return when (requested.singleOrNull()?.substringAfter('=')) {
                "read-only" -> 1
                "workspace-write" -> 2
                else -> throw RuntimeExceptionWithCode("unsupported_write_scope", "Expected exactly one read-only or workspace-write scope")
            }
        }

        internal fun executionSlot(envId: String, path: String, argv: List<String>, env: List<String>,
                                   cwd: String, resident: Boolean, writeScope: Int): ExecutionSlot {
            val option = env.singleOrNull { it.startsWith("SUCRUNE_RESIDENT_COMPANION=") }
                ?: return ExecutionSlot(null, writeScope)
            require(resident && option == "SUCRUNE_RESIDENT_COMPANION=1") { "A companion must be a declared resident service" }
            val settings = env.filterNot { it.startsWith("SUCRUNE_WRITE_SCOPE=") }.sorted()
            return ExecutionSlot(ResidentEntry(envId, path, argv, settings, cwd), writeScope)
        }

        internal fun executionSlotCount(executions: List<ExecutionSlot>): Int {
            val groups = executions.filter { it.entry != null }.groupBy { it.entry }
            return executions.count { it.entry == null } + groups.values.sumOf { group ->
                group.groupingBy { it.writeScope }.eachCount().values.max()
            }
        }

        internal fun networkPolicy(kind: String, environment: List<String>): Int {
            val selected = environment.firstOrNull { it.startsWith("SUCRUNE_NETWORK_POLICY=") }
                ?.substringAfter('=') ?: "none"
            if (kind != "linux" && selected != "none")
                throw RuntimeExceptionWithCode("unsupported_network_policy", "Network policy requires a Linux path execution")
            return when (selected) {
                "none" -> 0
                "loopback" -> 1
                "outbound" -> 2
                else -> throw RuntimeExceptionWithCode("unsupported_network_policy", "Supported network policies are none, loopback and outbound")
            }
        }
        // Linux UAPI values; Android's public OsConstants omits these send flags.
        private const val MSG_DONTWAIT = 0x40
        private const val MSG_NOSIGNAL = 0x4000
        internal fun isBundledProgram(id: String): Boolean {
            val catalog = JSONArray(NativeProbe.listPrograms())
            return (0 until catalog.length()).any { catalog.getJSONObject(it).getString("program_id") == id }
        }
        internal fun validateLinuxPath(path: String) {
            require('\u0000' !in path && path.startsWith('/') && path.toByteArray(Charsets.UTF_8).size < 1_024) {
                "Executable path must be an absolute guest path shorter than 1024 UTF-8 bytes"
            }
        }
        internal fun validateProgramArguments(argv: List<String>, env: List<String>) {
            require(argv.size <= 64 && env.size <= 64) { "At most 64 arguments and 64 environment entries are supported" }
            var bytes = 0
            (argv + env).forEach {
                require('\u0000' !in it) { "NUL is not supported" }
                val size = it.toByteArray(Charsets.UTF_8).size
                require(size <= 4_096) { "Argument or environment entry exceeds 4096 UTF-8 bytes" }
                bytes += size + 1
            }
            require(bytes <= 65_536) { "Arguments and environment exceed 64 KiB" }
            val names = HashSet<String>()
            env.forEach {
                val separator = it.indexOf('=')
                require(separator > 0) { "Environment entries must be NAME=value" }
                val name = it.substring(0, separator)
                require(name.matches(Regex("[A-Za-z_][A-Za-z0-9_]*")) && names.add(name)) {
                    "Environment names must be valid and unique"
                }
            }
        }
        @Volatile private var instance: RuntimeClient? = null
        @JvmStatic fun get(context: Context): RuntimeClient = instance ?: synchronized(this) {
            instance ?: RuntimeClient(context.applicationContext).also { instance = it }
        }
    }
}
