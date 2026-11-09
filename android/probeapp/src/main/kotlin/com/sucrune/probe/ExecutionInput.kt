package com.sucrune.probe

/** Bounded process-local input. Accepted bytes are queued, not acknowledged by the guest.
 * One feeder takes chunks and records successful writes; callers never own its descriptor. */
internal class ExecutionInput private constructor(val interactive: Boolean, initial: ByteArray) {
    data class Snapshot(val acceptedBytes: Int, val writtenBytes: Int, val closed: Boolean,
                        val ended: Boolean, val aborted: Boolean, val endReason: String?)
    class Failure(val code: String, message: String) : IllegalStateException(message)

    private val lock = Object()
    // Lifetime admission is bounded, so a linear buffer also bounds object overhead:
    // one million one-byte submissions must not allocate one million queue nodes.
    private var buffer: ByteArray? = if (initial.isEmpty()) null else initial.copyOf()
    private var accepted = initial.size
    private var taken = 0
    private var written = 0
    private var closed = !interactive
    private var ended = false
    private var aborted = false
    private var reason: String? = null

    init {
        require(initial.size <= LIMIT)
    }

    /** Copies and accepts the entire chunk, or changes no state. Never waits for capacity. */
    fun accept(bytes: ByteArray): Int = synchronized(lock) {
        if (!interactive) throw Failure("input_mode", "Execution has finite standard input")
        if (closed || ended) throw Failure("input_closed", "Standard input is closed")
        if (bytes.size > LIMIT - accepted) throw Failure("input_limit", "Standard input exceeds 1 MiB cumulatively")
        if (bytes.isNotEmpty()) {
            val storage = buffer ?: ByteArray(LIMIT).also { buffer = it }
            bytes.copyInto(storage, accepted)
            accepted += bytes.size
            lock.notifyAll()
        }
        bytes.size
    }

    /** Rejects future writes but lets the feeder drain all previously accepted chunks. */
    fun close(): Boolean = synchronized(lock) {
        if (!interactive) throw Failure("input_mode", "Execution has finite standard input")
        if (closed || ended) return@synchronized false
        closed = true
        lock.notifyAll()
        true
    }

    /** Cancelling does not close the FD: its single feeder remains the descriptor owner. */
    fun abort(endReason: String) = synchronized(lock) {
        if (ended) return@synchronized
        closed = true
        aborted = true
        reason = reason ?: endReason
        buffer = null
        taken = accepted
        lock.notifyAll()
    }

    /** Only the feeder calls this; null means either idle or closed (inspect snapshot). */
    fun awaitChunk(timeoutMs: Long): ByteArray? = synchronized(lock) {
        require(timeoutMs in 0L..100L)
        if (taken == accepted && !closed && !ended && timeoutMs > 0) lock.wait(timeoutMs)
        if (aborted || ended || taken == accepted) null else {
            val end = minOf(accepted, taken + CHUNK_SIZE)
            val chunk = checkNotNull(buffer).copyOfRange(taken, end)
            taken = end
            chunk
        }
    }

    fun recordWritten(count: Int) = synchronized(lock) {
        check(!ended && count > 0 && count <= accepted - written)
        written += count
    }

    /** Called only after the owned input endpoint is closed, or if no feeder was created. */
    fun finish(endReason: String) = synchronized(lock) {
        if (!ended) {
            closed = true
            ended = true
            reason = reason ?: endReason
            buffer = null
            taken = accepted
            lock.notifyAll()
        }
    }

    fun snapshot(): Snapshot = synchronized(lock) {
        Snapshot(accepted, written, closed, ended, aborted, reason)
    }

    companion object {
        const val LIMIT = 1_048_576
        const val CHUNK_SIZE = 4_096
        fun finite(bytes: ByteArray) = ExecutionInput(false, bytes)
        fun interactive() = ExecutionInput(true, byteArrayOf())
    }
}
