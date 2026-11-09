package com.sucrune.probe

/** One consuming, process-local reader for one launch. Reads never wait for
 * data. Process bytes before checking eof, which can accompany the final bytes.
 * Close the handle to release unread output without stopping the guest. */
class ExecutionStdout : AutoCloseable {
    data class Read(val bytes: ByteArray, val eof: Boolean)

    private enum class State { NEW, OPEN, EOF, OVERFLOW, FAILED, CLOSED }
    private var state = State.NEW
    private var storage: ByteArray? = null
    private var head = 0
    private var size = 0

    @Synchronized internal fun attach() {
        if (state != State.NEW) throw RuntimeExceptionWithCode("output_in_use", "Output handle is single-use")
        state = State.OPEN
    }

    /** The caller has already applied its stdout redaction filter. Capacity
     * applies to unread bytes. The producer never waits for room or for a reader. */
    @Synchronized internal fun publish(bytes: ByteArray, count: Int) {
        if (state != State.OPEN || count == 0) return
        if (count > UNREAD_LIMIT - size) {
            state = State.OVERFLOW
            discard()
            return
        }
        val ring = storage ?: ByteArray(UNREAD_LIMIT).also { storage = it }
        val tail = (head + size) % UNREAD_LIMIT
        val first = minOf(count, UNREAD_LIMIT - tail)
        bytes.copyInto(ring, tail, 0, first)
        bytes.copyInto(ring, 0, first, count)
        size += count
    }

    @Synchronized internal fun finish(cleanEof: Boolean) {
        if (state != State.OPEN) return
        state = if (cleanEof) State.EOF else State.FAILED
        if (!cleanEof || size == 0) discard()
    }

    /** Empty bytes and eof=false mean no bytes are available yet. Overflow is
     * terminal, so consumers cannot accidentally parse a suffix after a gap. */
    @Synchronized fun read(maxBytes: Int = 16_384): Read {
        require(maxBytes in 1..READ_LIMIT) { "A read must request 1..65536 bytes" }
        when (state) {
            State.NEW -> throw RuntimeExceptionWithCode("output_not_attached", "Attach this handle at launch")
            State.CLOSED -> throw RuntimeExceptionWithCode("output_closed", "Output reader is closed")
            State.FAILED -> throw RuntimeExceptionWithCode("output_failed", "Output stream did not reach a clean EOF")
            State.OVERFLOW -> throw RuntimeExceptionWithCode("output_overflow", "Unread stdout exceeded 1 MiB")
            State.OPEN, State.EOF -> Unit
        }
        val count = minOf(maxBytes, size)
        if (count == 0) return Read(EMPTY, state == State.EOF)
        val ring = checkNotNull(storage)
        val bytes = ByteArray(count)
        val first = minOf(count, UNREAD_LIMIT - head)
        ring.copyInto(bytes, 0, head, head + first)
        ring.copyInto(bytes, first, 0, count - first)
        ring.fill(0, head, head + first)
        ring.fill(0, 0, count - first)
        head = (head + count) % UNREAD_LIMIT
        size -= count
        val eof = size == 0 && state == State.EOF
        if (eof) discard()
        return Read(bytes, eof)
    }

    @Synchronized override fun close() {
        state = State.CLOSED
        discard()
    }

    private fun discard() {
        storage?.fill(0)
        storage = null
        size = 0
        head = 0
    }

    companion object {
        const val UNREAD_LIMIT = 1_048_576
        const val READ_LIMIT = 65_536
        private val EMPTY = ByteArray(0)
    }
}
