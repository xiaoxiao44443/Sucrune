package com.sucrune.probe

import java.util.concurrent.CountDownLatch
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicReference
import kotlin.concurrent.thread

private fun expectOutputError(code: String, operation: () -> Unit) {
    try { operation(); error("Missing error $code") }
    catch (failure: RuntimeExceptionWithCode) { check(failure.code == code) }
}

fun main() {
    ExecutionStdout().use { out ->
        expectOutputError("output_not_attached") { out.read() }
        out.attach()
        expectOutputError("output_in_use") { out.attach() }
        check(out.read().let { it.bytes.isEmpty() && !it.eof })
        for (size in listOf(0, 65_537)) {
            check(runCatching { out.read(size) }.exceptionOrNull() is IllegalArgumentException)
        }
        val copied = byteArrayOf(1, 2, 3, 4)
        out.publish(copied, 3)
        copied.fill(9)
        out.finish(true)
        check(out.read(2).let { it.bytes.contentEquals(byteArrayOf(1, 2)) && !it.eof })
        check(out.read().let { it.bytes.contentEquals(byteArrayOf(3)) && it.eof })
        check(out.read().let { it.bytes.isEmpty() && it.eof })
    }
    ExecutionStdout().use { out ->
        out.attach()
        val capacity = ExecutionStdout.UNREAD_LIMIT
        val initial = ByteArray(capacity) { (it * 31).toByte() }
        out.publish(initial, initial.size)
        val consumed = out.read(65_531).bytes
        check(consumed.contentEquals(initial.copyOfRange(0, consumed.size)))
        val more = ByteArray(consumed.size) { (it * 17 + 9).toByte() }
        out.publish(more, more.size)
        out.finish(true)
        val expected = initial.copyOfRange(consumed.size, capacity) + more
        var checked = 0
        while (true) {
            val part = out.read(13_823)
            check(part.bytes.contentEquals(expected.copyOfRange(checked, checked + part.bytes.size)))
            checked += part.bytes.size
            if (part.eof) break
            check(part.bytes.isNotEmpty())
        }
        check(checked == capacity)
    }
    ExecutionStdout().use { out ->
        out.attach()
        val bytes = ByteArray(4_096) { 65 }
        repeat(ExecutionStdout.UNREAD_LIMIT / bytes.size) { out.publish(bytes, bytes.size) }
        out.publish(bytes, 1)
        out.finish(true)
        repeat(2) { expectOutputError("output_overflow") { out.read() } }
    }
    ExecutionStdout().use { out ->
        out.attach()
        out.publish(byteArrayOf(1, 2), 2)
        out.finish(false)
        out.finish(true)
        expectOutputError("output_failed") { out.read() }
    }
    val closed = ExecutionStdout()
    closed.attach()
    closed.close()
    closed.publish(byteArrayOf(17), 1)
    closed.finish(true)
    expectOutputError("output_closed") { closed.read() }
    expectOutputError("output_in_use") { closed.attach() }

    // A withheld reader cannot hold up the producer at overflow or completion.
    val out = ExecutionStdout()
    out.attach()
    val completed = CountDownLatch(1)
    val problem = AtomicReference<Throwable?>()
    val worker = thread(name = "stdout-test-producer", isDaemon = true) {
        try {
            val bytes = ByteArray(4_096)
            repeat(1_024) { out.publish(bytes, bytes.size) }
            out.finish(true)
        } catch (failure: Throwable) { problem.set(failure) }
        finally { completed.countDown() }
    }
    check(completed.await(5, TimeUnit.SECONDS))
    worker.join(1_000)
    check(!worker.isAlive)
    problem.get()?.let { throw it }
    expectOutputError("output_overflow") { out.read() }
    out.close()
    println("PASS stdout single-use/copy/read bounds, exact capacity/wrap/reuse, final bytes/EOF, sticky overflow, setup failure, early close and producer completion with absent reader")
}
