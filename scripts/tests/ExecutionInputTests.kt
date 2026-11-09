package com.sucrune.probe

import java.util.concurrent.CountDownLatch
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicInteger
import java.util.concurrent.atomic.AtomicReference
import kotlin.concurrent.thread

private fun failure(code: String, action: () -> Unit) {
    try { action(); error("Expected $code") }
    catch (error: ExecutionInput.Failure) { check(error.code == code) }
}

private fun joined(worker: Thread) {
    worker.join(3_000)
    check(!worker.isAlive) { "Input test thread did not finish" }
}

fun main() {
    var passed = 0
    fun test(name: String, run: () -> Unit) { run(); passed++; println("PASS $name") }

    test("finite copies input and remains EOF-after-drain") {
        val source = byteArrayOf(1, 2, 3)
        val input = ExecutionInput.finite(source)
        source[0] = 99
        check(input.snapshot().closed && !input.snapshot().ended)
        check(input.awaitChunk(0)!!.contentEquals(byteArrayOf(1, 2, 3)))
        input.recordWritten(3)
        check(input.awaitChunk(0) == null)
        failure("input_mode") { input.accept(byteArrayOf()) }
        failure("input_mode") { input.close() }
        input.finish("eof")
        check(input.snapshot() == ExecutionInput.Snapshot(3, 3, true, true, false, "eof"))
    }
    test("finite empty input ends without waiting") {
        val input = ExecutionInput.finite(byteArrayOf())
        check(input.awaitChunk(100) == null)
        input.finish("eof")
        check(input.snapshot().ended && input.snapshot().acceptedBytes == 0)
    }
    test("interactive idle is distinct from EOF and copies callers") {
        val input = ExecutionInput.interactive()
        check(input.awaitChunk(0) == null && !input.snapshot().closed)
        check(input.accept(byteArrayOf()) == 0)
        val chunk = byteArrayOf(7, 8)
        check(input.accept(chunk) == 2)
        chunk[1] = 99
        check(input.awaitChunk(0)!!.contentEquals(byteArrayOf(7, 8)))
        check(input.snapshot().writtenBytes == 0)
        input.recordWritten(1)
        check(input.snapshot().writtenBytes == 1 && !input.snapshot().closed)
        input.recordWritten(1)
        input.close()
        input.finish("eof")
    }
    test("explicit close drains FIFO and is idempotent") {
        val input = ExecutionInput.interactive()
        input.accept(byteArrayOf(1)); input.accept(byteArrayOf(2, 3))
        check(input.close()); check(!input.close())
        failure("input_closed") { input.accept(byteArrayOf(4)) }
        failure("input_closed") { input.accept(byteArrayOf()) }
        check(input.awaitChunk(0)!!.contentEquals(byteArrayOf(1, 2, 3)))
        input.recordWritten(3)
        check(input.awaitChunk(0) == null)
        check(!input.snapshot().ended)
        input.finish("eof")
        check(input.snapshot().ended)
    }
    test("one MiB lifetime limit does not reset after writes") {
        val input = ExecutionInput.interactive()
        val almost = ByteArray(ExecutionInput.LIMIT - 1)
        check(input.accept(almost) == almost.size)
        failure("input_limit") { input.accept(byteArrayOf(1, 2)) }
        check(input.snapshot().acceptedBytes == almost.size)
        var sent = 0
        while (true) {
            val chunk = input.awaitChunk(0) ?: break
            check(chunk.size <= ExecutionInput.CHUNK_SIZE)
            input.recordWritten(chunk.size); sent += chunk.size
        }
        check(sent == almost.size)
        check(input.accept(byteArrayOf(1)) == 1)
        failure("input_limit") { input.accept(byteArrayOf(2)) }
        check(input.snapshot().acceptedBytes == ExecutionInput.LIMIT)
        input.abort("cancelled"); input.finish("cancelled")
    }
    test("oversized first submission has no partial admission") {
        val input = ExecutionInput.interactive()
        failure("input_limit") { input.accept(ByteArray(ExecutionInput.LIMIT + 1)) }
        check(input.snapshot().acceptedBytes == 0 && input.awaitChunk(0) == null)
    }
    test("cancel discards queued chunks and preserves actual write count") {
        val input = ExecutionInput.interactive()
        input.accept(byteArrayOf(1, 2))
        input.awaitChunk(0)
        input.recordWritten(1)
        input.accept(byteArrayOf(3))
        input.abort("cancelled")
        check(input.awaitChunk(0) == null)
        failure("input_closed") { input.accept(byteArrayOf(9)) }
        check(!input.snapshot().ended)
        input.finish("eof")
        check(input.snapshot() == ExecutionInput.Snapshot(3, 1, true, true, true, "cancelled"))
    }
    test("startup failure finishes queued input without pretending writes") {
        val input = ExecutionInput.interactive()
        input.accept(byteArrayOf(1, 2, 3))
        input.finish("startup_failed")
        check(input.awaitChunk(0) == null)
        check(input.snapshot() == ExecutionInput.Snapshot(3, 0, true, true, false, "startup_failed"))
        failure("input_closed") { input.accept(byteArrayOf(1)) }
        input.finish("eof")
        check(input.snapshot().endReason == "startup_failed")
    }
    test("close and abort wake idle feeder") {
        for (abort in listOf(false, true)) {
            val input = ExecutionInput.interactive()
            val started = CountDownLatch(1)
            val error = AtomicReference<Throwable?>()
            val worker = thread {
                try {
                    started.countDown()
                    while (!input.snapshot().closed) input.awaitChunk(100)
                } catch (failure: Throwable) { error.set(failure) }
            }
            check(started.await(1, TimeUnit.SECONDS))
            if (abort) input.abort("cancelled") else input.close()
            joined(worker)
            error.get()?.let { throw it }
        }
    }
    test("concurrent writers obey atomic chunk and shared lifetime bound") {
        val input = ExecutionInput.interactive()
        val start = CountDownLatch(1)
        val accepted = AtomicInteger()
        val rejected = AtomicInteger()
        val error = AtomicReference<Throwable?>()
        val writers = (1..4).map { value -> thread {
            try {
                start.await()
                repeat(4) {
                    try { accepted.addAndGet(input.accept(ByteArray(131_072) { value.toByte() })) }
                    catch (failure: ExecutionInput.Failure) { check(failure.code == "input_limit"); rejected.incrementAndGet() }
                }
            } catch (failure: Throwable) { error.compareAndSet(null, failure) }
        } }
        start.countDown(); writers.forEach(::joined)
        error.get()?.let { throw it }
        check(accepted.get() == ExecutionInput.LIMIT && rejected.get() == 8)
        input.close()
        var count = 0
        while (true) {
            val chunk = input.awaitChunk(0) ?: break
            check(chunk.size == ExecutionInput.CHUNK_SIZE && chunk.all { it == chunk[0] })
            input.recordWritten(chunk.size); count++
        }
        check(count == ExecutionInput.LIMIT / ExecutionInput.CHUNK_SIZE && input.snapshot().writtenBytes == ExecutionInput.LIMIT)
        input.finish("eof")
    }
    test("one million tiny writes coalesce to bounded feeder chunks") {
        val input = ExecutionInput.interactive()
        val one = byteArrayOf(17)
        repeat(ExecutionInput.LIMIT) { check(input.accept(one) == 1) }
        input.close()
        var chunks = 0
        while (true) {
            val chunk = input.awaitChunk(0) ?: break
            check(chunk.size == ExecutionInput.CHUNK_SIZE && chunk.all { it == 17.toByte() })
            input.recordWritten(chunk.size); chunks++
        }
        check(chunks == 256 && input.snapshot().acceptedBytes == ExecutionInput.LIMIT)
        input.finish("eof")
    }
    test("concurrent close never admits a chunk after it returns") {
        repeat(100) {
            val input = ExecutionInput.interactive()
            val start = CountDownLatch(1)
            val error = AtomicReference<Throwable?>()
            val writer = thread {
                try { start.await(); input.accept(byteArrayOf(1)) }
                catch (failure: ExecutionInput.Failure) { if (failure.code != "input_closed") error.set(failure) }
                catch (failure: Throwable) { error.set(failure) }
            }
            start.countDown(); input.close(); joined(writer)
            error.get()?.let { throw it }
            failure("input_closed") { input.accept(byteArrayOf(2)) }
            check(input.snapshot().acceptedBytes in 0..1)
            input.finish("eof")
        }
    }
    println("ExecutionInput: $passed tests passed (host state/queue only; no Android FD or guest claims)")
}
