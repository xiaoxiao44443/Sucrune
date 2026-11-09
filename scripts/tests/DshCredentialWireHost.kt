package com.sucrune.probe.tests

import java.net.InetAddress
import java.net.ServerSocket
import java.util.Base64

/** Synthetic-only Java Crypto provider interop. Does not emulate Android UID
 * credentials, abstract sockets, ADB forwarding or the instrumentation channel. */
fun main(args: Array<String>) {
    val expected = args.single()
    check(expected in setOf("success", "device_fixture", "unauthenticated", "tampered", "source_refused", "truncated"))
    DshCredentialWire().use { wire ->
        ServerSocket(0, 1, InetAddress.getByName("127.0.0.1")).use { server ->
            server.soTimeout = 10_000
            val pub = Base64.getEncoder().encodeToString(wire.publicKey)
            val nonce = Base64.getEncoder().encodeToString(wire.nonce)
            println("{\"port\":${server.localPort},\"type\":\"sucrune.dsh.credential.v1\",\"socket\":\"${wire.socketName}\",\"public_key\":\"$pub\",\"nonce\":\"$nonce\"}")
            System.out.flush()
            server.accept().use { socket ->
                socket.soTimeout = 5_000
                try {
                    val received = wire.receive(socket.getInputStream(), socket.getOutputStream())
                    try {
                        val marker = if (expected == "device_fixture") "sucrune-synthetic-device-bridge-v1" else "synthetic-wire-token"
                        check(expected in setOf("success", "device_fixture") && received.contentEquals(marker.toCharArray()))
                    }
                    finally { received.fill('\u0000') }
                } catch (failure: DshCredentialFailure) {
                    val phase = when (expected) {
                        "unauthenticated", "source_refused", "truncated" -> "credential_frame"
                        "tampered" -> "authenticated_payload"
                        else -> "unexpected_failure"
                    }
                    check(failure.phase == phase) { "Unexpected synthetic rejection phase" }
                }
                try { wire.receive(socket.getInputStream(), socket.getOutputStream()); error("Wire reused") }
                catch (failure: DshCredentialFailure) { check(failure.phase == "already_used") }
            }
        }
    }
    println("PASS " + expected)
}
