package com.sucrune.probe.tests

import android.net.LocalServerSocket
import android.os.SystemClock
import android.system.ErrnoException
import android.system.Os
import android.system.OsConstants
import android.system.StructPollfd
import android.util.Base64
import java.io.ByteArrayOutputStream
import java.io.DataInputStream
import java.io.DataOutputStream
import java.io.FilterInputStream
import java.io.InputStream
import java.io.OutputStream
import java.security.KeyFactory
import java.security.KeyPairGenerator
import java.security.MessageDigest
import java.security.SecureRandom
import java.security.interfaces.ECPublicKey
import java.security.spec.ECGenParameterSpec
import java.security.spec.X509EncodedKeySpec
import java.util.UUID
import javax.crypto.Cipher
import javax.crypto.KeyAgreement
import javax.crypto.Mac
import javax.crypto.spec.GCMParameterSpec
import javax.crypto.spec.SecretKeySpec
import org.json.JSONObject

/** Test-only, one connection. Announce only via the trusted instrumentation
 * status channel. The caller owns and must clear the returned CharArray. Neither
 * a persistent credential store nor an exported Android application API. */
internal object DshCredentialBridge {
    fun receive(announce: (JSONObject) -> Unit, timeoutMs: Int = 30_000): CharArray {
        require(timeoutMs in 1_000..60_000) { "Invalid credential bridge deadline" }
        val deadline = SystemClock.elapsedRealtime() + timeoutMs
        fun remaining(): Int {
            val left = deadline - SystemClock.elapsedRealtime()
            if (left <= 0) throw DshCredentialFailure("deadline")
            return left.toInt()
        }
        var stage = "initialize"
        try {
            DshCredentialWire().use { wire ->
                LocalServerSocket(wire.socketName).use { server ->
                    stage = "announce"
                    announce(JSONObject().put("type", "sucrune.dsh.credential.v1").put("socket", wire.socketName)
                        .put("public_key", Base64.encodeToString(wire.publicKey, Base64.NO_WRAP))
                        .put("nonce", Base64.encodeToString(wire.nonce, Base64.NO_WRAP)))
                    stage = "accept"
                    val descriptor = StructPollfd().apply { fd = server.fileDescriptor; events = OsConstants.POLLIN.toShort() }
                    while (true) {
                        try {
                            if (Os.poll(arrayOf(descriptor), remaining()) == 0) throw DshCredentialFailure("deadline")
                            break
                        } catch (failure: ErrnoException) { if (failure.errno != OsConstants.EINTR) throw failure }
                    }
                    server.accept().use { socket ->
                        if (socket.peerCredentials.uid != 2000) throw DshCredentialFailure("peer_uid")
                        val input = object : FilterInputStream(socket.inputStream) {
                            override fun read(): Int { socket.soTimeout = remaining(); return super.read() }
                            override fun read(b: ByteArray, off: Int, len: Int): Int {
                                socket.soTimeout = remaining(); return super.read(b, off, len)
                            }
                        }
                        socket.soTimeout = remaining()
                        return wire.receive(input, socket.outputStream)
                    }
                }
            }
        } catch (failure: DshCredentialFailure) { throw failure }
        catch (_: Exception) { throw DshCredentialFailure(stage) }
    }
}

/** Portable wire implementation shared by the Android endpoint and the
 * synthetic JVM interop test. ECDH and the two-block HKDF-SHA256 use fresh
 * P-256 keys and both nonces. The host pins the public descriptor obtained
 * directly from its own instrumentation run; no value-derived digest is kept.
 * The Android endpoint separately authenticates the local peer's shell UID. */
internal class DshCredentialWire : AutoCloseable {
    val socketName = "sucrune.dsh.credential." + UUID.randomUUID().toString().replace("-", "")
    val nonce = ByteArray(32).also { SecureRandom().nextBytes(it) }
    private val pair = KeyPairGenerator.getInstance("EC").apply { initialize(ECGenParameterSpec("secp256r1")) }.generateKeyPair()
    val publicKey: ByteArray get() = pair.public.encoded
    private var used = false

    @Synchronized fun receive(input: InputStream, output: OutputStream): CharArray {
        if (used) throw DshCredentialFailure("already_used")
        used = true
        var stage = "client_hello"
        val wipe = ArrayList<ByteArray>()
        var value: CharArray? = null
        try {
            val incoming = DataInputStream(input)
            val outgoing = DataOutputStream(output)
            if (incoming.readInt() != 0x53434831) throw DshCredentialFailure(stage)
            val size = incoming.readUnsignedShort()
            if (size !in 65..128) throw DshCredentialFailure(stage)
            val clientKey = ByteArray(size).also(incoming::readFully)
            val clientNonce = ByteArray(32).also(incoming::readFully)
            stage = "key_agreement"
            val peer = KeyFactory.getInstance("EC").generatePublic(X509EncodedKeySpec(clientKey)) as ECPublicKey
            val ours = pair.public as ECPublicKey
            if (peer.params.curve != ours.params.curve || peer.params.generator != ours.params.generator ||
                peer.params.order != ours.params.order || peer.params.cofactor != ours.params.cofactor) throw DshCredentialFailure(stage)
            val shared = KeyAgreement.getInstance("ECDH").run {
                init(pair.private); doPhase(peer, true); generateSecret()
            }.also(wipe::add)
            val transcriptBytes = ByteArrayOutputStream().apply {
                DataOutputStream(this).use { data ->
                    data.write(label("sucrune-dsh-credential-v1"))
                    listOf(socketName.toByteArray(Charsets.US_ASCII), publicKey, clientKey).forEach { data.writeShort(it.size); data.write(it) }
                    data.write(nonce); data.write(clientNonce)
                }
            }.toByteArray()
            val transcript = MessageDigest.getInstance("SHA-256").digest(transcriptBytes)
            val prk = mac(nonce + clientNonce, shared).also(wipe::add)
            val info = label("sucrune-dsh-credential-v1 keys") + transcript
            val enc = mac(prk, info, byteArrayOf(1)).also(wipe::add)
            val proof = mac(prk, enc, info, byteArrayOf(2)).also(wipe::add)
            stage = "server_proof"
            outgoing.writeInt(0x53535031)
            outgoing.write(mac(proof, label("server"), transcript))
            outgoing.flush()

            stage = "credential_frame"
            if (incoming.readInt() != 0x53434431) throw DshCredentialFailure(stage)
            val encryptedSize = incoming.readUnsignedShort()
            if (encryptedSize !in 17..(MAX_TOKEN + 16)) throw DshCredentialFailure(stage)
            val iv = ByteArray(12).also(incoming::readFully)
            val encrypted = ByteArray(encryptedSize).also(incoming::readFully).also(wipe::add)
            stage = "authenticated_payload"
            val plain = Cipher.getInstance("AES/GCM/NoPadding").run {
                init(Cipher.DECRYPT_MODE, SecretKeySpec(enc, "AES"), GCMParameterSpec(128, iv))
                updateAAD(label("credential") + transcript)
                doFinal(encrypted)
            }.also(wipe::add)
            if (plain.size !in 1..MAX_TOKEN || plain.any { (it.toInt() and 255) !in 0x21..0x7e }) throw DshCredentialFailure("credential_shape")
            val accepted = CharArray(plain.size) { (plain[it].toInt() and 255).toChar() }
            value = accepted
            stage = "acknowledgment"
            outgoing.writeInt(0x53434131)
            outgoing.write(mac(proof, label("accepted"), transcript, iv))
            outgoing.flush()
            value = null
            return accepted
        } catch (failure: DshCredentialFailure) { throw failure }
        catch (_: Exception) { throw DshCredentialFailure(stage) }
        finally { value?.fill('\u0000'); wipe.forEach { it.fill(0) } }
    }

    @Synchronized override fun close() {
        used = true
        try { pair.private.destroy() } catch (_: Exception) { /* JCA provider may not support destruction. */ }
    }

    companion object {
        // Linux env entry includes DEEPSEEK_API_KEY= within the 4096-byte limit.
        private const val MAX_TOKEN = 4_079
        private fun label(value: String) = (value + "\u0000").toByteArray(Charsets.US_ASCII)
        private fun mac(key: ByteArray, vararg parts: ByteArray): ByteArray = Mac.getInstance("HmacSHA256").run {
            init(SecretKeySpec(key, "HmacSHA256")); parts.forEach(::update); doFinal()
        }
    }
}

/** The phase is a fixed implementation token. Never include an exception cause,
 * socket payload, source value, or configuration parser message in diagnostics. */
internal class DshCredentialFailure(val phase: String) : IllegalStateException("Credential bridge failed: $phase")
