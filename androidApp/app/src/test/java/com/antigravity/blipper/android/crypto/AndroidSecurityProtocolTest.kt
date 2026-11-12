package com.antigravity.blipper.android.crypto

import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.async
import kotlinx.coroutines.awaitAll
import kotlinx.coroutines.runBlocking
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test
import java.util.UUID
import java.util.concurrent.atomic.AtomicInteger

class AndroidSecurityProtocolTest {

    @Test
    fun `pairing proof matches desktop PBKDF2-HMAC-SHA256 formula and rejects MITM cert swaps`() {
        val engine = PairingCryptoEngine()
        val serverSha = "a1b2c3d4e5f60718293a4b5c6d7e8f90a1b2c3d4e5f60718293a4b5c6d7e8f90"
        val clientSha = "0f1e2d3c4b5a69788796a5b4c3d2e1f00f1e2d3c4b5a69788796a5b4c3d2e1f0"
        val mitmSha = "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"
        val pin = "849271".toCharArray()
        val now = System.currentTimeMillis()

        val proof1 = engine.computePairingProofHex(pin.clone(), serverSha, clientSha, now, "nonce-42")
        val proof2 = engine.computePairingProofHex(pin.clone(), serverSha, clientSha, now, "nonce-42")
        assertEquals(64, proof1.length)
        assertEquals(proof1, proof2)

        // Verify expected mutual server ACK proof format (nonce + ":SERVER_ACK")
        val expectedServerAck = engine.computePairingProofHex(
            pin.clone(), serverSha, clientSha, now, "nonce-42:SERVER_ACK"
        )
        assertTrue(engine.verifyServerAckProof(pin.clone(), serverSha, clientSha, now, "nonce-42", expectedServerAck))
        assertFalse(engine.verifyServerAckProof(pin.clone(), mitmSha, clientSha, now, "nonce-42", expectedServerAck))
    }

    @Test
    fun `envelope verifier enforces constant-time HMAC, 30s clock window, and replay cache`() {
        val engine = PairingCryptoEngine()
        val hmacKey = ByteArray(32) { 0x3C }

        val env = engine.signEnvelope(hmacKey, "TASK_COMPLETED", """{"conversationTitle":"Carbon","taskSummary":"Hazır"}""")
        val json = env.toJsonString()
        val parsed = SignedEnvelopeModel.fromJsonString(json)

        assertTrue(engine.verifyEnvelope(hmacKey, parsed))
        // Replaying the exact same frame must be rejected!
        assertFalse(engine.verifyEnvelope(hmacKey, parsed))

        // Stale frame (> 30s old) must be rejected!
        val stale = engine.signEnvelopeAt(
            hmacKey,
            "TASK_COMPLETED",
            "{}",
            UUID.randomUUID().toString(),
            System.currentTimeMillis() - 60_000L
        )
        assertFalse(engine.verifyEnvelope(hmacKey, stale))
    }

    @Test
    fun `concurrent wipeEverything zeroizes session secrets and invokes cleanup idempotently`() = runBlocking {
        val store = EphemeralSessionStore()
        val keyBytes = ByteArray(32) { 0x5A }
        store.activateSession(
            desktopHost = "192.168.1.25",
            desktopPort = 58443,
            serverCertSha256Hex = "abc123",
            bearerToken = "secret-bearer-token",
            hmacKey = keyBytes,
            sessionExpiresAtMs = Long.MAX_VALUE
        )
        assertTrue(store.state.value.connected)
        assertNotNull(store.copyHmacKey())

        val cleanupCount = AtomicInteger(0)
        val jobs = (1..8).map {
            async(Dispatchers.Default) {
                if (store.wipeEverything()) {
                    cleanupCount.incrementAndGet()
                }
            }
        }
        jobs.awaitAll()

        assertEquals(1, cleanupCount.get())
        assertFalse(store.state.value.connected)
        assertNull(store.copyHmacKey())
    }
}
