package com.antigravity.blipper.android.crypto

import org.json.JSONObject
import java.nio.charset.StandardCharsets
import java.security.MessageDigest
import java.util.Arrays
import java.util.LinkedHashMap
import java.util.Locale
import java.util.UUID
import javax.crypto.Mac
import javax.crypto.SecretKeyFactory
import javax.crypto.spec.PBEKeySpec
import javax.crypto.spec.SecretKeySpec
import kotlin.math.abs

data class SignedEnvelopeModel(
    val type: String,
    val eventId: String,
    val timestampMs: Long,
    val payloadJson: String,
    val hmacHex: String
) {
    fun canonicalSigningInput(): String = "$type\n$eventId\n$timestampMs\n$payloadJson"

    fun toJsonString(): String = JSONObject().apply {
        put("type", type)
        put("eventId", eventId)
        put("timestampMs", timestampMs)
        put("payloadJson", payloadJson)
        put("hmacHex", hmacHex)
    }.toString()

    companion object {
        fun fromJsonString(rawJson: String): SignedEnvelopeModel {
            val obj = JSONObject(rawJson)
            return SignedEnvelopeModel(
                type = obj.optString("type", ""),
                eventId = obj.optString("eventId", ""),
                timestampMs = obj.optLong("timestampMs", 0L),
                payloadJson = obj.optString("payloadJson", ""),
                hmacHex = obj.optString("hmacHex", "")
            )
        }
    }
}

class PairingCryptoEngine {

    companion object {
        const val PBKDF2_ITERATIONS = 210_000
        const val ALLOWED_CLOCK_SKEW_MS = 30_000L
        private const val MAX_REPLAY_CACHE_SIZE = 4096
    }

    private val replayLock = Any()
    private val seenEventIds = object : LinkedHashMap<String, Long>(256, 0.75f, true) {
        override fun removeEldestEntry(eldest: MutableMap.MutableEntry<String, Long>?): Boolean {
            return size > MAX_REPLAY_CACHE_SIZE
        }
    }

    fun computePairingProofHex(
        pin: CharArray,
        serverCertSha256Hex: String,
        clientCertSha256Hex: String,
        timestampMs: Long,
        nonce: String
    ): String {
        val sHex = serverCertSha256Hex.trim().lowercase(Locale.ROOT)
        val cHex = clientCertSha256Hex.trim().lowercase(Locale.ROOT)
        val salt = "$sHex:$cHex".toByteArray(StandardCharsets.UTF_8)
        val spec = PBEKeySpec(pin, salt, PBKDF2_ITERATIONS, 256)
        var derivedKey: ByteArray? = null
        try {
            val skf = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256")
            derivedKey = skf.generateSecret(spec).encoded
            val msg = "PAIR-V1|$sHex|$cHex|$timestampMs|$nonce".toByteArray(StandardCharsets.UTF_8)
            return hmacSha256(derivedKey, msg).toLowerHex()
        } finally {
            spec.clearPassword()
            Arrays.fill(pin, '\u0000')
            derivedKey?.let { Arrays.fill(it, 0.toByte()) }
        }
    }

    fun verifyServerAckProof(
        pin: CharArray,
        serverCertSha256Hex: String,
        clientCertSha256Hex: String,
        timestampMs: Long,
        originalNonce: String,
        candidateServerProofHex: String
    ): Boolean {
        val candidateBytes = candidateServerProofHex.decodeHexOrNull() ?: run {
            Arrays.fill(pin, '\u0000')
            return false
        }
        val expectedHex = computePairingProofHex(
            pin,
            serverCertSha256Hex,
            clientCertSha256Hex,
            timestampMs,
            "$originalNonce:SERVER_ACK"
        )
        val expectedBytes = expectedHex.decodeHexOrNull() ?: return false
        return MessageDigest.isEqual(expectedBytes, candidateBytes)
    }

    fun signEnvelope(hmacKey: ByteArray, type: String, payloadJson: String): SignedEnvelopeModel {
        return signEnvelopeAt(
            hmacKey = hmacKey,
            type = type,
            payloadJson = payloadJson,
            eventId = UUID.randomUUID().toString(),
            timestampMs = System.currentTimeMillis()
        )
    }

    fun signEnvelopeAt(
        hmacKey: ByteArray,
        type: String,
        payloadJson: String,
        eventId: String,
        timestampMs: Long
    ): SignedEnvelopeModel {
        val unsigned = SignedEnvelopeModel(type, eventId, timestampMs, payloadJson, "")
        val mac = hmacSha256(hmacKey, unsigned.canonicalSigningInput().toByteArray(StandardCharsets.UTF_8))
        return unsigned.copy(hmacHex = mac.toLowerHex())
    }

    fun verifyEnvelope(hmacKey: ByteArray, envelope: SignedEnvelopeModel): Boolean {
        if (hmacKey.size < 32 || envelope.eventId.isBlank() || envelope.hmacHex.isBlank()) {
            return false
        }
        val now = System.currentTimeMillis()
        if (abs(now - envelope.timestampMs) > ALLOWED_CLOCK_SKEW_MS) {
            return false
        }
        val candidateMac = envelope.hmacHex.decodeHexOrNull() ?: return false
        val expectedMac = hmacSha256(
            hmacKey,
            envelope.canonicalSigningInput().toByteArray(StandardCharsets.UTF_8)
        )
        if (!MessageDigest.isEqual(expectedMac, candidateMac)) {
            return false
        }
        synchronized(replayLock) {
            val iter = seenEventIds.entries.iterator()
            while (iter.hasNext()) {
                val entry = iter.next()
                if (now - entry.value > ALLOWED_CLOCK_SKEW_MS * 2) {
                    iter.remove()
                }
            }
            if (seenEventIds.containsKey(envelope.eventId)) {
                return false
            }
            seenEventIds[envelope.eventId] = now
        }
        return true
    }

    fun clearReplayCache() {
        synchronized(replayLock) {
            seenEventIds.clear()
        }
    }

    private fun hmacSha256(key: ByteArray, data: ByteArray): ByteArray {
        val mac = Mac.getInstance("HmacSHA256")
        mac.init(SecretKeySpec(key, "HmacSHA256"))
        return mac.doFinal(data)
    }
}

internal fun ByteArray.toLowerHex(): String {
    val hexChars = "0123456789abcdef"
    val out = CharArray(size * 2)
    for (i in indices) {
        val v = this[i].toInt() and 0xFF
        out[i * 2] = hexChars[v ushr 4]
        out[i * 2 + 1] = hexChars[v and 0x0F]
    }
    return String(out)
}

internal fun String.decodeHexOrNull(): ByteArray? {
    val clean = trim().lowercase(Locale.ROOT)
    if (clean.isEmpty() || clean.length % 2 != 0) return null
    val out = ByteArray(clean.length / 2)
    for (i in out.indices) {
        val hi = Character.digit(clean[i * 2], 16)
        val lo = Character.digit(clean[i * 2 + 1], 16)
        if (hi == -1 || lo == -1) return null
        out[i] = ((hi shl 4) or lo).toByte()
    }
    return out
}
