package com.antigravity.blipper.android.network

import android.os.Build
import com.antigravity.blipper.android.crypto.EphemeralSessionStore
import com.antigravity.blipper.android.crypto.HardwareKeyManager
import com.antigravity.blipper.android.crypto.PairingCryptoEngine
import com.antigravity.blipper.android.crypto.SignedEnvelopeModel
import com.antigravity.blipper.android.crypto.decodeHexOrNull
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.Job
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.delay
import kotlinx.coroutines.isActive
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import okhttp3.ConnectionSpec
import okhttp3.MediaType.Companion.toMediaType
import okhttp3.OkHttpClient
import okhttp3.Request
import okhttp3.RequestBody.Companion.toRequestBody
import okhttp3.Response
import okhttp3.TlsVersion
import okhttp3.WebSocket
import okhttp3.WebSocketListener
import org.json.JSONObject
import java.nio.charset.StandardCharsets
import java.security.MessageDigest
import java.security.cert.X509Certificate
import java.util.Arrays
import java.util.Locale
import java.util.UUID
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicBoolean
import java.util.concurrent.atomic.AtomicLong

class BlipperSecureWsClient(
    private val cryptoEngine: PairingCryptoEngine,
    private val hardwareKeyManager: HardwareKeyManager,
    private val sessionStore: EphemeralSessionStore,
    private val onTaskCompleted: (eventId: String, title: String, summary: String) -> Unit,
    private val onNuclearTeardown: (reason: String) -> Unit
) {

    companion object {
        private const val HEARTBEAT_INTERVAL_MS = 12_000L
        private const val DEADMAN_TIMEOUT_MS = 30_000L
    }

    private val scope = CoroutineScope(SupervisorJob() + Dispatchers.IO)
    private val teardownGuard = AtomicBoolean(false)
    private val lastServerActivityMs = AtomicLong(0L)

    @Volatile
    private var okHttpClient: OkHttpClient? = null

    @Volatile
    private var activeWebSocket: WebSocket? = null

    @Volatile
    private var watchdogJob: Job? = null

    suspend fun pairAndConnect(
        host: String,
        tlsPort: Int,
        pinnedServerCertSha256Hex: String,
        pinCode: String
    ): Result<Unit> = withContext(Dispatchers.IO) {
        teardownGuard.set(false)
        val cleanPin = pinCode.trim()
        if (cleanPin.length < 6) {
            return@withContext Result.failure(IllegalArgumentException("Eşleştirme kodu en az 6 haneli olmalıdır."))
        }

        val pinCharsForProof = cleanPin.toCharArray()
        val pinCharsForVerify = cleanPin.toCharArray()
        try {
            val sslBundle = hardwareKeyManager.generateFreshMtlsBundle(pinnedServerCertSha256Hex)
            val strictTlsSpec = ConnectionSpec.Builder(ConnectionSpec.MODERN_TLS)
                .tlsVersions(TlsVersion.TLS_1_3)
                .build()

            val expectedPinUtf8 = pinnedServerCertSha256Hex.trim().lowercase(Locale.ROOT)
                .toByteArray(StandardCharsets.UTF_8)

            val client = OkHttpClient.Builder()
                .connectionSpecs(listOf(strictTlsSpec))
                .sslSocketFactory(sslBundle.sslSocketFactory, sslBundle.trustManager)
                .hostnameVerifier { _, session ->
                    val peerCert = session.peerCertificates.firstOrNull() as? X509Certificate ?: return@hostnameVerifier false
                    val actualUtf8 = HardwareKeyManager.sha256HexOfCert(peerCert).lowercase(Locale.ROOT)
                        .toByteArray(StandardCharsets.UTF_8)
                    MessageDigest.isEqual(expectedPinUtf8, actualUtf8)
                }
                .connectTimeout(6, TimeUnit.SECONDS)
                .readTimeout(0, TimeUnit.MILLISECONDS)
                .pingInterval(15, TimeUnit.SECONDS)
                .build()
            this@BlipperSecureWsClient.okHttpClient = client

            val timestampMs = System.currentTimeMillis()
            val nonce = UUID.randomUUID().toString()
            val proofHex = cryptoEngine.computePairingProofHex(
                pin = pinCharsForProof,
                serverCertSha256Hex = pinnedServerCertSha256Hex,
                clientCertSha256Hex = sslBundle.clientCertSha256Hex,
                timestampMs = timestampMs,
                nonce = nonce
            )

            val deviceLabel = "${Build.MANUFACTURER} ${Build.MODEL}".trim()
            val reqJson = JSONObject().apply {
                put("deviceName", deviceLabel)
                put("timestampMs", timestampMs)
                put("nonce", nonce)
                put("proofHex", proofHex)
            }.toString()

            val pairReq = Request.Builder()
                .url("https://$host:$tlsPort/api/v1/pair/complete")
                .post(reqJson.toRequestBody("application/json; charset=utf-8".toMediaType()))
                .build()

            val pairBodyText = client.newCall(pairReq).execute().use { resp ->
                val txt = resp.body?.string().orEmpty()
                if (!resp.isSuccessful) {
                    triggerLocalCleanupAndNotify("PAIRING_REJECTED_HTTP_${resp.code}")
                    return@withContext Result.failure(SecurityException("Masaüstü eşleştirmeyi reddetti (${resp.code})."))
                }
                txt
            }

            val respJson = JSONObject(pairBodyText)
            if (!respJson.optBoolean("accepted", false)) {
                triggerLocalCleanupAndNotify("PAIRING_REJECTED")
                return@withContext Result.failure(SecurityException("Eşleştirme reddedildi."))
            }

            val serverProofHex = respJson.optString("serverProofHex", "")
            val mutualServerVerified = cryptoEngine.verifyServerAckProof(
                pin = pinCharsForVerify,
                serverCertSha256Hex = pinnedServerCertSha256Hex,
                clientCertSha256Hex = sslBundle.clientCertSha256Hex,
                timestampMs = timestampMs,
                originalNonce = nonce,
                candidateServerProofHex = serverProofHex
            )
            if (!mutualServerVerified) {
                triggerLocalCleanupAndNotify("MUTUAL_SERVER_PROOF_FAILED")
                return@withContext Result.failure(SecurityException("Karşı sunucu PIN kanıtı geçersiz (MITM engellendi)!"))
            }

            val bearerToken = respJson.getString("bearerToken")
            val hmacKey = respJson.getString("hmacKeyHex").decodeHexOrNull()
                ?: throw SecurityException("Geçersiz oturum anahtarı")
            val sessionExpiresAtMs = respJson.optLong("sessionExpiresAtMs", Long.MAX_VALUE)

            try {
                sessionStore.activateSession(
                    desktopHost = host,
                    desktopPort = tlsPort,
                    serverCertSha256Hex = pinnedServerCertSha256Hex,
                    bearerToken = bearerToken,
                    hmacKey = hmacKey,
                    sessionExpiresAtMs = sessionExpiresAtMs
                )
            } finally {
                Arrays.fill(hmacKey, 0.toByte())
            }

            openAuthenticatedWebSocket(client, host, tlsPort, bearerToken)
            Result.success(Unit)
        } catch (e: Exception) {
            triggerLocalCleanupAndNotify("CONNECT_EXCEPTION")
            Result.failure(e)
        } finally {
            Arrays.fill(pinCharsForProof, '\u0000')
            Arrays.fill(pinCharsForVerify, '\u0000')
        }
    }

    private fun openAuthenticatedWebSocket(
        client: OkHttpClient,
        host: String,
        tlsPort: Int,
        bearerToken: String
    ) {
        lastServerActivityMs.set(System.currentTimeMillis())
        val wsReq = Request.Builder()
            .url("wss://$host:$tlsPort/ws/v1/stream")
            .header("Authorization", "Bearer $bearerToken")
            .build()

        activeWebSocket = client.newWebSocket(wsReq, object : WebSocketListener() {
            override fun onOpen(webSocket: WebSocket, response: Response) {
                lastServerActivityMs.set(System.currentTimeMillis())
                startHeartbeatAndWatchdog()
            }

            override fun onMessage(webSocket: WebSocket, text: String) {
                handleIncomingEnvelope(webSocket, text)
            }

            override fun onClosing(webSocket: WebSocket, code: Int, reason: String) {
                webSocket.close(1000, null)
                triggerLocalCleanupAndNotify("WS_CLOSING")
            }

            override fun onClosed(webSocket: WebSocket, code: Int, reason: String) {
                triggerLocalCleanupAndNotify("WS_CLOSED")
            }

            override fun onFailure(webSocket: WebSocket, t: Throwable, response: Response?) {
                triggerLocalCleanupAndNotify("WS_FAILURE")
            }
        })
    }

    private fun handleIncomingEnvelope(webSocket: WebSocket, rawText: String) {
        val hmacKey = sessionStore.copyHmacKey() ?: run {
            triggerLocalCleanupAndNotify("MISSING_HMAC_KEY")
            return
        }
        try {
            val env = SignedEnvelopeModel.fromJsonString(rawText)
            if (!cryptoEngine.verifyEnvelope(hmacKey, env)) {
                sendNuclearTeardownAndClose("ENVELOPE_VERIFICATION_FAILED")
                return
            }
            lastServerActivityMs.set(System.currentTimeMillis())

            when (env.type) {
                "HEARTBEAT_ACK" -> Unit
                "TASK_COMPLETED" -> {
                    val payload = JSONObject(env.payloadJson)
                    val title = payload.optString("conversationTitle", "Aktif Sohbet")
                    val summary = payload.optString("taskSummary", "Görev tamamlandı")

                    val ackPayload = JSONObject().put("ackedEventId", env.eventId).toString()
                    val ackEnv = cryptoEngine.signEnvelope(hmacKey, "TASK_ACK", ackPayload)
                    webSocket.send(ackEnv.toJsonString())

                    onTaskCompleted(env.eventId, title, summary)
                }
                "NUCLEAR_TEARDOWN" -> {
                    triggerLocalCleanupAndNotify("REMOTE_DESKTOP_NUCLEAR_TEARDOWN")
                }
            }
        } catch (_: Exception) {
            sendNuclearTeardownAndClose("MALFORMED_ENVELOPE")
        } finally {
            Arrays.fill(hmacKey, 0.toByte())
        }
    }

    private fun startHeartbeatAndWatchdog() {
        watchdogJob?.cancel()
        watchdogJob = scope.launch {
            while (isActive && sessionStore.state.value.connected) {
                delay(HEARTBEAT_INTERVAL_MS)
                val now = System.currentTimeMillis()
                if (sessionStore.isExpired(now)) {
                    sendNuclearTeardownAndClose("ANDROID_TTL_EXPIRED")
                    return@launch
                }
                if (now - lastServerActivityMs.get() > DEADMAN_TIMEOUT_MS) {
                    sendNuclearTeardownAndClose("ANDROID_DEADMAN_30S_TIMEOUT")
                    return@launch
                }
                val hmacKey = sessionStore.copyHmacKey() ?: continue
                try {
                    val hb = cryptoEngine.signEnvelope(hmacKey, "HEARTBEAT", "{}")
                    activeWebSocket?.send(hb.toJsonString())
                } finally {
                    Arrays.fill(hmacKey, 0.toByte())
                }
            }
        }
    }

    fun sendNuclearTeardownAndClose(reason: String) {
        if (!teardownGuard.compareAndSet(false, true)) {
            return
        }
        watchdogJob?.cancel()
        watchdogJob = null

        val ws = activeWebSocket
        val hmacKey = sessionStore.copyHmacKey()
        if (ws != null && hmacKey != null) {
            try {
                val payload = JSONObject().put("reason", reason).toString()
                val env = cryptoEngine.signEnvelope(hmacKey, "NUCLEAR_TEARDOWN", payload)
                val enqueued = ws.send(env.toJsonString())
                ws.close(1000, "NUCLEAR_TEARDOWN")
                if (enqueued) {
                    runCatching { Thread.sleep(120L) }
                }
            } catch (_: Exception) {
            } finally {
                Arrays.fill(hmacKey, 0.toByte())
            }
        }
        shutdownTransportAndWipe(reason)
    }

    private fun triggerLocalCleanupAndNotify(reason: String) {
        if (!teardownGuard.compareAndSet(false, true)) {
            return
        }
        watchdogJob?.cancel()
        watchdogJob = null
        shutdownTransportAndWipe(reason)
    }

    private fun shutdownTransportAndWipe(reason: String) {
        runCatching { activeWebSocket?.cancel() }
        activeWebSocket = null
        okHttpClient?.let { client ->
            runCatching { client.dispatcher.executorService.shutdown() }
            runCatching { client.connectionPool.evictAll() }
        }
        okHttpClient = null
        cryptoEngine.clearReplayCache()
        hardwareKeyManager.wipeAllKeys()
        sessionStore.wipeEverything()
        onNuclearTeardown(reason)
    }
}
