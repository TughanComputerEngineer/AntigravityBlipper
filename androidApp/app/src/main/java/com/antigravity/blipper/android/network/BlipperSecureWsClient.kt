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
import kotlinx.coroutines.cancel
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
import java.security.cert.CertificateException
import java.security.cert.X509Certificate
import java.util.Arrays
import java.util.Locale
import java.util.UUID
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicBoolean
import java.util.concurrent.atomic.AtomicInteger
import java.util.concurrent.atomic.AtomicLong
import javax.net.ssl.SSLHandshakeException
import javax.net.ssl.SSLPeerUnverifiedException

class BlipperSecureWsClient(
    private val cryptoEngine: PairingCryptoEngine,
    private val hardwareKeyManager: HardwareKeyManager,
    private val sessionStore: EphemeralSessionStore,
    private val onTaskCompleted: (eventId: String, title: String, summary: String) -> Unit,
    private val onNuclearTeardown: (reason: String) -> Unit
) {

    companion object {
        private const val HEARTBEAT_INTERVAL_MS = 18_000L
        private val RECONNECT_BACKOFF_MS = longArrayOf(1_000L, 2_000L, 3_500L, 5_000L)

        fun shouldTerminateSessionOnFailure(
            throwable: Throwable?,
            httpStatusCode: Int?,
            sessionExpired: Boolean,
            explicitTeardownRequested: Boolean
        ): Boolean {
            if (explicitTeardownRequested || sessionExpired) {
                return true
            }
            if (httpStatusCode == 401 || httpStatusCode == 403) {
                return true
            }
            var cur: Throwable? = throwable
            var depth = 0
            while (cur != null && depth < 8) {
                if (cur is SSLHandshakeException ||
                    cur is SSLPeerUnverifiedException ||
                    cur is CertificateException ||
                    cur is SecurityException
                ) {
                    return true
                }
                cur = cur.cause
                depth++
            }
            return false
        }
    }

    private val scope = CoroutineScope(SupervisorJob() + Dispatchers.IO)
    private val teardownGuard = AtomicBoolean(false)
    private val reconnectingGuard = AtomicBoolean(false)
    private val reconnectAttempt = AtomicInteger(0)
    private val connectionSeq = AtomicLong(0L)

    @Volatile
    private var okHttpClient: OkHttpClient? = null

    @Volatile
    private var activeWebSocket: WebSocket? = null

    @Volatile
    private var watchdogJob: Job? = null

    @Volatile
    private var reconnectJob: Job? = null

    @Volatile
    private var sessionHost: String = ""

    @Volatile
    private var sessionPort: Int = 0

    suspend fun pairAndConnect(
        host: String,
        tlsPort: Int,
        pinnedServerCertSha256Hex: String,
        pinCode: String
    ): Result<Unit> = withContext(Dispatchers.IO) {
        teardownGuard.set(false)
        reconnectingGuard.set(false)
        reconnectAttempt.set(0)
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
                .connectTimeout(8, TimeUnit.SECONDS)
                .readTimeout(0, TimeUnit.MILLISECONDS)
                .pingInterval(25, TimeUnit.SECONDS)
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
                .header("Connection", "close")
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

            this@BlipperSecureWsClient.sessionHost = host
            this@BlipperSecureWsClient.sessionPort = tlsPort

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

            startSessionTtlAndHeartbeatWatchdog()
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
        if (teardownGuard.get()) {
            return
        }
        val seq = connectionSeq.incrementAndGet()
        val wsReq = Request.Builder()
            .url("wss://$host:$tlsPort/ws/v1/stream")
            .header("Authorization", "Bearer $bearerToken")
            .build()

        activeWebSocket = client.newWebSocket(wsReq, object : WebSocketListener() {
            override fun onOpen(webSocket: WebSocket, response: Response) {
                if (connectionSeq.get() != seq || teardownGuard.get()) {
                    runCatching { webSocket.close(1000, null) }
                    return
                }
                reconnectAttempt.set(0)
                reconnectingGuard.set(false)
                sessionStore.updateLiveStreamStatus("🟢 mTLS 1.3 Şifreli Bağlı ($host:$tlsPort)")
            }

            override fun onMessage(webSocket: WebSocket, text: String) {
                if (connectionSeq.get() == seq) {
                    handleIncomingEnvelope(webSocket, text)
                }
            }

            override fun onClosing(webSocket: WebSocket, code: Int, reason: String) {
                runCatching { webSocket.close(1000, null) }
                if (reason == "NUCLEAR_TEARDOWN" || teardownGuard.get()) {
                    triggerLocalCleanupAndNotify("WS_REMOTE_NUCLEAR_CLOSE")
                } else if (connectionSeq.get() == seq) {
                    handleTransientOrTerminalDisconnect(null, null)
                }
            }

            override fun onClosed(webSocket: WebSocket, code: Int, reason: String) {
                if (reason == "NUCLEAR_TEARDOWN" || teardownGuard.get()) {
                    triggerLocalCleanupAndNotify("WS_CLOSED")
                } else if (connectionSeq.get() == seq) {
                    handleTransientOrTerminalDisconnect(null, null)
                }
            }

            override fun onFailure(webSocket: WebSocket, t: Throwable, response: Response?) {
                if (connectionSeq.get() == seq) {
                    handleTransientOrTerminalDisconnect(t, response?.code)
                }
            }
        })
    }

    private fun handleTransientOrTerminalDisconnect(throwable: Throwable?, httpStatusCode: Int?) {
        val expired = sessionStore.isExpired(System.currentTimeMillis())
        if (shouldTerminateSessionOnFailure(
                throwable = throwable,
                httpStatusCode = httpStatusCode,
                sessionExpired = expired,
                explicitTeardownRequested = teardownGuard.get()
            )
        ) {
            if (expired) {
                sendNuclearTeardownAndClose("ANDROID_TTL_EXPIRED")
            } else {
                val reason = if (httpStatusCode != null) "DESKTOP_HTTP_$httpStatusCode" else "DESKTOP_SESSION_CLOSED"
                triggerLocalCleanupAndNotify(reason)
            }
            return
        }
        scheduleReconnect()
    }

    private fun scheduleReconnect() {
        if (teardownGuard.get() || !sessionStore.state.value.connected) {
            return
        }
        if (!reconnectingGuard.compareAndSet(false, true)) {
            return
        }
        sessionStore.updateLiveStreamStatus("🔄 mTLS 1.3 Otomatik Yeniden Bağlanıyor ($sessionHost:$sessionPort)...")
        reconnectJob?.cancel()
        reconnectJob = scope.launch {
            if (isActive && !teardownGuard.get() && sessionStore.state.value.connected) {
                if (sessionStore.isExpired(System.currentTimeMillis())) {
                    reconnectingGuard.set(false)
                    sendNuclearTeardownAndClose("ANDROID_TTL_EXPIRED")
                    return@launch
                }
                val idx = reconnectAttempt.getAndIncrement().coerceAtMost(RECONNECT_BACKOFF_MS.lastIndex)
                delay(RECONNECT_BACKOFF_MS[idx])
                if (teardownGuard.get() || !sessionStore.state.value.connected) {
                    reconnectingGuard.set(false)
                    return@launch
                }
                val client = okHttpClient
                val token = sessionStore.readBearerToken()
                if (client == null || token.isNullOrBlank()) {
                    reconnectingGuard.set(false)
                    triggerLocalCleanupAndNotify("MISSING_RECONNECT_MATERIAL")
                    return@launch
                }
                runCatching { activeWebSocket?.cancel() }
                reconnectingGuard.set(false)
                openAuthenticatedWebSocket(client, sessionHost, sessionPort, token)
                return@launch
            }
            reconnectingGuard.set(false)
        }
    }

    private fun handleIncomingEnvelope(webSocket: WebSocket, rawText: String) {
        val hmacKey = sessionStore.copyHmacKey() ?: run {
            triggerLocalCleanupAndNotify("MISSING_HMAC_KEY")
            return
        }
        try {
            val env = SignedEnvelopeModel.fromJsonString(rawText)
            when (cryptoEngine.verifyEnvelopeDetailed(hmacKey, env)) {
                PairingCryptoEngine.EnvelopeVerificationResult.INVALID_OR_TAMPERED -> {
                    sendNuclearTeardownAndClose("ENVELOPE_VERIFICATION_FAILED")
                    return
                }
                PairingCryptoEngine.EnvelopeVerificationResult.DUPLICATE_ALREADY_PROCESSED -> {
                    if (env.type == "TASK_COMPLETED") {
                        val ackPayload = JSONObject().put("ackedEventId", env.eventId).toString()
                        val ackEnv = cryptoEngine.signEnvelope(hmacKey, "TASK_ACK", ackPayload)
                        webSocket.send(ackEnv.toJsonString())
                    }
                    return
                }
                PairingCryptoEngine.EnvelopeVerificationResult.ACCEPTED_NEW -> Unit
            }

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

    private fun startSessionTtlAndHeartbeatWatchdog() {
        watchdogJob?.cancel()
        watchdogJob = scope.launch {
            while (isActive && sessionStore.state.value.connected && !teardownGuard.get()) {
                delay(HEARTBEAT_INTERVAL_MS)
                val now = System.currentTimeMillis()
                if (sessionStore.isExpired(now)) {
                    sendNuclearTeardownAndClose("ANDROID_TTL_EXPIRED")
                    return@launch
                }
                val ws = activeWebSocket ?: continue
                val hmacKey = sessionStore.copyHmacKey() ?: continue
                try {
                    val hb = cryptoEngine.signEnvelope(hmacKey, "HEARTBEAT", "{}")
                    ws.send(hb.toJsonString())
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
        reconnectJob?.cancel()
        reconnectJob = null

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
        reconnectJob?.cancel()
        reconnectJob = null
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
        scope.cancel()
        cryptoEngine.clearReplayCache()
        hardwareKeyManager.wipeAllKeys()
        sessionStore.wipeEverything()
        onNuclearTeardown(reason)
    }
}
