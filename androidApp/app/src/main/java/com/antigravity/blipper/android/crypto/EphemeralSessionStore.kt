package com.antigravity.blipper.android.crypto

import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.flow.update
import java.nio.charset.StandardCharsets
import java.util.Arrays

data class SessionUiState(
    val connected: Boolean = false,
    val connecting: Boolean = false,
    val statusMessage: String = "🔒 Kapalı — Sıfır Kayıtlı Cihaz / Sıfır Açık Port",
    val desktopEndpoint: String = "",
    val sessionExpiresAtMs: Long = 0L,
    val burstNotificationCount: Int = 5,
    val lastCompletedBanner: String = ""
)

class EphemeralSessionStore {

    private val lock = Any()
    private val _state = MutableStateFlow(SessionUiState())
    val state: StateFlow<SessionUiState> = _state.asStateFlow()

    private var bearerTokenUtf8: ByteArray? = null
    private var hmacKeyBytes: ByteArray? = null
    private var pinnedServerSha256: String? = null

    fun setConnecting(message: String) {
        _state.update { it.copy(connecting = true, statusMessage = message) }
    }

    fun updateLiveStreamStatus(message: String) {
        synchronized(lock) {
            if (_state.value.connected) {
                _state.update { it.copy(connecting = false, statusMessage = message) }
            }
        }
    }

    fun setDisconnectedStatus(message: String) {
        _state.update {
            it.copy(
                connected = false,
                connecting = false,
                statusMessage = message,
                desktopEndpoint = "",
                sessionExpiresAtMs = 0L
            )
        }
    }

    fun setBurstCount(count: Int) {
        val clamped = count.coerceIn(5, 10)
        _state.update { it.copy(burstNotificationCount = clamped) }
    }

    fun recordCompletedAlert(bannerText: String) {
        _state.update { it.copy(lastCompletedBanner = bannerText) }
    }

    fun activateSession(
        desktopHost: String,
        desktopPort: Int,
        serverCertSha256Hex: String,
        bearerToken: String,
        hmacKey: ByteArray,
        sessionExpiresAtMs: Long
    ) {
        synchronized(lock) {
            zeroizeSecretsLocked()
            this.bearerTokenUtf8 = bearerToken.toByteArray(StandardCharsets.UTF_8)
            this.hmacKeyBytes = hmacKey.copyOf()
            this.pinnedServerSha256 = serverCertSha256Hex
            _state.update {
                it.copy(
                    connected = true,
                    connecting = false,
                    statusMessage = "🟢 mTLS 1.3 Şifreli Bağlı ($desktopHost:$desktopPort)",
                    desktopEndpoint = "$desktopHost:$desktopPort",
                    sessionExpiresAtMs = sessionExpiresAtMs
                )
            }
        }
    }

    fun copyHmacKey(): ByteArray? = synchronized(lock) {
        hmacKeyBytes?.copyOf()
    }

    fun readBearerToken(): String? = synchronized(lock) {
        bearerTokenUtf8?.let { String(it, StandardCharsets.UTF_8) }
    }

    fun isExpired(nowMs: Long = System.currentTimeMillis()): Boolean = synchronized(lock) {
        val exp = _state.value.sessionExpiresAtMs
        _state.value.connected && exp > 0L && exp != Long.MAX_VALUE && nowMs >= exp
    }

    fun wipeEverything(reasonMessage: String = "🔒 Bağlantı Kesildi — Tüm Şifreli Anahtarlar İmha Edildi"): Boolean {
        synchronized(lock) {
            val hadMaterial = bearerTokenUtf8 != null || hmacKeyBytes != null || _state.value.connected
            zeroizeSecretsLocked()
            _state.update {
                it.copy(
                    connected = false,
                    connecting = false,
                    statusMessage = reasonMessage,
                    desktopEndpoint = "",
                    sessionExpiresAtMs = 0L
                )
            }
            return hadMaterial
        }
    }

    private fun zeroizeSecretsLocked() {
        bearerTokenUtf8?.let { Arrays.fill(it, 0.toByte()) }
        bearerTokenUtf8 = null
        hmacKeyBytes?.let { Arrays.fill(it, 0.toByte()) }
        hmacKeyBytes = null
        pinnedServerSha256 = null
    }
}

data class StagedPairingRequest(
    val host: String,
    val port: Int,
    val serverCertSha256Hex: String,
    val pinChars: CharArray
) {
    fun zeroize() {
        Arrays.fill(pinChars, '\u0000')
    }
}

object BlipperAppGraph {
    private val stagingLock = Any()
    private var stagedRequest: StagedPairingRequest? = null

    @Volatile
    var activeDisconnectHandler: ((String) -> Unit)? = null

    val cryptoEngine = PairingCryptoEngine()
    val hardwareKeyManager = HardwareKeyManager()
    val sessionStore = EphemeralSessionStore()

    fun stagePairingRequest(host: String, port: Int, serverCertSha256Hex: String, pin: String) {
        synchronized(stagingLock) {
            stagedRequest?.zeroize()
            stagedRequest = StagedPairingRequest(
                host = host.trim(),
                port = port,
                serverCertSha256Hex = serverCertSha256Hex.trim(),
                pinChars = pin.trim().toCharArray()
            )
        }
    }

    fun consumeStagedPairingRequest(): StagedPairingRequest? = synchronized(stagingLock) {
        val current = stagedRequest
        stagedRequest = null
        current
    }

    fun clearStagedPairingRequest() = synchronized(stagingLock) {
        stagedRequest?.zeroize()
        stagedRequest = null
    }

    fun triggerGlobalNuclearTeardown(reason: String) {
        clearStagedPairingRequest()
        val handler = activeDisconnectHandler
        if (handler != null) {
            handler.invoke(reason)
        } else {
            cryptoEngine.clearReplayCache()
            hardwareKeyManager.wipeAllKeys()
            sessionStore.wipeEverything()
        }
    }
}
