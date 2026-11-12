package com.antigravity.blipper.android.service

import android.app.Notification
import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.PendingIntent
import android.app.Service
import android.content.Context
import android.content.Intent
import android.content.pm.ServiceInfo
import android.net.wifi.WifiManager
import android.os.Build
import android.os.IBinder
import androidx.core.app.NotificationCompat
import androidx.core.content.ContextCompat
import com.antigravity.blipper.android.alert.AlertBurstEngine
import com.antigravity.blipper.android.alert.AndroidSystemBurstDispatcher
import com.antigravity.blipper.android.crypto.BlipperAppGraph
import com.antigravity.blipper.android.network.BlipperSecureWsClient
import com.antigravity.blipper.android.ui.MainActivity
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.cancel
import kotlinx.coroutines.launch
import java.util.concurrent.atomic.AtomicBoolean

class BlipperConnectionService : Service() {

    companion object {
        const val ACTION_PAIR_AND_CONNECT = "com.antigravity.blipper.android.action.PAIR_AND_CONNECT"
        const val ACTION_NUCLEAR_DISCONNECT = "com.antigravity.blipper.android.action.NUCLEAR_DISCONNECT"

        private const val FGS_CHANNEL_ID = "antigravity_blipper_fgs_v1"
        private const val FGS_NOTIFICATION_ID = 1001

        fun startPairingSession(
            context: Context,
            host: String,
            port: Int,
            serverCertSha256Hex: String,
            pin: String
        ) {
            BlipperAppGraph.stagePairingRequest(host, port, serverCertSha256Hex, pin)
            val intent = Intent(context, BlipperConnectionService::class.java).apply {
                action = ACTION_PAIR_AND_CONNECT
            }
            ContextCompat.startForegroundService(context, intent)
        }

        fun requestNuclearDisconnect(context: Context, reason: String = "ANDROID_USER_KILL_SWITCH") {
            BlipperAppGraph.triggerGlobalNuclearTeardown(reason)
            runCatching {
                context.stopService(Intent(context, BlipperConnectionService::class.java))
            }
        }
    }

    private val serviceScope = CoroutineScope(SupervisorJob() + Dispatchers.IO)
    private val stoppingGuard = AtomicBoolean(false)
    private var wifiLock: WifiManager.WifiLock? = null

    @Volatile
    private var wsClient: BlipperSecureWsClient? = null
    private lateinit var alertBurstEngine: AlertBurstEngine

    override fun onCreate() {
        super.onCreate()
        ensureFgsChannel()
        alertBurstEngine = AlertBurstEngine(
            dispatcher = AndroidSystemBurstDispatcher(applicationContext),
            delayMs = 900L
        )
        BlipperAppGraph.activeDisconnectHandler = { reason ->
            executeNuclearDisconnectInternal(reason)
        }
    }

    override fun onBind(intent: Intent?): IBinder? = null

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        when (intent?.action) {
            ACTION_NUCLEAR_DISCONNECT -> {
                promoteToForeground("Şifreli oturum imha ediliyor...")
                executeNuclearDisconnectInternal("NOTIFICATION_KILL_SWITCH")
                return START_NOT_STICKY
            }
            ACTION_PAIR_AND_CONNECT -> {
                stoppingGuard.set(false)
                promoteToForeground("Masaüstü ile mTLS 1.3 şifreli eşleşme başlatılıyor...")
                acquireLowLatencyWifiLock()
                val staged = BlipperAppGraph.consumeStagedPairingRequest()
                if (staged == null) {
                    executeNuclearDisconnectInternal("MISSING_STAGED_CREDENTIALS")
                    return START_NOT_STICKY
                }
                startSecureWsSession(
                    host = staged.host,
                    port = staged.port,
                    serverCertSha256Hex = staged.serverCertSha256Hex,
                    pinChars = staged.pinChars
                )
                return START_NOT_STICKY
            }
            else -> {
                promoteToForeground("Oturum kapatılıyor...")
                executeNuclearDisconnectInternal("UNEXPECTED_START")
                return START_NOT_STICKY
            }
        }
    }

    override fun onTaskRemoved(rootIntent: Intent?) {
        // Spec 2C: If Phone app is closed/swiped away, disconnect PC and wipe everything on both sides!
        executeNuclearDisconnectInternal("ANDROID_TASK_REMOVED")
        super.onTaskRemoved(rootIntent)
    }

    override fun onDestroy() {
        if (BlipperAppGraph.activeDisconnectHandler != null) {
            BlipperAppGraph.activeDisconnectHandler = null
        }
        executeNuclearDisconnectInternal("SERVICE_DESTROYED")
        serviceScope.cancel()
        super.onDestroy()
    }

    private fun startSecureWsSession(
        host: String,
        port: Int,
        serverCertSha256Hex: String,
        pinChars: CharArray
    ) {
        wsClient?.sendNuclearTeardownAndClose("SUPERSEDED_BY_NEW_PAIRING")
        val client = BlipperSecureWsClient(
            cryptoEngine = BlipperAppGraph.cryptoEngine,
            hardwareKeyManager = BlipperAppGraph.hardwareKeyManager,
            sessionStore = BlipperAppGraph.sessionStore,
            onTaskCompleted = { eventId, title, summary ->
                val bannerText = "ANTIGRAVITY: $title: $summary"
                BlipperAppGraph.sessionStore.recordCompletedAlert(bannerText)
                val count = BlipperAppGraph.sessionStore.state.value.burstNotificationCount
                serviceScope.launch {
                    alertBurstEngine.triggerTaskCompletedBurst(
                        eventId = eventId,
                        conversationTitle = title,
                        taskSummary = summary,
                        count = count
                    )
                }
            },
            onNuclearTeardown = { reason ->
                stopServiceAfterTeardown(reason)
            }
        )
        wsClient = client

        BlipperAppGraph.sessionStore.setConnecting("🔐 mTLS 1.3 + PBKDF2 kanıtı doğrulanıyor ($host:$port)...")
        val pinString = String(pinChars)
        pinChars.fill('\u0000')

        serviceScope.launch {
            val result = client.pairAndConnect(
                host = host,
                tlsPort = port,
                pinnedServerCertSha256Hex = serverCertSha256Hex,
                pinCode = pinString
            )
            if (result.isSuccess) {
                updateForegroundNotification("🟢 mTLS 1.3 Aktif ($host:$port) — Samsung Anlık Bildirim Köprüsü")
            } else {
                val errMsg = result.exceptionOrNull()?.message ?: "Bağlantı başarısız"
                BlipperAppGraph.sessionStore.wipeEverything("⛔ Eşleştirme Reddedildi: $errMsg")
                stopServiceAfterTeardown("PAIRING_FAILED")
            }
        }
    }

    private fun executeNuclearDisconnectInternal(reason: String) {
        if (!stoppingGuard.compareAndSet(false, true)) {
            return
        }
        val activeClient = wsClient
        wsClient = null
        if (activeClient != null) {
            CoroutineScope(Dispatchers.IO).launch {
                runCatching { activeClient.sendNuclearTeardownAndClose(reason) }
                finishShutdownUiAndService(reason)
            }
        } else {
            BlipperAppGraph.cryptoEngine.clearReplayCache()
            BlipperAppGraph.hardwareKeyManager.wipeAllKeys()
            BlipperAppGraph.sessionStore.wipeEverything()
            finishShutdownUiAndService(reason)
        }
    }

    private fun stopServiceAfterTeardown(reason: String) {
        stoppingGuard.set(true)
        wsClient = null
        finishShutdownUiAndService(reason)
    }

    private fun finishShutdownUiAndService(reason: String) {
        releaseWifiLock()
        if (BlipperAppGraph.sessionStore.state.value.connected) {
            BlipperAppGraph.sessionStore.wipeEverything(
                "🔒 Bağlantı Kapatıldı ($reason) — Tüm Anahtarlar İmha Edildi"
            )
        }
        runCatching { stopForeground(STOP_FOREGROUND_REMOVE) }
        runCatching { stopSelf() }
    }

    @Suppress("DEPRECATION")
    private fun acquireLowLatencyWifiLock() {
        runCatching {
            val wm = applicationContext.getSystemService(Context.WIFI_SERVICE) as WifiManager
            val lock = wifiLock ?: wm.createWifiLock(
                WifiManager.WIFI_MODE_FULL_LOW_LATENCY,
                "AntigravityBlipper:LowLatencyWifiLock"
            ).apply {
                setReferenceCounted(false)
                wifiLock = this
            }
            if (!lock.isHeld) {
                lock.acquire()
            }
        }
    }

    private fun releaseWifiLock() {
        runCatching {
            val lock = wifiLock
            if (lock != null && lock.isHeld) {
                lock.release()
            }
            wifiLock = null
        }
    }

    private fun promoteToForeground(statusText: String) {
        val notification = buildForegroundNotification(statusText)
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.UPSIDE_DOWN_CAKE) {
            startForeground(
                FGS_NOTIFICATION_ID,
                notification,
                ServiceInfo.FOREGROUND_SERVICE_TYPE_SPECIAL_USE
            )
        } else {
            startForeground(FGS_NOTIFICATION_ID, notification)
        }
    }

    private fun updateForegroundNotification(statusText: String) {
        val nm = getSystemService(Context.NOTIFICATION_SERVICE) as NotificationManager
        nm.notify(FGS_NOTIFICATION_ID, buildForegroundNotification(statusText))
    }

    private fun buildForegroundNotification(statusText: String): Notification {
        val openAppIntent = PendingIntent.getActivity(
            this,
            2001,
            Intent(this, MainActivity::class.java).apply {
                flags = Intent.FLAG_ACTIVITY_SINGLE_TOP or Intent.FLAG_ACTIVITY_CLEAR_TOP
            },
            PendingIntent.FLAG_UPDATE_CURRENT or PendingIntent.FLAG_IMMUTABLE
        )

        val killIntent = PendingIntent.getService(
            this,
            2002,
            Intent(this, BlipperConnectionService::class.java).apply {
                action = ACTION_NUCLEAR_DISCONNECT
            },
            PendingIntent.FLAG_UPDATE_CURRENT or PendingIntent.FLAG_IMMUTABLE
        )

        return NotificationCompat.Builder(this, FGS_CHANNEL_ID)
            .setSmallIcon(android.R.drawable.ic_secure)
            .setContentTitle("AntigravityBlipper Güvenli Köprü")
            .setContentText(statusText)
            .setOngoing(true)
            .setOnlyAlertOnce(true)
            .setCategory(NotificationCompat.CATEGORY_SERVICE)
            .setVisibility(NotificationCompat.VISIBILITY_PUBLIC)
            .setContentIntent(openAppIntent)
            .addAction(
                android.R.drawable.ic_delete,
                "Bağlantıyı Kes ve Sil",
                killIntent
            )
            .build()
    }

    private fun ensureFgsChannel() {
        val nm = getSystemService(Context.NOTIFICATION_SERVICE) as NotificationManager
        if (nm.getNotificationChannel(FGS_CHANNEL_ID) != null) {
            return
        }
        val channel = NotificationChannel(
            FGS_CHANNEL_ID,
            "AntigravityBlipper Aktif Oturum Köprüsü",
            NotificationManager.IMPORTANCE_LOW
        ).apply {
            description = "Sadece aktif mTLS 1.3 eşleşmesi süresince Samsung Wi-Fi uykusunu engeller."
            setShowBadge(false)
        }
        nm.createNotificationChannel(channel)
    }
}
