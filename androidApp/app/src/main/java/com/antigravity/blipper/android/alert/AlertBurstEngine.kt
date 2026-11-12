package com.antigravity.blipper.android.alert

import android.Manifest
import android.app.Notification
import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.PendingIntent
import android.content.Context
import android.content.pm.PackageManager
import android.media.AudioAttributes
import android.media.RingtoneManager
import android.os.Build
import android.os.PowerManager
import androidx.core.app.NotificationCompat
import androidx.core.content.ContextCompat
import com.antigravity.blipper.android.ui.WakeAlertActivity
import kotlinx.coroutines.delay
import java.util.concurrent.ConcurrentLinkedQueue
import java.util.concurrent.atomic.AtomicInteger

data class BurstNotificationSpec(
    val notificationId: Int,
    val tag: String,
    val sequenceIndex: Int,
    val totalCount: Int,
    val title: String,
    val body: String,
    val conversationTitle: String,
    val taskSummary: String,
    val eventId: String,
    val attachFullScreenIntent: Boolean
)

interface BurstNotificationDispatcher {
    fun acquireBurstWakeLock(timeoutMs: Long)
    fun releaseBurstWakeLock()
    fun launchFullScreenWakeup(eventId: String, conversationTitle: String, taskSummary: String)
    fun postHighPriorityAlarmNotification(spec: BurstNotificationSpec)
}

class AlertBurstEngine(
    private val dispatcher: BurstNotificationDispatcher,
    private val delayMs: Long = 900L
) {
    private val nextNotificationId = AtomicInteger(40_000)

    suspend fun triggerTaskCompletedBurst(
        eventId: String,
        conversationTitle: String,
        taskSummary: String,
        count: Int = 5
    ) {
        val effectiveCount = maxOf(5, count).coerceAtMost(20)
        val cleanTitle = conversationTitle.ifBlank { "Aktif Sohbet" }
        val cleanSummary = taskSummary.ifBlank { "Görev tamamlandı" }

        dispatcher.acquireBurstWakeLock(timeoutMs = 15_000L)
        try {
            dispatcher.launchFullScreenWakeup(eventId, cleanTitle, cleanSummary)
            for (index in 1..effectiveCount) {
                val notifId = nextNotificationId.incrementAndGet()
                val tag = "blipper-burst-$eventId-$index-$notifId"
                val spec = BurstNotificationSpec(
                    notificationId = notifId,
                    tag = tag,
                    sequenceIndex = index,
                    totalCount = effectiveCount,
                    title = "ANTIGRAVITY [$index/$effectiveCount]: $cleanTitle",
                    body = cleanSummary,
                    conversationTitle = cleanTitle,
                    taskSummary = cleanSummary,
                    eventId = eventId,
                    attachFullScreenIntent = (index == 1)
                )
                dispatcher.postHighPriorityAlarmNotification(spec)
                if (index < effectiveCount && delayMs > 0L) {
                    delay(delayMs)
                }
            }
        } finally {
            dispatcher.releaseBurstWakeLock()
        }
    }
}

class AndroidSystemBurstDispatcher(
    context: Context
) : BurstNotificationDispatcher {

    companion object {
        const val ALARM_CHANNEL_ID = "antigravity_blipper_alarm_v1"
        private val activeBurstKeys = ConcurrentLinkedQueue<Pair<String, Int>>()

        fun ensureAlarmChannel(context: Context) {
            val nm = context.getSystemService(Context.NOTIFICATION_SERVICE) as NotificationManager
            if (nm.getNotificationChannel(ALARM_CHANNEL_ID) != null) {
                return
            }
            val alarmUri = RingtoneManager.getDefaultUri(RingtoneManager.TYPE_ALARM)
                ?: RingtoneManager.getDefaultUri(RingtoneManager.TYPE_NOTIFICATION)
            val audioAttrs = AudioAttributes.Builder()
                .setUsage(AudioAttributes.USAGE_ALARM)
                .setContentType(AudioAttributes.CONTENT_TYPE_SONIFICATION)
                .build()

            val channel = NotificationChannel(
                ALARM_CHANNEL_ID,
                "Antigravity Kritik Görev Alarmları (5x)",
                NotificationManager.IMPORTANCE_HIGH
            ).apply {
                description = "Antigravity görev tamamlandığında ekranı uyandırır ve ardışık uyarı verir."
                lockscreenVisibility = Notification.VISIBILITY_PUBLIC
                enableVibration(true)
                vibrationPattern = longArrayOf(0L, 450L, 160L, 450L, 160L, 650L)
                enableLights(true)
                setBypassDnd(true)
                if (alarmUri != null) {
                    setSound(alarmUri, audioAttrs)
                }
            }
            nm.createNotificationChannel(channel)
        }

        fun dismissActiveBurstNotifications(context: Context) {
            val nm = context.getSystemService(Context.NOTIFICATION_SERVICE) as NotificationManager
            while (true) {
                val entry = activeBurstKeys.poll() ?: break
                runCatching { nm.cancel(entry.first, entry.second) }
            }
        }
    }

    private val appContext = context.applicationContext
    private val wakeLockMutex = Any()
    private var burstWakeLock: PowerManager.WakeLock? = null

    init {
        ensureAlarmChannel(appContext)
    }

    override fun acquireBurstWakeLock(timeoutMs: Long) {
        synchronized(wakeLockMutex) {
            val pm = appContext.getSystemService(Context.POWER_SERVICE) as PowerManager
            val lock = burstWakeLock ?: pm.newWakeLock(
                PowerManager.PARTIAL_WAKE_LOCK,
                "AntigravityBlipper:BurstWakeLock"
            ).apply {
                setReferenceCounted(false)
                burstWakeLock = this
            }
            runCatching { lock.acquire(timeoutMs) }
        }
    }

    override fun releaseBurstWakeLock() {
        synchronized(wakeLockMutex) {
            val lock = burstWakeLock
            if (lock != null && lock.isHeld) {
                runCatching { lock.release() }
            }
        }
    }

    override fun launchFullScreenWakeup(
        eventId: String,
        conversationTitle: String,
        taskSummary: String
    ) {
        val wakeIntent = WakeAlertActivity.createLaunchIntent(
            appContext,
            eventId = eventId,
            conversationTitle = conversationTitle,
            taskSummary = taskSummary
        )
        runCatching {
            appContext.startActivity(wakeIntent)
        }
    }

    override fun postHighPriorityAlarmNotification(spec: BurstNotificationSpec) {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
            val granted = ContextCompat.checkSelfPermission(
                appContext,
                Manifest.permission.POST_NOTIFICATIONS
            ) == PackageManager.PERMISSION_GRANTED
            if (!granted) {
                return
            }
        }
        ensureAlarmChannel(appContext)
        val nm = appContext.getSystemService(Context.NOTIFICATION_SERVICE) as NotificationManager

        val wakeIntent = WakeAlertActivity.createLaunchIntent(
            appContext,
            eventId = spec.eventId,
            conversationTitle = spec.conversationTitle,
            taskSummary = spec.taskSummary
        )
        val pendingWakeIntent = PendingIntent.getActivity(
            appContext,
            spec.notificationId,
            wakeIntent,
            PendingIntent.FLAG_UPDATE_CURRENT or PendingIntent.FLAG_IMMUTABLE
        )

        val builder = NotificationCompat.Builder(appContext, ALARM_CHANNEL_ID)
            .setSmallIcon(android.R.drawable.ic_lock_idle_alarm)
            .setContentTitle(spec.title)
            .setContentText(spec.body)
            .setStyle(
                NotificationCompat.BigTextStyle()
                    .bigText("ANTIGRAVITY: ${spec.conversationTitle}: ${spec.taskSummary}")
            )
            .setPriority(NotificationCompat.PRIORITY_MAX)
            .setCategory(NotificationCompat.CATEGORY_ALARM)
            .setVisibility(NotificationCompat.VISIBILITY_PUBLIC)
            .setAutoCancel(true)
            .setDefaults(NotificationCompat.DEFAULT_VIBRATE or NotificationCompat.DEFAULT_LIGHTS)
            .setGroupAlertBehavior(NotificationCompat.GROUP_ALERT_ALL)
            .setContentIntent(pendingWakeIntent)

        if (spec.attachFullScreenIntent) {
            builder.setFullScreenIntent(pendingWakeIntent, true)
        }

        activeBurstKeys.add(spec.tag to spec.notificationId)
        while (activeBurstKeys.size > 100) {
            activeBurstKeys.poll()
        }
        nm.notify(spec.tag, spec.notificationId, builder.build())
    }
}
