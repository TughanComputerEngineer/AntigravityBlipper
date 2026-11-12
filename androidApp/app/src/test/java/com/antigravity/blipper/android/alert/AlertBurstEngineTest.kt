package com.antigravity.blipper.android.alert

import kotlinx.coroutines.ExperimentalCoroutinesApi
import kotlinx.coroutines.test.runTest
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test

@OptIn(ExperimentalCoroutinesApi::class)
class AlertBurstEngineTest {

    private class FakeBurstDispatcher(
        private val throwOnIndex: Int = -1
    ) : BurstNotificationDispatcher {
        var wakeLockAcquired = false
        var wakeLockReleased = false
        var wakeScreenTriggeredFirst = false
        var wakeScreenTitle = ""
        var wakeScreenSummary = ""
        val postedNotifications = mutableListOf<BurstNotificationSpec>()

        override fun acquireBurstWakeLock(timeoutMs: Long) {
            wakeLockAcquired = true
        }

        override fun releaseBurstWakeLock() {
            wakeLockReleased = true
        }

        override fun launchFullScreenWakeup(
            eventId: String,
            conversationTitle: String,
            taskSummary: String
        ) {
            wakeScreenTriggeredFirst = wakeLockAcquired && postedNotifications.isEmpty()
            wakeScreenTitle = conversationTitle
            wakeScreenSummary = taskSummary
        }

        override fun postHighPriorityAlarmNotification(spec: BurstNotificationSpec) {
            if (throwOnIndex > 0 && spec.sequenceIndex == throwOnIndex) {
                throw IllegalStateException("Simulated notification manager failure")
            }
            postedNotifications.add(spec)
        }
    }

    @Test
    fun `triggerTaskCompletedBurst enforces minimum 5 distinct notification IDs and wakes screen first`() = runTest {
        val fakeDispatcher = FakeBurstDispatcher()
        val engine = AlertBurstEngine(fakeDispatcher, delayMs = 900L)

        // Even if caller passes count = 2, spec requires >= 5 sequential notifications!
        engine.triggerTaskCompletedBurst(
            eventId = "evt-1",
            conversationTitle = "Carbon Merhaba Greeting",
            taskSummary = "Modül tamamlandı",
            count = 2
        )

        assertTrue(fakeDispatcher.wakeLockAcquired)
        assertTrue(fakeDispatcher.wakeScreenTriggeredFirst)
        assertEquals("Carbon Merhaba Greeting", fakeDispatcher.wakeScreenTitle)
        assertEquals("Modül tamamlandı", fakeDispatcher.wakeScreenSummary)
        assertEquals(5, fakeDispatcher.postedNotifications.size)
        assertEquals(5, fakeDispatcher.postedNotifications.map { it.notificationId }.toSet().size)
        assertEquals(5, fakeDispatcher.postedNotifications.map { it.tag }.toSet().size)
        assertEquals(
            "ANTIGRAVITY [1/5]: Carbon Merhaba Greeting",
            fakeDispatcher.postedNotifications.first().title
        )
        assertTrue(fakeDispatcher.postedNotifications.first().attachFullScreenIntent)
        assertEquals(
            "ANTIGRAVITY [5/5]: Carbon Merhaba Greeting",
            fakeDispatcher.postedNotifications.last().title
        )
        assertTrue(fakeDispatcher.wakeLockReleased)
    }

    @Test
    fun `triggerTaskCompletedBurst honors higher count and always releases wakeLock on failure`() = runTest {
        val fakeDispatcher = FakeBurstDispatcher()
        val engine = AlertBurstEngine(fakeDispatcher, delayMs = 900L)

        engine.triggerTaskCompletedBurst(
            eventId = "evt-7",
            conversationTitle = "Güvenlik Katmanı",
            taskSummary = "Testler geçti",
            count = 7
        )
        assertEquals(7, fakeDispatcher.postedNotifications.size)
        assertEquals(7, fakeDispatcher.postedNotifications.map { it.notificationId }.toSet().size)
        assertTrue(fakeDispatcher.wakeLockReleased)

        val failingDispatcher = FakeBurstDispatcher(throwOnIndex = 3)
        val failingEngine = AlertBurstEngine(failingDispatcher, delayMs = 900L)
        val failed = runCatching {
            failingEngine.triggerTaskCompletedBurst(
                eventId = "evt-fail",
                conversationTitle = "Hata Testi",
                taskSummary = "WakeLock serbest kalmalı",
                count = 5
            )
        }.isFailure
        assertTrue(failed)
        assertTrue(failingDispatcher.wakeLockAcquired)
        assertTrue(failingDispatcher.wakeLockReleased)
    }
}
