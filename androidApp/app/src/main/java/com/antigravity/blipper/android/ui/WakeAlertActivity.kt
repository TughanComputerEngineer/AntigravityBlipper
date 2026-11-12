package com.antigravity.blipper.android.ui

import android.content.Context
import android.content.Intent
import android.media.AudioManager
import android.media.ToneGenerator
import android.os.Bundle
import android.os.VibrationEffect
import android.os.Vibrator
import android.view.WindowManager
import androidx.activity.ComponentActivity
import androidx.activity.compose.setContent
import androidx.compose.foundation.background
import androidx.compose.foundation.border
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material3.Button
import androidx.compose.material3.ButtonDefaults
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Surface
import androidx.compose.material3.Text
import androidx.compose.material3.darkColorScheme
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.style.TextAlign
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import com.antigravity.blipper.android.alert.AndroidSystemBurstDispatcher

class WakeAlertActivity : ComponentActivity() {

    companion object {
        private const val EXTRA_EVENT_ID = "extra_event_id"
        private const val EXTRA_CONVERSATION_TITLE = "extra_conversation_title"
        private const val EXTRA_TASK_SUMMARY = "extra_task_summary"

        fun createLaunchIntent(
            context: Context,
            eventId: String,
            conversationTitle: String,
            taskSummary: String
        ): Intent = Intent(context, WakeAlertActivity::class.java).apply {
            flags = Intent.FLAG_ACTIVITY_NEW_TASK or
                Intent.FLAG_ACTIVITY_SINGLE_TOP or
                Intent.FLAG_ACTIVITY_CLEAR_TOP
            putExtra(EXTRA_EVENT_ID, eventId)
            putExtra(EXTRA_CONVERSATION_TITLE, conversationTitle)
            putExtra(EXTRA_TASK_SUMMARY, taskSummary)
        }
    }

    private var conversationTitleState by mutableStateOf("Aktif Sohbet")
    private var taskSummaryState by mutableStateOf("Görev tamamlandı")

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        enableWakeLockScreenFlags()
        applyIntentPayload(intent)
        emitImmediateAttentionPulse()

        setContent {
            MaterialTheme(
                colorScheme = darkColorScheme(
                    background = Color(0xFF060B10),
                    surface = Color(0xFF0D1722),
                    primary = Color(0xFF10B981)
                )
            ) {
                Surface(
                    modifier = Modifier.fillMaxSize(),
                    color = Color(0xFF060B10)
                ) {
                    Column(
                        modifier = Modifier
                            .fillMaxSize()
                            .padding(24.dp),
                        verticalArrangement = Arrangement.Center,
                        horizontalAlignment = Alignment.CenterHorizontally
                    ) {
                        Box(
                            modifier = Modifier
                                .background(Color(0xFF064E3B), RoundedCornerShape(999.dp))
                                .border(1.5.dp, Color(0xFF34D399), RoundedCornerShape(999.dp))
                                .padding(horizontal = 20.dp, vertical = 10.dp)
                        ) {
                            Text(
                                text = "⚡ ANTIGRAVITY GÖREV TAMAMLANDI",
                                color = Color(0xFFA7F3D0),
                                fontSize = 15.sp,
                                fontWeight = FontWeight.ExtraBold
                            )
                        }

                        Spacer(modifier = Modifier.height(24.dp))

                        Box(
                            modifier = Modifier
                                .fillMaxWidth()
                                .background(Color(0xFF0F1D2B), RoundedCornerShape(20.dp))
                                .border(2.dp, Color(0xFF10B981), RoundedCornerShape(20.dp))
                                .padding(24.dp)
                        ) {
                            Column(horizontalAlignment = Alignment.CenterHorizontally) {
                                Text(
                                    text = "ANTIGRAVITY: $conversationTitleState: $taskSummaryState",
                                    color = Color.White,
                                    fontSize = 22.sp,
                                    lineHeight = 30.sp,
                                    fontWeight = FontWeight.Bold,
                                    textAlign = TextAlign.Center
                                )
                                Spacer(modifier = Modifier.height(16.dp))
                                Text(
                                    text = "Sohbet: $conversationTitleState",
                                    color = Color(0xFF6EE7B7),
                                    fontSize = 15.sp,
                                    fontWeight = FontWeight.SemiBold,
                                    textAlign = TextAlign.Center
                                )
                            }
                        }

                        Spacer(modifier = Modifier.height(32.dp))

                        Button(
                            onClick = {
                                AndroidSystemBurstDispatcher.dismissActiveBurstNotifications(applicationContext)
                                finish()
                            },
                            modifier = Modifier
                                .fillMaxWidth()
                                .height(68.dp),
                            shape = RoundedCornerShape(16.dp),
                            colors = ButtonDefaults.buttonColors(
                                containerColor = Color(0xFF10B981),
                                contentColor = Color(0xFF042F2E)
                            )
                        ) {
                            Text(
                                text = "✅ GÖRDÜM / BİLDİRİMLERİ SUSTUR",
                                fontSize = 18.sp,
                                fontWeight = FontWeight.ExtraBold
                            )
                        }
                    }
                }
            }
        }
    }

    override fun onNewIntent(intent: Intent) {
        super.onNewIntent(intent)
        setIntent(intent)
        enableWakeLockScreenFlags()
        applyIntentPayload(intent)
        emitImmediateAttentionPulse()
    }

    private fun enableWakeLockScreenFlags() {
        setShowWhenLocked(true)
        setTurnScreenOn(true)
        window.addFlags(WindowManager.LayoutParams.FLAG_KEEP_SCREEN_ON)
    }

    private fun applyIntentPayload(incoming: Intent?) {
        conversationTitleState = incoming?.getStringExtra(EXTRA_CONVERSATION_TITLE)
            ?.takeIf { it.isNotBlank() } ?: "Aktif Sohbet"
        taskSummaryState = incoming?.getStringExtra(EXTRA_TASK_SUMMARY)
            ?.takeIf { it.isNotBlank() } ?: "Görev tamamlandı"
    }

    @Suppress("DEPRECATION")
    private fun emitImmediateAttentionPulse() {
        runCatching {
            val vibrator = getSystemService(Context.VIBRATOR_SERVICE) as? Vibrator
            vibrator?.vibrate(
                VibrationEffect.createWaveform(longArrayOf(0L, 400L, 150L, 500L), -1)
            )
        }
        runCatching {
            val tone = ToneGenerator(AudioManager.STREAM_ALARM, 95)
            tone.startTone(ToneGenerator.TONE_CDMA_ALERT_CALL_GUARD, 450)
            window.decorView.postDelayed({ runCatching { tone.release() } }, 600L)
        }
    }
}
