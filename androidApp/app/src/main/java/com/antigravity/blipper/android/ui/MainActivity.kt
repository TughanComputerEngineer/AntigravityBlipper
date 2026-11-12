package com.antigravity.blipper.android.ui

import android.Manifest
import android.os.Build
import android.os.Bundle
import androidx.activity.ComponentActivity
import androidx.activity.compose.setContent
import androidx.activity.result.contract.ActivityResultContracts
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.darkColorScheme
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.setValue
import androidx.compose.ui.graphics.Color
import com.antigravity.blipper.android.alert.AndroidSystemBurstDispatcher

class MainActivity : ComponentActivity() {

    private var readinessState by mutableStateOf(
        SamsungReadinessStatus(
            notificationsGranted = false,
            batteryUnrestricted = false,
            fullScreenWakeAllowed = false
        )
    )

    private val notificationPermissionLauncher = registerForActivityResult(
        ActivityResultContracts.RequestPermission()
    ) {
        refreshPermissions()
    }

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        AndroidSystemBurstDispatcher.ensureAlarmChannel(applicationContext)
        refreshPermissions()

        setContent {
            MaterialTheme(
                colorScheme = darkColorScheme(
                    background = Color(0xFF070C12),
                    surface = Color(0xFF0F172A),
                    primary = Color(0xFF10B981)
                )
            ) {
                BlipperMainScreen(
                    readinessStatus = readinessState,
                    onRequestPostNotifications = {
                        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
                            notificationPermissionLauncher.launch(Manifest.permission.POST_NOTIFICATIONS)
                        } else {
                            refreshPermissions()
                        }
                    },
                    onRequestBatteryUnrestricted = {
                        PermissionHelper.openBatteryUnrestrictedSettings(this)
                    },
                    onRequestFullScreenWake = {
                        PermissionHelper.openFullScreenIntentSettings(this)
                    }
                )
            }
        }
    }

    override fun onResume() {
        super.onResume()
        refreshPermissions()
    }

    private fun refreshPermissions() {
        readinessState = PermissionHelper.inspectStatus(this)
    }
}
