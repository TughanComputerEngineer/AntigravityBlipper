package com.antigravity.blipper.android.ui

import android.Manifest
import android.app.NotificationManager
import android.content.Context
import android.content.Intent
import android.content.pm.PackageManager
import android.net.Uri
import android.os.Build
import android.os.PowerManager
import android.provider.Settings
import androidx.core.content.ContextCompat

data class SamsungReadinessStatus(
    val notificationsGranted: Boolean,
    val batteryUnrestricted: Boolean,
    val fullScreenWakeAllowed: Boolean
) {
    val allReady: Boolean
        get() = notificationsGranted && batteryUnrestricted && fullScreenWakeAllowed
}

object PermissionHelper {

    fun inspectStatus(context: Context): SamsungReadinessStatus {
        return SamsungReadinessStatus(
            notificationsGranted = hasNotificationPermission(context),
            batteryUnrestricted = isIgnoringBatteryOptimizations(context),
            fullScreenWakeAllowed = canUseFullScreenIntent(context)
        )
    }

    fun hasNotificationPermission(context: Context): Boolean {
        return if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
            ContextCompat.checkSelfPermission(
                context,
                Manifest.permission.POST_NOTIFICATIONS
            ) == PackageManager.PERMISSION_GRANTED
        } else {
            true
        }
    }

    fun isIgnoringBatteryOptimizations(context: Context): Boolean {
        val pm = context.getSystemService(Context.POWER_SERVICE) as PowerManager
        return pm.isIgnoringBatteryOptimizations(context.packageName)
    }

    fun canUseFullScreenIntent(context: Context): Boolean {
        return if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.UPSIDE_DOWN_CAKE) {
            val nm = context.getSystemService(Context.NOTIFICATION_SERVICE) as NotificationManager
            nm.canUseFullScreenIntent()
        } else {
            true
        }
    }

    fun openBatteryUnrestrictedSettings(context: Context) {
        val pkgUri = Uri.parse("package:${context.packageName}")
        val directIntent = Intent(
            Settings.ACTION_REQUEST_IGNORE_BATTERY_OPTIMIZATIONS,
            pkgUri
        ).addFlags(Intent.FLAG_ACTIVITY_NEW_TASK)

        val fallbackIntent = Intent(Settings.ACTION_IGNORE_BATTERY_OPTIMIZATION_SETTINGS)
            .addFlags(Intent.FLAG_ACTIVITY_NEW_TASK)

        runCatching { context.startActivity(directIntent) }
            .onFailure { runCatching { context.startActivity(fallbackIntent) } }
    }

    fun openFullScreenIntentSettings(context: Context) {
        val pkgUri = Uri.parse("package:${context.packageName}")
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.UPSIDE_DOWN_CAKE) {
            val fsiIntent = Intent(
                Settings.ACTION_MANAGE_APP_USE_FULL_SCREEN_INTENT,
                pkgUri
            ).addFlags(Intent.FLAG_ACTIVITY_NEW_TASK)
            if (runCatching { context.startActivity(fsiIntent) }.isSuccess) {
                return
            }
        }
        val appDetails = Intent(Settings.ACTION_APPLICATION_DETAILS_SETTINGS, pkgUri)
            .addFlags(Intent.FLAG_ACTIVITY_NEW_TASK)
        runCatching { context.startActivity(appDetails) }
    }
}
