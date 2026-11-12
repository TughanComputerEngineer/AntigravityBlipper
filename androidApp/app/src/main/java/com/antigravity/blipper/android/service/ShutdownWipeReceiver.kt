package com.antigravity.blipper.android.service

import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent
import com.antigravity.blipper.android.crypto.BlipperAppGraph
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch

class ShutdownWipeReceiver : BroadcastReceiver() {

    override fun onReceive(context: Context, intent: Intent?) {
        if (intent?.action != Intent.ACTION_SHUTDOWN) {
            return
        }
        val pendingResult = goAsync()
        CoroutineScope(Dispatchers.IO).launch {
            try {
                BlipperAppGraph.triggerGlobalNuclearTeardown("ANDROID_DEVICE_SHUTDOWN")
            } finally {
                pendingResult.finish()
            }
        }
    }
}
