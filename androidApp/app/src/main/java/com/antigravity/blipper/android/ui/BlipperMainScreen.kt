package com.antigravity.blipper.android.ui

import androidx.compose.foundation.background
import androidx.compose.foundation.border
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.foundation.text.KeyboardOptions
import androidx.compose.foundation.verticalScroll
import androidx.compose.material3.Button
import androidx.compose.material3.ButtonDefaults
import androidx.compose.material3.Card
import androidx.compose.material3.CardDefaults
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Surface
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.collectAsState
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableLongStateOf
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.runtime.saveable.rememberSaveable
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.input.KeyboardType
import androidx.compose.ui.text.input.PasswordVisualTransformation
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import com.antigravity.blipper.android.alert.AlertBurstEngine
import com.antigravity.blipper.android.alert.AndroidSystemBurstDispatcher
import com.antigravity.blipper.android.crypto.BlipperAppGraph
import com.antigravity.blipper.android.network.LanDiscoveryClient
import com.antigravity.blipper.android.service.BlipperConnectionService
import kotlinx.coroutines.delay
import kotlinx.coroutines.launch
import java.util.UUID

@Composable
fun BlipperMainScreen(
    readinessStatus: SamsungReadinessStatus,
    onRequestPostNotifications: () -> Unit,
    onRequestBatteryUnrestricted: () -> Unit,
    onRequestFullScreenWake: () -> Unit
) {
    val context = LocalContext.current
    val scope = rememberCoroutineScope()
    val uiState by BlipperAppGraph.sessionStore.state.collectAsState()

    var hostIp by rememberSaveable { mutableStateOf("") }
    var tlsPortText by rememberSaveable { mutableStateOf("58443") }
    var serverCertSha256 by rememberSaveable { mutableStateOf("") }
    var pinCode by remember { mutableStateOf("") }
    var discoveryStatus by remember { mutableStateOf("Gizli Mod: Yalnızca 'Masaüstü Ara' dediğinizde tek paket sorulur.") }
    var isDiscovering by remember { mutableStateOf(false) }
    var nowMs by remember { mutableLongStateOf(System.currentTimeMillis()) }

    LaunchedEffect(uiState.connected, uiState.sessionExpiresAtMs) {
        while (uiState.connected) {
            nowMs = System.currentTimeMillis()
            delay(1_000L)
        }
    }

    val discoveryClient = remember { LanDiscoveryClient() }

    Surface(
        modifier = Modifier.fillMaxSize(),
        color = Color(0xFF070C12)
    ) {
        Column(
            modifier = Modifier
                .fillMaxSize()
                .verticalScroll(rememberScrollState())
                .padding(horizontal = 16.dp, vertical = 20.dp),
            verticalArrangement = Arrangement.spacedBy(16.dp)
        ) {
            // Header & Live Security State
            Box(
                modifier = Modifier
                    .fillMaxWidth()
                    .background(
                        if (uiState.connected) Color(0xFF062E22) else Color(0xFF111927),
                        RoundedCornerShape(18.dp)
                    )
                    .border(
                        1.5.dp,
                        if (uiState.connected) Color(0xFF10B981) else Color(0xFF334155),
                        RoundedCornerShape(18.dp)
                    )
                    .padding(18.dp)
            ) {
                Column(verticalArrangement = Arrangement.spacedBy(6.dp)) {
                    Text(
                        text = "⚡ ANTIGRAVITY BLIPPER",
                        color = Color(0xFF34D399),
                        fontSize = 19.sp,
                        fontWeight = FontWeight.ExtraBold
                    )
                    Text(
                        text = uiState.statusMessage,
                        color = Color.White,
                        fontSize = 14.sp,
                        fontWeight = FontWeight.SemiBold
                    )
                    Text(
                        text = "Sıfır Dinleyen Port (0 Inbound Socket) • TLS 1.3 + AndroidKeyStore P-256",
                        color = Color(0xFF94A3B8),
                        fontSize = 12.sp
                    )
                    if (uiState.connected && uiState.sessionExpiresAtMs > 0L) {
                        val ttlLabel = if (uiState.sessionExpiresAtMs == Long.MAX_VALUE) {
                            "Yetki Süresi: Sınırsız (Bağlantı kesilene kadar)"
                        } else {
                            val remainSec = ((uiState.sessionExpiresAtMs - nowMs).coerceAtLeast(0L)) / 1000L
                            val hrs = remainSec / 3600L
                            val mins = (remainSec % 3600L) / 60L
                            val secs = remainSec % 60L
                            "Kalan Oturum İzni: %02d:%02d:%02d".format(hrs, mins, secs)
                        }
                        Text(
                            text = ttlLabel,
                            color = Color(0xFF6EE7B7),
                            fontSize = 13.sp,
                            fontWeight = FontWeight.Bold
                        )
                    }
                    if (uiState.lastCompletedBanner.isNotBlank()) {
                        Spacer(modifier = Modifier.height(4.dp))
                        Text(
                            text = "Son Görev: ${uiState.lastCompletedBanner}",
                            color = Color(0xFFFDE68A),
                            fontSize = 12.sp
                        )
                    }
                }
            }

            // Samsung 3-Permission Readiness Card
            Card(
                colors = CardDefaults.cardColors(containerColor = Color(0xFF0F172A)),
                shape = RoundedCornerShape(16.dp),
                modifier = Modifier.fillMaxWidth()
            ) {
                Column(
                    modifier = Modifier.padding(16.dp),
                    verticalArrangement = Arrangement.spacedBy(10.dp)
                ) {
                    Text(
                        text = "🛡️ Samsung Kesintisiz Bildirim & Ekran Uyandırma Zırhı",
                        color = Color.White,
                        fontSize = 15.sp,
                        fontWeight = FontWeight.Bold
                    )

                    PermissionRow(
                        label = "1. Anlık Alarm Bildirim İzni",
                        granted = readinessStatus.notificationsGranted,
                        actionText = "İzin Ver",
                        onClick = onRequestPostNotifications
                    )
                    PermissionRow(
                        label = "2. Pil Kısıtlamasız (Doze Muafiyeti)",
                        granted = readinessStatus.batteryUnrestricted,
                        actionText = "Muaf Tut",
                        onClick = onRequestBatteryUnrestricted
                    )
                    PermissionRow(
                        label = "3. Kilitli Ekranı Açma (Full-Screen Alarm)",
                        granted = readinessStatus.fullScreenWakeAllowed,
                        actionText = "Ayarları Aç",
                        onClick = onRequestFullScreenWake
                    )

                    // Burst count selector (minimum 5 enforced)
                    Row(
                        modifier = Modifier.fillMaxWidth(),
                        verticalAlignment = Alignment.CenterVertically,
                        horizontalArrangement = Arrangement.SpaceBetween
                    ) {
                        Text(
                            text = "Üst Üste Bildirim Sayısı (Min 5):",
                            color = Color(0xFFCBD5E1),
                            fontSize = 13.sp
                        )
                        Row(verticalAlignment = Alignment.CenterVertically) {
                            OutlinedButton(
                                onClick = {
                                    BlipperAppGraph.sessionStore.setBurstCount(uiState.burstNotificationCount - 1)
                                }
                            ) { Text("-") }
                            Spacer(modifier = Modifier.width(10.dp))
                            Text(
                                text = "${uiState.burstNotificationCount}x",
                                color = Color(0xFF34D399),
                                fontSize = 16.sp,
                                fontWeight = FontWeight.ExtraBold
                            )
                            Spacer(modifier = Modifier.width(10.dp))
                            OutlinedButton(
                                onClick = {
                                    BlipperAppGraph.sessionStore.setBurstCount(uiState.burstNotificationCount + 1)
                                }
                            ) { Text("+") }
                        }
                    }

                    OutlinedButton(
                        onClick = {
                            scope.launch {
                                val engine = AlertBurstEngine(
                                    AndroidSystemBurstDispatcher(context.applicationContext),
                                    delayMs = 900L
                                )
                                engine.triggerTaskCompletedBurst(
                                    eventId = "selftest-${UUID.randomUUID()}",
                                    conversationTitle = "Samsung Uyanma Testi",
                                    taskSummary = "5x ardışık bildirim ve ekran uyandırma doğrulandı!",
                                    count = uiState.burstNotificationCount
                                )
                            }
                        },
                        modifier = Modifier.fillMaxWidth()
                    ) {
                        Text("🔔 Yerel ${uiState.burstNotificationCount}x Bildirim & Ekran Uyandırma Testi")
                    }
                }
            }

            // Pairing Card (when disconnected)
            if (!uiState.connected) {
                Card(
                    colors = CardDefaults.cardColors(containerColor = Color(0xFF0F172A)),
                    shape = RoundedCornerShape(16.dp),
                    modifier = Modifier.fillMaxWidth()
                ) {
                    Column(
                        modifier = Modifier.padding(16.dp),
                        verticalArrangement = Arrangement.spacedBy(12.dp)
                    ) {
                        Text(
                            text = "🔐 Masaüstü Eşleştirme (60sn Pencere + 6 Haneli Kod)",
                            color = Color.White,
                            fontSize = 15.sp,
                            fontWeight = FontWeight.Bold
                        )

                        Button(
                            onClick = {
                                isDiscovering = true
                                discoveryStatus = "Aynı Wi-Fi üzerinde açık eşleştirme penceresi aranıyor..."
                                scope.launch {
                                    val found = discoveryClient.discoverDesktop()
                                    isDiscovering = false
                                    if (found != null) {
                                        hostIp = found.hostIp
                                        tlsPortText = found.tlsPort.toString()
                                        serverCertSha256 = found.serverCertSha256Hex
                                        discoveryStatus = "✅ Masaüstü bulundu: ${found.hostIp}:${found.tlsPort} (Sertifika sabitlendi)"
                                    } else {
                                        discoveryStatus = "⚠️ Masaüstü bulunamadı. Bilgisayarda '60sn Eşleştirme Başlat' açık olmalı."
                                    }
                                }
                            },
                            enabled = !isDiscovering && !uiState.connecting,
                            modifier = Modifier.fillMaxWidth(),
                            colors = ButtonDefaults.buttonColors(containerColor = Color(0xFF1D4ED8))
                        ) {
                            Text(
                                text = if (isDiscovering) "📡 Aranıyor..." else "📡 Masaüstü Ara (60sn Gizli Keşif)",
                                fontWeight = FontWeight.Bold
                            )
                        }

                        Text(
                            text = discoveryStatus,
                            color = Color(0xFF94A3B8),
                            fontSize = 12.sp
                        )

                        Row(
                            modifier = Modifier.fillMaxWidth(),
                            horizontalArrangement = Arrangement.spacedBy(8.dp)
                        ) {
                            OutlinedTextField(
                                value = hostIp,
                                onValueChange = { hostIp = it },
                                label = { Text("Masaüstü IP") },
                                singleLine = true,
                                modifier = Modifier.weight(0.68f)
                            )
                            OutlinedTextField(
                                value = tlsPortText,
                                onValueChange = { tlsPortText = it.filter(Char::isDigit) },
                                label = { Text("Port") },
                                singleLine = true,
                                keyboardOptions = KeyboardOptions(keyboardType = KeyboardType.Number),
                                modifier = Modifier.weight(0.32f)
                            )
                        }

                        OutlinedTextField(
                            value = serverCertSha256,
                            onValueChange = { serverCertSha256 = it.trim() },
                            label = { Text("Sunucu TLS Sertifika SHA-256 Parmak İzi (64 Hex)") },
                            textStyle = androidx.compose.ui.text.TextStyle(
                                fontFamily = FontFamily.Monospace,
                                fontSize = 12.sp
                            ),
                            modifier = Modifier.fillMaxWidth()
                        )

                        OutlinedTextField(
                            value = pinCode,
                            onValueChange = { pinCode = it.filter(Char::isDigit).take(12) },
                            label = { Text("Masaüstü Eşleştirme Kodu (En az 6 Hane)") },
                            singleLine = true,
                            visualTransformation = PasswordVisualTransformation(),
                            keyboardOptions = KeyboardOptions(keyboardType = KeyboardType.NumberPassword),
                            modifier = Modifier.fillMaxWidth()
                        )

                        val canConnect = hostIp.isNotBlank() &&
                            (tlsPortText.toIntOrNull() ?: 0) in 1..65535 &&
                            serverCertSha256.trim().length == 64 &&
                            pinCode.length >= 6 &&
                            !uiState.connecting

                        Button(
                            onClick = {
                                val cleanPin = pinCode
                                pinCode = ""
                                BlipperConnectionService.startPairingSession(
                                    context = context,
                                    host = hostIp.trim(),
                                    port = tlsPortText.toIntOrNull() ?: 58443,
                                    serverCertSha256Hex = serverCertSha256.trim(),
                                    pin = cleanPin
                                )
                            },
                            enabled = canConnect,
                            modifier = Modifier
                                .fillMaxWidth()
                                .height(56.dp),
                            shape = RoundedCornerShape(14.dp),
                            colors = ButtonDefaults.buttonColors(
                                containerColor = Color(0xFF10B981),
                                contentColor = Color(0xFF042F2E)
                            )
                        ) {
                            Text(
                                text = if (uiState.connecting) "🔐 ŞİFRELİ BAĞLANIYOR..." else "🔐 mTLS 1.3 İLE EŞLEŞ VE BAĞLAN",
                                fontSize = 15.sp,
                                fontWeight = FontWeight.ExtraBold
                            )
                        }
                    }
                }
            }

            // Giant Mutual Scorched-Earth Kill Switch Button (Always available!)
            Button(
                onClick = {
                    pinCode = ""
                    serverCertSha256 = ""
                    BlipperConnectionService.requestNuclearDisconnect(
                        context = context,
                        reason = "ANDROID_KILL_SWITCH_BUTTON"
                    )
                },
                modifier = Modifier
                    .fillMaxWidth()
                    .height(68.dp),
                shape = RoundedCornerShape(16.dp),
                colors = ButtonDefaults.buttonColors(
                    containerColor = Color(0xFFDC2626),
                    contentColor = Color.White
                )
            ) {
                Text(
                    text = "💣 BAĞLANTIYI KES VE HER ŞEYİ SİL",
                    fontSize = 16.sp,
                    fontWeight = FontWeight.ExtraBold
                )
            }
        }
    }
}

@Composable
private fun PermissionRow(
    label: String,
    granted: Boolean,
    actionText: String,
    onClick: () -> Unit
) {
    Row(
        modifier = Modifier.fillMaxWidth(),
        verticalAlignment = Alignment.CenterVertically,
        horizontalArrangement = Arrangement.SpaceBetween
    ) {
        Text(
            text = if (granted) "✅ $label" else "⚠️ $label",
            color = if (granted) Color(0xFF6EE7B7) else Color(0xFFFCD34D),
            fontSize = 13.sp,
            modifier = Modifier.weight(1f)
        )
        if (!granted) {
            Spacer(modifier = Modifier.width(8.dp))
            OutlinedButton(onClick = onClick) {
                Text(actionText, fontSize = 12.sp)
            }
        }
    }
}
