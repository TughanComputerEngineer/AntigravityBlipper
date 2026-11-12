package com.antigravity.blipper.android.network

import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import org.json.JSONObject
import java.net.DatagramPacket
import java.net.DatagramSocket
import java.net.Inet4Address
import java.net.InetAddress
import java.net.NetworkInterface
import java.nio.charset.StandardCharsets

data class DiscoveredDesktop(
    val hostIp: String,
    val tlsPort: Int,
    val serverCertSha256Hex: String
)

class LanDiscoveryClient {

    companion object {
        const val DEFAULT_DISCOVERY_PORT = 58444
        private const val DISCOVERY_MAGIC = "BLIPPER_DISCOVER_V1"
    }

    suspend fun discoverDesktop(
        udpPort: Int = DEFAULT_DISCOVERY_PORT,
        timeoutMs: Int = 2500
    ): DiscoveredDesktop? = withContext(Dispatchers.IO) {
        try {
            // Ephemeral outbound-only UDP socket; closed immediately via use {}
            DatagramSocket().use { socket ->
                socket.broadcast = true
                socket.soTimeout = timeoutMs
                val payload = DISCOVERY_MAGIC.toByteArray(StandardCharsets.UTF_8)

                val targets = linkedSetOf<InetAddress>()
                targets.add(InetAddress.getByName("255.255.255.255"))
                collectSubnetBroadcastAddresses().forEach { targets.add(it) }

                for (addr in targets) {
                    runCatching {
                        socket.send(DatagramPacket(payload, payload.size, addr, udpPort))
                    }
                }

                val buf = ByteArray(512)
                val reply = DatagramPacket(buf, buf.size)
                socket.receive(reply)

                val text = String(reply.data, reply.offset, reply.length, StandardCharsets.UTF_8)
                val json = JSONObject(text)
                if (json.optString("proto") != "blipper-v1") {
                    return@withContext null
                }
                val tlsPort = json.optInt("port", -1)
                val certSha = json.optString("serverCertSha256", "")
                val senderIp = reply.address?.hostAddress ?: return@withContext null
                if (tlsPort <= 0 || certSha.length != 64) {
                    return@withContext null
                }
                DiscoveredDesktop(senderIp, tlsPort, certSha)
            }
        } catch (_: Exception) {
            null
        }
    }

    private fun collectSubnetBroadcastAddresses(): List<InetAddress> {
        val result = mutableListOf<InetAddress>()
        runCatching {
            val interfaces = NetworkInterface.getNetworkInterfaces() ?: return emptyList()
            while (interfaces.hasMoreElements()) {
                val nif = interfaces.nextElement()
                if (!nif.isUp || nif.isLoopback) continue
                for (ia in nif.interfaceAddresses) {
                    val bcast = ia.broadcast
                    if (bcast is Inet4Address) {
                        result.add(bcast)
                    }
                }
            }
        }
        return result
    }
}
