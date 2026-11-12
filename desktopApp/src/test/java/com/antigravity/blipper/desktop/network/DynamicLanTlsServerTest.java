package com.antigravity.blipper.desktop.network;

import com.antigravity.blipper.desktop.crypto.EphemeralKeyMaterialService;
import com.antigravity.blipper.desktop.crypto.SignedEnvelope;
import com.antigravity.blipper.desktop.security.SessionStateRegistry;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLSocket;
import javax.net.ssl.TrustManager;
import javax.net.ssl.X509TrustManager;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.ConnectException;
import java.net.DatagramPacket;
import java.net.DatagramSocket;
import java.net.InetAddress;
import java.net.Socket;
import java.nio.charset.StandardCharsets;
import java.security.KeyStore;
import java.security.SecureRandom;
import java.security.cert.X509Certificate;
import java.time.Duration;
import java.util.Base64;
import java.util.HexFormat;
import java.util.List;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicBoolean;

import static org.junit.jupiter.api.Assertions.*;

class DynamicLanTlsServerTest {

    private EphemeralKeyMaterialService crypto;
    private SessionStateRegistry registry;
    private WindowsNetworkFingerprintService networkService;
    private DynamicLanTlsServer server;
    private final ObjectMapper mapper = new ObjectMapper();

    @BeforeEach
    void setUp() {
        crypto = new EphemeralKeyMaterialService();
        registry = new SessionStateRegistry(crypto);
        networkService = new WindowsNetworkFingerprintService(
                () -> "HomeFiber|Wi-Fi|192.168.1.25|192.168.1.1|AA-BB-CC-11-22-33"
        );
        server = new DynamicLanTlsServer(crypto, registry, networkService);
    }

    @AfterEach
    void tearDown() {
        server.stopImmediately();
    }

    @Test
    void refusesToOpenPortOnUntrustedNetworkAndFiresIntrusionOnPlaintextProbe() throws Exception {
        assertFalse(server.isListening());

        // Cannot start pairing before approving home network
        assertThrows(IllegalStateException.class, () ->
                server.startForPairing(0, 0, 6, Duration.ofHours(1)));

        networkService.approveNetworkForCurrentSession(networkService.readCurrentNetwork().orElseThrow());
        List<IntrusionEvent> events = new CopyOnWriteArrayList<>();
        CountDownLatch alertLatch = new CountDownLatch(1);
        server.addIntrusionListener(ev -> {
            events.add(ev);
            alertLatch.countDown();
        });

        var info = server.startForPairing(0, 0, 6, Duration.ofHours(1));
        assertTrue(server.isListening());
        assertTrue(info.lanPort() > 0);

        // Plaintext HTTP scanner touches port and closes -> MUST fire TLS_HANDSHAKE_FAILED intrusion event!
        try (Socket raw = new Socket("127.0.0.1", info.lanPort())) {
            raw.getOutputStream().write("GET / HTTP/1.1\r\nHost: 127.0.0.1\r\n\r\n".getBytes(StandardCharsets.UTF_8));
            raw.getOutputStream().flush();
        }

        assertTrue(alertLatch.await(5, TimeUnit.SECONDS), "Plaintext TCP probe must fire intrusion event");
        assertEquals(IntrusionEvent.IntrusionType.TLS_HANDSHAKE_FAILED, events.get(0).type());
        assertFalse(events.get(0).authorizedConnection());
    }

    @Test
    void udpDiscoveryPairingPinnedMtlsWssFullParanoiaAlertAndRemoteTeardownWorkEndToEnd() throws Exception {
        networkService.approveNetworkForCurrentSession(networkService.readCurrentNetwork().orElseThrow());
        List<IntrusionEvent> events = new CopyOnWriteArrayList<>();
        server.addIntrusionListener(events::add);

        AtomicBoolean remoteTeardownFired = new AtomicBoolean(false);
        CountDownLatch teardownLatch = new CountDownLatch(1);
        server.setOnRemoteNuclearTeardown(() -> {
            remoteTeardownFired.set(true);
            teardownLatch.countDown();
        });

        var startInfo = server.startForPairing(0, 0, 6, Duration.ofHours(4));

        // 1. UDP Discovery during 60s pairing window returns port and serverCertSha256
        try (DatagramSocket udp = new DatagramSocket()) {
            udp.setSoTimeout(2500);
            byte[] req = "BLIPPER_DISCOVER_V1".getBytes(StandardCharsets.UTF_8);
            udp.send(new DatagramPacket(req, req.length, InetAddress.getByName("127.0.0.1"), startInfo.udpPort()));
            byte[] buf = new byte[512];
            DatagramPacket resp = new DatagramPacket(buf, buf.length);
            udp.receive(resp);
            JsonNode disc = mapper.readTree(new String(resp.getData(), 0, resp.getLength(), StandardCharsets.UTF_8));
            assertEquals("blipper-v1", disc.get("proto").asText());
            assertEquals(startInfo.lanPort(), disc.get("port").asInt());
            assertEquals(startInfo.serverCertSha256Hex(), disc.get("serverCertSha256").asText());
        }

        // 2. Pair with 6-digit PIN + client ECDSA cert over TLS 1.3
        var phoneCert = crypto.generateEphemeralEcCert("Samsung-Galaxy");
        SSLContext phoneSsl = buildClientSslContext(phoneCert, startInfo.serverCertSha256Hex());

        long ts = System.currentTimeMillis();
        String proof = crypto.computePairingProofHex(
                startInfo.pinCode().toCharArray(),
                startInfo.serverCertSha256Hex(),
                phoneCert.sha256Hex(),
                ts,
                "pair-nonce-1"
        );
        String pairJson = mapper.writeValueAsString(java.util.Map.of(
                "deviceName", "Samsung-S24",
                "timestampMs", ts,
                "nonce", "pair-nonce-1",
                "proofHex", proof
        ));

        JsonNode pairResp;
        try (SSLSocket pairSock = (SSLSocket) phoneSsl.getSocketFactory().createSocket("127.0.0.1", startInfo.lanPort())) {
            pairSock.setEnabledProtocols(new String[]{"TLSv1.3"});
            pairSock.startHandshake();
            String httpReq = "POST /api/v1/pair/complete HTTP/1.1\r\n"
                    + "Host: 127.0.0.1\r\n"
                    + "Content-Type: application/json\r\n"
                    + "Content-Length: " + pairJson.getBytes(StandardCharsets.UTF_8).length + "\r\n"
                    + "Connection: close\r\n\r\n"
                    + pairJson;
            pairSock.getOutputStream().write(httpReq.getBytes(StandardCharsets.UTF_8));
            pairSock.getOutputStream().flush();
            String rawHttpResp = new String(pairSock.getInputStream().readAllBytes(), StandardCharsets.UTF_8);
            assertTrue(rawHttpResp.startsWith("HTTP/1.1 200"));
            String body = rawHttpResp.substring(rawHttpResp.indexOf("\r\n\r\n") + 4);
            pairResp = mapper.readTree(body);
        }
        assertTrue(pairResp.get("accepted").asBoolean());
        String bearerToken = pairResp.get("bearerToken").asText();
        byte[] hmacKey = HexFormat.of().parseHex(pairResp.get("hmacKeyHex").asText());

        // 3. Rogue phone with different cert trying to connect after pairing is REJECTED + fires UNAUTHORIZED_TOUCH!
        var rogueCert = crypto.generateEphemeralEcCert("Attacker-Phone");
        SSLContext rogueSsl = buildClientSslContext(rogueCert, startInfo.serverCertSha256Hex());
        try (SSLSocket rogueSock = (SSLSocket) rogueSsl.getSocketFactory().createSocket("127.0.0.1", startInfo.lanPort())) {
            rogueSock.setEnabledProtocols(new String[]{"TLSv1.3"});
            String wsUpgrade = "GET /ws/v1/stream HTTP/1.1\r\nHost: 127.0.0.1\r\nAuthorization: Bearer " + bearerToken + "\r\n\r\n";
            try {
                rogueSock.startHandshake();
                rogueSock.getOutputStream().write(wsUpgrade.getBytes(StandardCharsets.UTF_8));
                rogueSock.getInputStream().read();
            } catch (Exception ignored) {
                // Expected TLS / socket rejection
            }
        }
        Thread.sleep(150);
        assertTrue(events.stream().anyMatch(e -> !e.authorizedConnection()),
                "Rogue client cert must trigger unauthorized intrusion alert");

        // 4. Legitimate phone upgrades to WSS -> triggers Full Paranoia AUTHENTICATED_DEVICE_CONNECT + receives TASK_COMPLETED!
        try (SSLSocket wsSock = (SSLSocket) phoneSsl.getSocketFactory().createSocket("127.0.0.1", startInfo.lanPort())) {
            wsSock.setEnabledProtocols(new String[]{"TLSv1.3"});
            wsSock.startHandshake();
            String wsKey = Base64.getEncoder().encodeToString("0123456789abcdef".getBytes(StandardCharsets.UTF_8));
            String upgrade = "GET /ws/v1/stream HTTP/1.1\r\n"
                    + "Host: 127.0.0.1\r\n"
                    + "Upgrade: websocket\r\n"
                    + "Connection: Upgrade\r\n"
                    + "Sec-WebSocket-Key: " + wsKey + "\r\n"
                    + "Sec-WebSocket-Version: 13\r\n"
                    + "Authorization: Bearer " + bearerToken + "\r\n\r\n";
            OutputStream out = wsSock.getOutputStream();
            InputStream in = wsSock.getInputStream();
            out.write(upgrade.getBytes(StandardCharsets.UTF_8));
            out.flush();

            String handshakeHeader = readHttpHeader(in);
            assertTrue(handshakeHeader.startsWith("HTTP/1.1 101"));
            assertTrue(server.hasActiveAuthenticatedStream());
            assertTrue(events.stream().anyMatch(e ->
                    e.type() == IntrusionEvent.IntrusionType.AUTHENTICATED_DEVICE_CONNECT && e.authorizedConnection()));

            // Desktop pushes TASK_COMPLETED -> Phone reads and verifies HMAC!
            assertTrue(server.sendTaskCompleted("Carbon Merhaba Greeting", "Modül tamamlandı"));
            String frameText = readUnmaskedServerWsTextFrame(in);
            SignedEnvelope receivedEnv = mapper.readValue(frameText, SignedEnvelope.class);
            assertEquals("TASK_COMPLETED", receivedEnv.type());
            assertTrue(crypto.verifyEnvelope(hmacKey, receivedEnv));

            // Phone sends signed NUCLEAR_TEARDOWN -> Desktop triggers callback & stops port!
            SignedEnvelope teardownEnv = crypto.signEnvelope(hmacKey, "NUCLEAR_TEARDOWN", "{\"reason\":\"PHONE_DISCONNECT\"}");
            writeMaskedClientWsTextFrame(out, mapper.writeValueAsString(teardownEnv));
            assertTrue(teardownLatch.await(5, TimeUnit.SECONDS));
            assertTrue(remoteTeardownFired.get());
        }

        server.stopImmediately();
        assertFalse(server.isListening());
        assertThrows(ConnectException.class, () -> new Socket("127.0.0.1", startInfo.lanPort()).close());
    }

    private SSLContext buildClientSslContext(
            EphemeralKeyMaterialService.EphemeralCertBundle clientBundle,
            String pinnedServerSha256Hex
    ) throws Exception {
        KeyStore ks = KeyStore.getInstance("PKCS12");
        ks.load(null, null);
        ks.setKeyEntry("client", clientBundle.keyPair().getPrivate(), new char[0],
                new X509Certificate[]{clientBundle.certificate()});
        KeyManagerFactory kmf = KeyManagerFactory.getInstance(KeyManagerFactory.getDefaultAlgorithm());
        kmf.init(ks, new char[0]);

        TrustManager pinnedTm = new X509TrustManager() {
            @Override
            public void checkClientTrusted(X509Certificate[] chain, String authType) {}

            @Override
            public void checkServerTrusted(X509Certificate[] chain, String authType) {
                if (chain == null || chain.length == 0) {
                    throw new SecurityException("Empty server cert chain");
                }
                String actual = crypto.computeCertSha256Hex(chain[0]);
                if (!pinnedServerSha256Hex.equalsIgnoreCase(actual)) {
                    throw new SecurityException("Server cert pin mismatch");
                }
            }

            @Override
            public X509Certificate[] getAcceptedIssuers() {
                return new X509Certificate[0];
            }
        };

        SSLContext ctx = SSLContext.getInstance("TLSv1.3");
        ctx.init(kmf.getKeyManagers(), new TrustManager[]{pinnedTm}, new SecureRandom());
        return ctx;
    }

    private static String readHttpHeader(InputStream in) throws Exception {
        StringBuilder sb = new StringBuilder();
        int b;
        while ((b = in.read()) != -1) {
            sb.append((char) b);
            if (sb.length() >= 4 && sb.substring(sb.length() - 4).equals("\r\n\r\n")) {
                break;
            }
        }
        return sb.toString();
    }

    private static String readUnmaskedServerWsTextFrame(InputStream in) throws Exception {
        int b0 = in.read();
        int b1 = in.read();
        assertEquals(0x81, b0);
        int len = b1 & 0x7F;
        if (len == 126) {
            len = ((in.read() & 0xFF) << 8) | (in.read() & 0xFF);
        } else if (len == 127) {
            long l = 0;
            for (int i = 0; i < 8; i++) {
                l = (l << 8) | (in.read() & 0xFF);
            }
            len = (int) l;
        }
        byte[] payload = in.readNBytes(len);
        return new String(payload, StandardCharsets.UTF_8);
    }

    private static void writeMaskedClientWsTextFrame(OutputStream out, String text) throws Exception {
        byte[] payload = text.getBytes(StandardCharsets.UTF_8);
        byte[] mask = new byte[]{0x11, 0x22, 0x33, 0x44};
        out.write(0x81);
        if (payload.length < 126) {
            out.write(0x80 | payload.length);
        } else {
            out.write(0x80 | 126);
            out.write((payload.length >> 8) & 0xFF);
            out.write(payload.length & 0xFF);
        }
        out.write(mask);
        for (int i = 0; i < payload.length; i++) {
            out.write(payload[i] ^ mask[i % 4]);
        }
        out.flush();
    }
}
