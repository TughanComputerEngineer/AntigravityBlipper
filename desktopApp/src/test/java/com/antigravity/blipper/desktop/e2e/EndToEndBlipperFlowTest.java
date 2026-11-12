package com.antigravity.blipper.desktop.e2e;

import com.antigravity.blipper.desktop.BlipperDesktopApplication;
import com.antigravity.blipper.desktop.agy.AntigravityConversationReader;
import com.antigravity.blipper.desktop.agy.LocalHookController;
import com.antigravity.blipper.desktop.crypto.EphemeralKeyMaterialService;
import com.antigravity.blipper.desktop.crypto.SignedEnvelope;
import com.antigravity.blipper.desktop.network.DynamicLanTlsServer;
import com.antigravity.blipper.desktop.network.IntrusionEvent;
import com.antigravity.blipper.desktop.network.NuclearTeardownCoordinator;
import com.antigravity.blipper.desktop.network.WindowsNetworkFingerprintService;
import com.antigravity.blipper.desktop.security.LocalHookSecretManager;
import com.antigravity.blipper.desktop.security.SecurityAuditLogger;
import com.antigravity.blipper.desktop.security.SessionStateRegistry;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.context.TestConfiguration;
import org.springframework.boot.test.web.server.LocalServerPort;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Primary;

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
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.KeyStore;
import java.security.SecureRandom;
import java.security.cert.X509Certificate;
import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.Statement;
import java.time.Duration;
import java.util.Base64;
import java.util.HexFormat;
import java.util.List;
import java.util.Map;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;

import static org.junit.jupiter.api.Assertions.*;

@SpringBootTest(
        classes = {BlipperDesktopApplication.class, EndToEndBlipperFlowTest.IsolatedTestConfig.class},
        webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT,
        properties = {
                "server.address=127.0.0.1",
                "blipper.ui.enabled=false",
                "blipper.hook.auto-install=false"
        }
)
class EndToEndBlipperFlowTest {

    private static Path sandboxDir;
    private static Path sqliteDbPath;

    @TestConfiguration
    static class IsolatedTestConfig {

        private static synchronized Path ensureSandboxDir() {
            if (sandboxDir == null) {
                try {
                    sandboxDir = Files.createTempDirectory("blipper-e2e-test-");
                    sqliteDbPath = sandboxDir.resolve("conversation_summaries.db");
                    try (Connection conn = DriverManager.getConnection("jdbc:sqlite:" + sqliteDbPath.toAbsolutePath());
                         Statement st = conn.createStatement()) {
                        st.execute("PRAGMA journal_mode=WAL;");
                        st.execute("CREATE TABLE conversation_summaries ("
                                + "conversation_id TEXT PRIMARY KEY, "
                                + "title TEXT NOT NULL DEFAULT '', "
                                + "parent_conversation_id TEXT NOT NULL DEFAULT '')");
                        st.execute("INSERT INTO conversation_summaries VALUES "
                                + "('e2e-conv-1', 'AntigravityBlipper Güvenlik Mimarisi', '')");
                    }
                } catch (Exception e) {
                    throw new IllegalStateException("Failed to initialize E2E sandbox", e);
                }
            }
            return sandboxDir;
        }

        @Bean
        @Primary
        public WindowsNetworkFingerprintService testNetworkFingerprintService() {
            return new WindowsNetworkFingerprintService(
                    () -> "Tughan_Ev_5GHz|Wi-Fi|192.168.1.42|192.168.1.1|AA-BB-CC-DD-EE-FF"
            );
        }

        @Bean
        @Primary
        public SecurityAuditLogger testSecurityAuditLogger() {
            return new SecurityAuditLogger(ensureSandboxDir().resolve("security-audit.jsonl"));
        }

        @Bean
        @Primary
        public LocalHookSecretManager testLocalHookSecretManager() {
            return new LocalHookSecretManager(ensureSandboxDir().resolve("local-hook.secret"));
        }

        @Bean
        @Primary
        public AntigravityConversationReader testConversationReader() {
            ensureSandboxDir();
            return new AntigravityConversationReader(sqliteDbPath);
        }
    }

    @LocalServerPort
    private int loopbackPort;

    @Autowired
    private EphemeralKeyMaterialService crypto;

    @Autowired
    private SessionStateRegistry sessionRegistry;

    @Autowired
    private WindowsNetworkFingerprintService networkService;

    @Autowired
    private DynamicLanTlsServer lanServer;

    @Autowired
    private NuclearTeardownCoordinator teardownCoordinator;

    @Autowired
    private SecurityAuditLogger auditLogger;

    @Autowired
    private LocalHookSecretManager hookSecretManager;

    @Autowired
    private LocalHookController localHookController;

    private final ObjectMapper mapper = new ObjectMapper();

    @Test
    void fullFourStageLifecycleFromZeroPortsToHookBannerMtlsBurstAndEmergencyShutdown() throws Exception {
        // STAGE 1: Boot starts with 0 open LAN ports and CLOSED state
        assertFalse(lanServer.isListening(), "Desktop app must boot with 0 open LAN ports");
        assertEquals(SessionStateRegistry.State.CLOSED, sessionRegistry.getState());

        // STAGE 2: Approve Home Network -> Open 60s Pairing -> UDP Discovery -> 6-digit PIN + mTLS 1.3 WSS
        var homeFp = networkService.readCurrentNetwork().orElseThrow();
        networkService.approveNetworkForCurrentSession(homeFp);

        List<IntrusionEvent> capturedIntrusions = new CopyOnWriteArrayList<>();
        lanServer.addIntrusionListener(capturedIntrusions::add);

        List<AntigravityConversationReader.CompletedTaskSummary> capturedBanners = new CopyOnWriteArrayList<>();
        localHookController.addTaskCompletedListener(capturedBanners::add);

        var startInfo = lanServer.startForPairing(0, 0, 6, Duration.ofHours(2));
        assertTrue(lanServer.isListening());
        assertEquals(6, startInfo.pinCode().length());

        // Simulated Android LanDiscoveryClient single UDP query
        String discoveredServerSha;
        int discoveredTlsPort;
        try (DatagramSocket udp = new DatagramSocket()) {
            udp.setSoTimeout(2500);
            byte[] query = "BLIPPER_DISCOVER_V1".getBytes(StandardCharsets.UTF_8);
            udp.send(new DatagramPacket(query, query.length, InetAddress.getByName("127.0.0.1"), startInfo.udpPort()));
            byte[] buf = new byte[512];
            DatagramPacket reply = new DatagramPacket(buf, buf.length);
            udp.receive(reply);
            JsonNode json = mapper.readTree(new String(reply.getData(), 0, reply.getLength(), StandardCharsets.UTF_8));
            assertEquals("blipper-v1", json.get("proto").asText());
            discoveredTlsPort = json.get("port").asInt();
            discoveredServerSha = json.get("serverCertSha256").asText();
        }
        assertEquals(startInfo.lanPort(), discoveredTlsPort);
        assertEquals(startInfo.serverCertSha256Hex(), discoveredServerSha);

        // Simulated Android HardwareKeyManager + BlipperSecureWsClient pairing
        var androidCert = crypto.generateEphemeralEcCert("Samsung-S24-Ultra");
        SSLContext androidSsl = buildPinnedClientSsl(androidCert, discoveredServerSha);

        long pairTs = System.currentTimeMillis();
        String pairNonce = "android-e2e-nonce-01";
        String clientProofHex = crypto.computePairingProofHex(
                startInfo.pinCode().toCharArray(),
                discoveredServerSha,
                androidCert.sha256Hex(),
                pairTs,
                pairNonce
        );
        String pairPayload = mapper.writeValueAsString(Map.of(
                "deviceName", "Samsung SM-S928B",
                "timestampMs", pairTs,
                "nonce", pairNonce,
                "proofHex", clientProofHex
        ));

        JsonNode pairResp;
        try (SSLSocket pairSock = (SSLSocket) androidSsl.getSocketFactory().createSocket("127.0.0.1", discoveredTlsPort)) {
            pairSock.setEnabledProtocols(new String[]{"TLSv1.3"});
            pairSock.startHandshake();
            String httpReq = "POST /api/v1/pair/complete HTTP/1.1\r\n"
                    + "Host: 127.0.0.1\r\n"
                    + "Content-Type: application/json\r\n"
                    + "Content-Length: " + pairPayload.getBytes(StandardCharsets.UTF_8).length + "\r\n"
                    + "Connection: close\r\n\r\n"
                    + pairPayload;
            pairSock.getOutputStream().write(httpReq.getBytes(StandardCharsets.UTF_8));
            pairSock.getOutputStream().flush();
            String rawResp = new String(pairSock.getInputStream().readAllBytes(), StandardCharsets.UTF_8);
            assertTrue(rawResp.startsWith("HTTP/1.1 200"));
            pairResp = mapper.readTree(rawResp.substring(rawResp.indexOf("\r\n\r\n") + 4));
        }

        assertTrue(pairResp.get("accepted").asBoolean());
        String expectedServerAck = crypto.computePairingProofHex(
                startInfo.pinCode().toCharArray(),
                discoveredServerSha,
                androidCert.sha256Hex(),
                pairTs,
                pairNonce + ":SERVER_ACK"
        );
        assertEquals(expectedServerAck, pairResp.get("serverProofHex").asText(), "Mutual server PIN proof must match");

        String bearerToken = pairResp.get("bearerToken").asText();
        byte[] hmacKey = HexFormat.of().parseHex(pairResp.get("hmacKeyHex").asText());

        // Upgrade to authenticated WSS stream -> Full Paranoia alert MUST fire even for paired phone!
        try (SSLSocket wsSock = (SSLSocket) androidSsl.getSocketFactory().createSocket("127.0.0.1", discoveredTlsPort)) {
            wsSock.setEnabledProtocols(new String[]{"TLSv1.3"});
            wsSock.startHandshake();
            String wsKey = Base64.getEncoder().encodeToString("blipper-ws-key16".getBytes(StandardCharsets.UTF_8));
            String upgrade = "GET /ws/v1/stream HTTP/1.1\r\n"
                    + "Host: 127.0.0.1\r\n"
                    + "Upgrade: websocket\r\n"
                    + "Connection: Upgrade\r\n"
                    + "Sec-WebSocket-Key: " + wsKey + "\r\n"
                    + "Sec-WebSocket-Version: 13\r\n"
                    + "Authorization: Bearer " + bearerToken + "\r\n\r\n";

            OutputStream wsOut = wsSock.getOutputStream();
            InputStream wsIn = wsSock.getInputStream();
            wsOut.write(upgrade.getBytes(StandardCharsets.UTF_8));
            wsOut.flush();

            String upgradeResp = readHttpHeader(wsIn);
            assertTrue(upgradeResp.startsWith("HTTP/1.1 101"));
            assertTrue(lanServer.hasActiveAuthenticatedStream());
            assertTrue(capturedIntrusions.stream().anyMatch(e ->
                            e.type() == IntrusionEvent.IntrusionType.AUTHENTICATED_DEVICE_CONNECT && e.authorizedConnection()),
                    "Full Paranoia mode must fire alert event when paired phone connects");

            // STAGE 3: Simulated Antigravity Stop Hook posts over real loopback HTTP -> Banner + Signed WSS Push + ACK
            Path transcriptPath = sandboxDir.resolve("e2e-transcript.jsonl");
            Files.writeString(transcriptPath,
                    "{\"step_index\":1,\"type\":\"PLANNER_RESPONSE\",\"content\":\"**mTLS 1.3 köprüsü** ve `Samsung 5x uyandırma` tamamlandı!\"}\n",
                    StandardCharsets.UTF_8);

            HttpClient loopbackHttp = HttpClient.newHttpClient();
            String hookBody = mapper.writeValueAsString(Map.of(
                    "conversationId", "e2e-conv-1",
                    "terminationReason", "NO_TOOL_CALL",
                    "transcriptPath", transcriptPath.toString()
            ));

            // Unauthorized loopback call without X-Blipper-Local-Secret MUST fail with 403!
            HttpResponse<String> unauthResp = loopbackHttp.send(
                    HttpRequest.newBuilder(URI.create("http://127.0.0.1:" + loopbackPort + "/local/v1/agy-stop"))
                            .header("Content-Type", "application/json")
                            .POST(HttpRequest.BodyPublishers.ofString(hookBody))
                            .build(),
                    HttpResponse.BodyHandlers.ofString()
            );
            assertEquals(403, unauthResp.statusCode());

            // Authorized loopback Stop hook call -> 200 OK
            HttpResponse<String> authResp = loopbackHttp.send(
                    HttpRequest.newBuilder(URI.create("http://127.0.0.1:" + loopbackPort + "/local/v1/agy-stop"))
                            .header("Content-Type", "application/json")
                            .header(LocalHookSecretManager.HEADER_NAME, hookSecretManager.getOrCreateSecret())
                            .POST(HttpRequest.BodyPublishers.ofString(hookBody))
                            .build(),
                    HttpResponse.BodyHandlers.ofString()
            );
            assertEquals(200, authResp.statusCode());
            JsonNode hookRespJson = mapper.readTree(authResp.body());
            assertTrue(hookRespJson.get("dispatched").asBoolean());
            assertTrue(hookRespJson.get("lanSent").asBoolean());

            // Verify Desktop Top Banner received exact formatted copy
            assertEquals(1, capturedBanners.size());
            assertEquals(
                    "ANTIGRAVITY: AntigravityBlipper Güvenlik Mimarisi: mTLS 1.3 köprüsü ve Samsung 5x uyandırma tamamlandı!",
                    capturedBanners.get(0).formattedBannerText()
            );

            // Verify Android WSS stream received signed TASK_COMPLETED envelope and sends signed TASK_ACK
            String rawWsFrame = readUnmaskedServerWsTextFrame(wsIn);
            SignedEnvelope taskEnv = mapper.readValue(rawWsFrame, SignedEnvelope.class);
            assertEquals("TASK_COMPLETED", taskEnv.type());
            assertTrue(crypto.verifyEnvelope(hmacKey, taskEnv));
            JsonNode taskPayload = mapper.readTree(taskEnv.payloadJson());
            assertEquals("AntigravityBlipper Güvenlik Mimarisi", taskPayload.get("conversationTitle").asText());
            assertEquals("mTLS 1.3 köprüsü ve Samsung 5x uyandırma tamamlandı!", taskPayload.get("taskSummary").asText());

            SignedEnvelope ackEnv = crypto.signEnvelope(
                    hmacKey,
                    "TASK_ACK",
                    "{\"ackedEventId\":\"" + taskEnv.eventId() + "\"}"
            );
            writeMaskedClientWsTextFrame(wsOut, mapper.writeValueAsString(ackEnv));

            // STAGE 4: Simulated rogue scanner touches LAN port -> Intrusion logged -> NUCLEAR_TEARDOWN -> 0 Open Ports!
            CountDownLatch rogueLatch = new CountDownLatch(1);
            lanServer.addIntrusionListener(ev -> {
                if (!ev.authorizedConnection()) {
                    rogueLatch.countDown();
                }
            });

            try (Socket rogueRaw = new Socket("127.0.0.1", discoveredTlsPort)) {
                rogueRaw.getOutputStream().write("SSH-2.0-RogueScanner\r\n".getBytes(StandardCharsets.UTF_8));
                rogueRaw.getOutputStream().flush();
            }
            assertTrue(rogueLatch.await(5, TimeUnit.SECONDS), "Rogue socket probe must emit unauthorized IntrusionEvent");

            IntrusionEvent rogueEvent = capturedIntrusions.stream()
                    .filter(ev -> !ev.authorizedConnection())
                    .findFirst()
                    .orElseThrow();

            // User clicks giant red "LOGLA VE PORTU ANINDA KAPAT" button -> logs forensics, sends NUCLEAR_TEARDOWN, closes port
            teardownCoordinator.logIntrusionAndShutdownPort(rogueEvent);

            String teardownFrame = readUnmaskedServerWsTextFrame(wsIn);
            SignedEnvelope teardownEnv = mapper.readValue(teardownFrame, SignedEnvelope.class);
            assertEquals("NUCLEAR_TEARDOWN", teardownEnv.type());
            assertTrue(crypto.verifyEnvelope(hmacKey, teardownEnv));
        }

        assertFalse(lanServer.isListening(), "LAN port must be completely closed after emergency shutdown");
        assertEquals(SessionStateRegistry.State.CLOSED, sessionRegistry.getState());
        assertTrue(sessionRegistry.getSessionHmacKeyCopy().isEmpty(), "Session HMAC key must be wiped from RAM");
        assertFalse(networkService.isCurrentNetworkTrusted(), "Approved network must be cleared on nuclear teardown");
        assertThrows(ConnectException.class, () -> new Socket("127.0.0.1", discoveredTlsPort).close());
        assertTrue(auditLogger.verifyChainIntegrity(), "Tamper-evident SHA-256 audit log chain must verify true");
    }

    private SSLContext buildPinnedClientSsl(
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
        byte[] mask = new byte[]{0x5A, 0x3C, 0x19, 0x7E};
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
