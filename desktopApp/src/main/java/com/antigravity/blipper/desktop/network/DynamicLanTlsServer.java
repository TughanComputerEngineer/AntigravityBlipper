package com.antigravity.blipper.desktop.network;

import com.antigravity.blipper.desktop.crypto.EphemeralKeyMaterialService;
import com.antigravity.blipper.desktop.crypto.SignedEnvelope;
import com.antigravity.blipper.desktop.security.SessionStateRegistry;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.springframework.stereotype.Service;

import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLHandshakeException;
import javax.net.ssl.SSLPeerUnverifiedException;
import javax.net.ssl.SSLSocket;
import javax.net.ssl.TrustManager;
import javax.net.ssl.X509TrustManager;
import java.io.ByteArrayOutputStream;
import java.io.EOFException;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.InetSocketAddress;
import java.net.ServerSocket;
import java.net.Socket;
import java.net.SocketException;
import java.nio.charset.StandardCharsets;
import java.security.KeyStore;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.time.Duration;
import java.time.Instant;
import java.util.Arrays;
import java.util.Base64;
import java.util.HashMap;
import java.util.HexFormat;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Optional;
import java.util.UUID;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicLong;
import java.util.function.Consumer;

@Service
public class DynamicLanTlsServer {

    private static final String WS_GUID = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11";
    private static final int MAX_HTTP_HEADER_BYTES = 16 * 1024;
    private static final int MAX_HTTP_BODY_BYTES = 32 * 1024;
    private static final int MAX_WS_FRAME_BYTES = 65535;
    private static final int WS_READ_TIMEOUT_MS = 90_000;
    private static final long SERVER_WS_PING_INTERVAL_MS = 20_000L;
    private static final long PENDING_TASK_BUFFER_TTL_MS = 120_000L;

    public record PairingStartInfo(
            int lanPort,
            int udpPort,
            String pinCode,
            long expiresAtMs,
            String serverCertSha256Hex
    ) {}

    private record PendingTaskAlert(
            String eventId,
            String payloadJson,
            long createdAtMs
    ) {}

    private final EphemeralKeyMaterialService crypto;
    private final SessionStateRegistry sessionRegistry;
    private final WindowsNetworkFingerprintService networkService;
    private final UdpDiscoveryResponder udpDiscoveryResponder;
    private final ObjectMapper mapper = new ObjectMapper();
    private final List<Consumer<IntrusionEvent>> intrusionListeners = new CopyOnWriteArrayList<>();
    private final AtomicLong lastAlertedGeneration = new AtomicLong(-1L);

    private volatile ServerSocket serverSocket;
    private volatile SSLContext sslContext;
    private volatile ExecutorService connectionExecutor;
    private volatile ScheduledExecutorService keepaliveExecutor;
    private volatile WsClientConnection activeWsConnection;
    private volatile PendingTaskAlert pendingTaskAlert;
    private volatile Runnable onRemoteNuclearTeardown;

    public DynamicLanTlsServer(
            EphemeralKeyMaterialService crypto,
            SessionStateRegistry sessionRegistry,
            WindowsNetworkFingerprintService networkService
    ) {
        this.crypto = crypto;
        this.sessionRegistry = sessionRegistry;
        this.networkService = networkService;
        this.udpDiscoveryResponder = new UdpDiscoveryResponder(sessionRegistry);
    }

    public synchronized PairingStartInfo startForPairing(int lanPort, int udpPort, int codeDigits, Duration ttl) {
        if (!networkService.isCurrentNetworkTrusted()) {
            throw new IllegalStateException("Home network must be verified and approved before opening LAN port");
        }
        stopImmediately();

        var serverCert = crypto.generateEphemeralEcCert("AntigravityBlipper-Desktop");
        var challenge = sessionRegistry.openPairingWindow(codeDigits, ttl, serverCert);

        try {
            this.sslContext = createServerSslContext(serverCert);
            ServerSocket ss = new ServerSocket();
            ss.setReuseAddress(true);
            ss.bind(new InetSocketAddress("0.0.0.0", lanPort));
            this.serverSocket = ss;
            this.connectionExecutor = Executors.newCachedThreadPool(r -> {
                Thread t = new Thread(r, "blipper-lan-conn");
                t.setDaemon(true);
                return t;
            });
            ScheduledExecutorService keepalive = Executors.newSingleThreadScheduledExecutor(r -> {
                Thread t = new Thread(r, "blipper-lan-ws-keepalive");
                t.setDaemon(true);
                return t;
            });
            keepalive.scheduleWithFixedDelay(
                    this::sendServerKeepalivePing,
                    SERVER_WS_PING_INTERVAL_MS,
                    SERVER_WS_PING_INTERVAL_MS,
                    TimeUnit.MILLISECONDS
            );
            this.keepaliveExecutor = keepalive;

            int boundLanPort = ss.getLocalPort();
            int boundUdpPort = udpDiscoveryResponder.start(udpPort, boundLanPort, serverCert.sha256Hex());

            Thread acceptThread = new Thread(() -> acceptLoop(ss), "blipper-lan-accept");
            acceptThread.setDaemon(true);
            acceptThread.start();

            return new PairingStartInfo(
                    boundLanPort,
                    boundUdpPort,
                    challenge.pinCode(),
                    challenge.expiresAtMs(),
                    serverCert.sha256Hex()
            );
        } catch (Exception e) {
            sessionRegistry.wipeAll();
            stopImmediately();
            throw new IllegalStateException("Failed to start dynamic TLS 1.3 LAN server", e);
        }
    }

    public boolean isListening() {
        ServerSocket ss = this.serverSocket;
        return ss != null && !ss.isClosed();
    }

    public int getBoundPort() {
        ServerSocket ss = this.serverSocket;
        return (ss != null && !ss.isClosed()) ? ss.getLocalPort() : -1;
    }

    public boolean hasActiveAuthenticatedStream() {
        WsClientConnection conn = this.activeWsConnection;
        return conn != null && conn.isOpen()
                && sessionRegistry.getState() == SessionStateRegistry.State.ACTIVE_SESSION;
    }

    public boolean sendTaskCompleted(String conversationTitle, String taskSummary) {
        if (sessionRegistry.getState() != SessionStateRegistry.State.ACTIVE_SESSION) {
            return false;
        }
        Optional<byte[]> hmacKeyOpt = sessionRegistry.getSessionHmacKeyCopy();
        if (hmacKeyOpt.isEmpty()) {
            return false;
        }
        byte[] hmacKey = hmacKeyOpt.get();
        try {
            String payloadJson = mapper.writeValueAsString(Map.of(
                    "conversationTitle", conversationTitle == null ? "" : conversationTitle,
                    "taskSummary", taskSummary == null ? "" : taskSummary
            ));
            String eventId = UUID.randomUUID().toString();
            SignedEnvelope env = crypto.signEnvelopeAt(hmacKey, "TASK_COMPLETED", payloadJson, eventId, System.currentTimeMillis());
            String envelopeJson = mapper.writeValueAsString(env);
            if (envelopeJson.getBytes(StandardCharsets.UTF_8).length > MAX_WS_FRAME_BYTES) {
                return false;
            }

            WsClientConnection conn = this.activeWsConnection;
            if (conn != null && conn.isOpen() && conn.sendTextFrame(envelopeJson)) {
                return true;
            }

            // Paired phone is momentarily reconnecting over Wi-Fi; buffer within active session for instant replay!
            this.pendingTaskAlert = new PendingTaskAlert(eventId, payloadJson, System.currentTimeMillis());
            return true;
        } catch (Exception e) {
            return false;
        } finally {
            Arrays.fill(hmacKey, (byte) 0);
        }
    }

    public synchronized void sendNuclearTeardownAndStop() {
        WsClientConnection conn = this.activeWsConnection;
        Optional<byte[]> hmacKeyOpt = sessionRegistry.getSessionHmacKeyCopy();
        if (conn != null && conn.isOpen() && hmacKeyOpt.isPresent()) {
            byte[] hmacKey = hmacKeyOpt.get();
            try {
                SignedEnvelope env = crypto.signEnvelope(hmacKey, "NUCLEAR_TEARDOWN", "{\"reason\":\"DESKTOP_SHUTDOWN\"}");
                conn.sendTextFrame(mapper.writeValueAsString(env));
                conn.sendCloseFrame();
            } catch (Exception ignored) {
                // Best effort flush before socket close
            } finally {
                Arrays.fill(hmacKey, (byte) 0);
            }
        }
        stopImmediately();
    }

    public synchronized void stopImmediately() {
        udpDiscoveryResponder.stop();
        this.pendingTaskAlert = null;
        ScheduledExecutorService keepalive = this.keepaliveExecutor;
        this.keepaliveExecutor = null;
        if (keepalive != null) {
            keepalive.shutdownNow();
        }
        WsClientConnection ws = this.activeWsConnection;
        this.activeWsConnection = null;
        if (ws != null) {
            ws.closeQuietly();
        }
        ServerSocket ss = this.serverSocket;
        this.serverSocket = null;
        if (ss != null && !ss.isClosed()) {
            try {
                ss.close();
            } catch (IOException ignored) {}
        }
        ExecutorService exec = this.connectionExecutor;
        this.connectionExecutor = null;
        if (exec != null) {
            exec.shutdownNow();
        }
        this.sslContext = null;
    }

    public void addIntrusionListener(Consumer<IntrusionEvent> listener) {
        if (listener != null) {
            intrusionListeners.add(listener);
        }
    }

    public void setOnRemoteNuclearTeardown(Runnable callback) {
        this.onRemoteNuclearTeardown = callback;
    }

    private void sendServerKeepalivePing() {
        if (!isListening() || sessionRegistry.getState() != SessionStateRegistry.State.ACTIVE_SESSION) {
            return;
        }
        WsClientConnection conn = this.activeWsConnection;
        if (conn != null && conn.isOpen()) {
            conn.sendPingFrame("blipper-keepalive".getBytes(StandardCharsets.UTF_8));
        }
    }

    private void acceptLoop(ServerSocket ss) {
        while (!ss.isClosed()) {
            try {
                Socket rawSocket = ss.accept();
                ExecutorService exec = this.connectionExecutor;
                if (exec == null || exec.isShutdown()) {
                    rawSocket.close();
                    return;
                }
                exec.submit(() -> handleAcceptedSocket(rawSocket));
            } catch (SocketException closed) {
                return;
            } catch (Exception ignored) {
                // Keep listener alive unless explicitly closed
            }
        }
    }

    private void handleAcceptedSocket(Socket rawSocket) {
        String remoteIp = rawSocket.getInetAddress() != null
                ? rawSocket.getInetAddress().getHostAddress()
                : "unknown";
        int remotePort = rawSocket.getPort();
        SSLContext ctx = this.sslContext;
        if (ctx == null) {
            closeQuietly(rawSocket);
            return;
        }

        SSLSocket sslSocket = null;
        boolean peerVerifiedAsPinnedDevice = false;
        try {
            rawSocket.setKeepAlive(true);
            rawSocket.setSoTimeout(12_000);
            SessionStateRegistry.State currentState = sessionRegistry.getState();
            if (currentState == SessionStateRegistry.State.CLOSED) {
                emitIntrusion(IntrusionEvent.IntrusionType.UNAUTHORIZED_TOUCH, remoteIp, remotePort,
                        "Port touched while session state CLOSED", false);
                closeQuietly(rawSocket);
                return;
            }

            sslSocket = (SSLSocket) ctx.getSocketFactory().createSocket(rawSocket, remoteIp, remotePort, true);
            sslSocket.setUseClientMode(false);
            sslSocket.setEnabledProtocols(new String[]{"TLSv1.3"});
            if (currentState == SessionStateRegistry.State.ACTIVE_SESSION) {
                sslSocket.setNeedClientAuth(true);
            } else {
                sslSocket.setWantClientAuth(true);
            }

            sslSocket.startHandshake();
            X509Certificate peerCert = extractPeerCertificate(sslSocket);
            if (peerCert == null) {
                emitIntrusion(IntrusionEvent.IntrusionType.UNAUTHORIZED_TOUCH, remoteIp, remotePort,
                        "TLS 1.3 client did not present an X.509 certificate", false);
                closeQuietly(sslSocket);
                return;
            }

            peerVerifiedAsPinnedDevice = sessionRegistry.isPinnedClientCertificate(peerCert);

            InputStream in = sslSocket.getInputStream();
            OutputStream out = sslSocket.getOutputStream();
            ParsedHttpRequest req = readHttpRequest(in);
            if (req == null) {
                if (!peerVerifiedAsPinnedDevice && isListening()) {
                    emitIntrusion(IntrusionEvent.IntrusionType.UNAUTHORIZED_TOUCH, remoteIp, remotePort,
                            "Empty or malformed HTTP request over TLS", false);
                }
                closeQuietly(sslSocket);
                return;
            }

            if ("POST".equalsIgnoreCase(req.method) && "/api/v1/pair/complete".equals(req.path)) {
                handlePairingRequest(sslSocket, out, peerCert, req, remoteIp, remotePort);
            } else if ("GET".equalsIgnoreCase(req.method) && "/ws/v1/stream".equals(req.path)) {
                handleWebSocketStream(sslSocket, in, out, peerCert, req, remoteIp, remotePort);
            } else {
                emitIntrusion(IntrusionEvent.IntrusionType.UNAUTHORIZED_TOUCH, remoteIp, remotePort,
                        "Unexpected endpoint probe: " + req.method + " " + req.path, false);
                writeHttpResponse(out, 403, "{\"error\":\"FORBIDDEN\"}");
                closeQuietly(sslSocket);
            }
        } catch (SSLHandshakeException handshakeEx) {
            if (isListening()) {
                emitIntrusion(IntrusionEvent.IntrusionType.TLS_HANDSHAKE_FAILED, remoteIp, remotePort,
                        "TLS 1.3 handshake rejected: " + handshakeEx.getMessage(), false);
            }
            closeQuietly(sslSocket != null ? sslSocket : rawSocket);
        } catch (Exception ex) {
            // Do NOT fire fake intrusion alarms if server is stopping or if the already-pinned phone dropped mid-socket
            if (isListening() && !peerVerifiedAsPinnedDevice) {
                emitIntrusion(IntrusionEvent.IntrusionType.TLS_HANDSHAKE_FAILED, remoteIp, remotePort,
                        "Connection aborted before authentication: " + ex.getClass().getSimpleName(), false);
            }
            closeQuietly(sslSocket != null ? sslSocket : rawSocket);
        }
    }

    private void handlePairingRequest(
            SSLSocket sslSocket,
            OutputStream out,
            X509Certificate clientCert,
            ParsedHttpRequest req,
            String remoteIp,
            int remotePort
    ) throws IOException {
        try {
            if (sessionRegistry.getState() != SessionStateRegistry.State.PAIRING_WINDOW) {
                emitIntrusion(IntrusionEvent.IntrusionType.UNAUTHORIZED_TOUCH, remoteIp, remotePort,
                        "Pairing endpoint hit outside active pairing window", false);
                writeHttpResponse(out, 403, "{\"accepted\":false,\"reason\":\"PAIRING_CLOSED\"}");
                return;
            }
            JsonNode body = mapper.readTree(req.bodyBytes);
            String deviceName = body.path("deviceName").asText("Android");
            long timestampMs = body.path("timestampMs").asLong(0L);
            String nonce = body.path("nonce").asText("");
            String proofHex = body.path("proofHex").asText("");

            var outcome = sessionRegistry.attemptPairing(clientCert, deviceName, timestampMs, nonce, proofHex);
            udpDiscoveryResponder.stop();

            if (!outcome.accepted()) {
                emitIntrusion(IntrusionEvent.IntrusionType.INVALID_PIN, remoteIp, remotePort,
                        "Invalid pairing PIN/HMAC proof (" + outcome.reason() + ")", false);
                writeHttpResponse(out, 403, mapper.writeValueAsString(Map.of(
                        "accepted", false,
                        "reason", outcome.reason()
                )));
                stopImmediately();
                return;
            }

            byte[] hmacKeyCopy = outcome.hmacKeyCopy();
            try {
                String json = mapper.writeValueAsString(Map.of(
                        "accepted", true,
                        "bearerToken", outcome.bearerToken(),
                        "hmacKeyHex", HexFormat.of().formatHex(hmacKeyCopy),
                        "sessionExpiresAtMs", outcome.sessionExpiresAtMs(),
                        "serverProofHex", outcome.serverProofHex()
                ));
                writeHttpResponse(out, 200, json);
            } finally {
                Arrays.fill(hmacKeyCopy, (byte) 0);
            }
        } finally {
            closeQuietly(sslSocket);
        }
    }

    private void handleWebSocketStream(
            SSLSocket sslSocket,
            InputStream in,
            OutputStream out,
            X509Certificate clientCert,
            ParsedHttpRequest req,
            String remoteIp,
            int remotePort
    ) throws Exception {
        String authHeader = req.headers.getOrDefault("authorization", "");
        String bearer = authHeader.toLowerCase(Locale.ROOT).startsWith("bearer ")
                ? authHeader.substring(7).trim()
                : "";
        if (!sessionRegistry.isAuthorizedSession(clientCert, bearer)) {
            emitIntrusion(IntrusionEvent.IntrusionType.UNAUTHORIZED_TOUCH, remoteIp, remotePort,
                    "Unauthorized WebSocket attempt (invalid bearer token or unpinned cert)", false);
            writeHttpResponse(out, 403, "{\"error\":\"UNAUTHORIZED\"}");
            closeQuietly(sslSocket);
            return;
        }

        String wsKey = req.headers.get("sec-websocket-key");
        if (wsKey == null || wsKey.isBlank()) {
            emitIntrusion(IntrusionEvent.IntrusionType.UNAUTHORIZED_TOUCH, remoteIp, remotePort,
                    "Missing Sec-WebSocket-Key header", false);
            writeHttpResponse(out, 400, "{\"error\":\"BAD_WS_UPGRADE\"}");
            closeQuietly(sslSocket);
            return;
        }

        String acceptHash = Base64.getEncoder().encodeToString(
                MessageDigest.getInstance("SHA-1")
                        .digest((wsKey.trim() + WS_GUID).getBytes(StandardCharsets.UTF_8))
        );
        String upgradeResp = "HTTP/1.1 101 Switching Protocols\r\n"
                + "Upgrade: websocket\r\n"
                + "Connection: Upgrade\r\n"
                + "Sec-WebSocket-Accept: " + acceptHash + "\r\n\r\n";
        sslSocket.setKeepAlive(true);
        sslSocket.setSoTimeout(WS_READ_TIMEOUT_MS);

        WsClientConnection previous = this.activeWsConnection;
        WsClientConnection current = new WsClientConnection(sslSocket, out);
        this.activeWsConnection = current;
        if (previous != null) {
            previous.closeQuietly();
        }
        sessionRegistry.recordHeartbeat();

        // Emit Full Paranoia confirmation ONCE when a newly paired session attaches (never spam on Wi-Fi auto-reconnects)
        long gen = sessionRegistry.getActiveGeneration();
        if (gen > 0 && lastAlertedGeneration.getAndSet(gen) != gen) {
            String deviceLabel = sessionRegistry.getActiveSessionSnapshot()
                    .map(SessionStateRegistry.ActiveSessionSnapshot::deviceName)
                    .orElse("Paired-Android");
            emitIntrusion(
                    IntrusionEvent.IntrusionType.AUTHENTICATED_DEVICE_CONNECT,
                    remoteIp,
                    remotePort,
                    "Doğrulanmış cihaz bağlandı: " + deviceLabel,
                    true
            );
        }

        // All post-authentication I/O is isolated so normal mobile Wi-Fi disconnects NEVER trigger TLS_HANDSHAKE_FAILED
        try {
            out.write(upgradeResp.getBytes(StandardCharsets.UTF_8));
            out.flush();
            flushPendingTaskAlertIfPresent(current);
            readWebSocketLoop(current, in, remoteIp, remotePort);
        } catch (IOException ignored) {
            // Paired phone closed or roamed Wi-Fi; keep session active so phone can auto-reconnect seamlessly
        } finally {
            if (this.activeWsConnection == current) {
                this.activeWsConnection = null;
            }
            current.closeQuietly();
        }
    }

    private void flushPendingTaskAlertIfPresent(WsClientConnection conn) {
        PendingTaskAlert pending = this.pendingTaskAlert;
        if (pending == null) {
            return;
        }
        long now = System.currentTimeMillis();
        if ((now - pending.createdAtMs()) > PENDING_TASK_BUFFER_TTL_MS) {
            this.pendingTaskAlert = null;
            return;
        }
        Optional<byte[]> hmacKeyOpt = sessionRegistry.getSessionHmacKeyCopy();
        if (hmacKeyOpt.isEmpty()) {
            return;
        }
        byte[] hmacKey = hmacKeyOpt.get();
        try {
            SignedEnvelope env = crypto.signEnvelopeAt(
                    hmacKey,
                    "TASK_COMPLETED",
                    pending.payloadJson(),
                    pending.eventId(),
                    now
            );
            if (conn.sendTextFrame(mapper.writeValueAsString(env))) {
                this.pendingTaskAlert = null;
            }
        } catch (Exception ignored) {
        } finally {
            Arrays.fill(hmacKey, (byte) 0);
        }
    }

    private void readWebSocketLoop(
            WsClientConnection conn,
            InputStream in,
            String remoteIp,
            int remotePort
    ) throws IOException {
        while (conn.isOpen() && isListening()) {
            WsFrame frame = readClientWsFrame(in);
            if (frame == null || frame.opcode == 0x8) {
                return;
            }
            if (frame.opcode == 0x9) {
                sessionRegistry.recordHeartbeat();
                conn.sendPongFrame(frame.payload);
                continue;
            }
            if (frame.opcode == 0xA) {
                sessionRegistry.recordHeartbeat();
                continue;
            }
            if (frame.opcode != 0x1) {
                continue;
            }

            Optional<byte[]> hmacKeyOpt = sessionRegistry.getSessionHmacKeyCopy();
            if (hmacKeyOpt.isEmpty()) {
                return;
            }
            byte[] hmacKey = hmacKeyOpt.get();
            try {
                String jsonText = new String(frame.payload, StandardCharsets.UTF_8);
                SignedEnvelope env = mapper.readValue(jsonText, SignedEnvelope.class);
                if (!crypto.verifyEnvelope(hmacKey, env)) {
                    emitIntrusion(IntrusionEvent.IntrusionType.REPLAY_OR_TOKEN_VIOLATION, remoteIp, remotePort,
                            "Invalid HMAC or replayed WebSocket frame: " + env.type(), false);
                    return;
                }
                sessionRegistry.recordHeartbeat();
                if ("HEARTBEAT".equals(env.type())) {
                    SignedEnvelope ack = crypto.signEnvelope(hmacKey, "HEARTBEAT_ACK", "{}");
                    conn.sendTextFrame(mapper.writeValueAsString(ack));
                } else if ("TASK_ACK".equals(env.type())) {
                    PendingTaskAlert pending = this.pendingTaskAlert;
                    if (pending != null) {
                        JsonNode ackNode = mapper.readTree(env.payloadJson());
                        if (pending.eventId().equals(ackNode.path("ackedEventId").asText(""))) {
                            this.pendingTaskAlert = null;
                        }
                    }
                } else if ("NUCLEAR_TEARDOWN".equals(env.type())) {
                    Runnable cb = this.onRemoteNuclearTeardown;
                    if (cb != null) {
                        cb.run();
                    }
                    stopImmediately();
                    return;
                }
            } finally {
                Arrays.fill(hmacKey, (byte) 0);
            }
        }
    }

    private SSLContext createServerSslContext(EphemeralKeyMaterialService.EphemeralCertBundle serverCert) throws Exception {
        KeyStore ks = KeyStore.getInstance("PKCS12");
        ks.load(null, null);
        ks.setKeyEntry("server", serverCert.keyPair().getPrivate(), new char[0],
                new X509Certificate[]{serverCert.certificate()});
        KeyManagerFactory kmf = KeyManagerFactory.getInstance(KeyManagerFactory.getDefaultAlgorithm());
        kmf.init(ks, new char[0]);

        TrustManager dynamicClientVerifier = new X509TrustManager() {
            @Override
            public void checkClientTrusted(X509Certificate[] chain, String authType) throws CertificateException {
                if (chain == null || chain.length == 0 || chain[0] == null) {
                    throw new CertificateException("Empty client certificate chain");
                }
                X509Certificate leaf = chain[0];
                leaf.checkValidity();
                SessionStateRegistry.State st = sessionRegistry.getState();
                if (st == SessionStateRegistry.State.PAIRING_WINDOW) {
                    try {
                        leaf.verify(leaf.getPublicKey());
                    } catch (Exception e) {
                        throw new CertificateException("Invalid self-signed pairing client cert", e);
                    }
                } else if (st == SessionStateRegistry.State.ACTIVE_SESSION) {
                    if (!sessionRegistry.isPinnedClientCertificate(leaf)) {
                        throw new CertificateException("Client certificate is NOT pinned for active session");
                    }
                } else {
                    throw new CertificateException("Server session state is CLOSED");
                }
            }

            @Override
            public void checkServerTrusted(X509Certificate[] chain, String authType) throws CertificateException {
                throw new CertificateException("Server does not act as TLS client");
            }

            @Override
            public X509Certificate[] getAcceptedIssuers() {
                return new X509Certificate[0];
            }
        };

        SSLContext ctx = SSLContext.getInstance("TLSv1.3");
        ctx.init(kmf.getKeyManagers(), new TrustManager[]{dynamicClientVerifier}, new SecureRandom());
        return ctx;
    }

    private void emitIntrusion(
            IntrusionEvent.IntrusionType type,
            String remoteIp,
            int remotePort,
            String detail,
            boolean authorized
    ) {
        Optional<NetworkFingerprint> netOpt = networkService.getApprovedNetwork()
                .or(networkService::getCachedSnapshot)
                .or(networkService::readCurrentNetwork);
        String profile = netOpt.map(NetworkFingerprint::profileName).orElse("UNKNOWN");
        String mac = netOpt.map(NetworkFingerprint::gatewayMac).orElse("UNKNOWN");
        IntrusionEvent event = new IntrusionEvent(
                type, remoteIp, remotePort, profile, mac, Instant.now(), detail, authorized
        );
        for (Consumer<IntrusionEvent> listener : intrusionListeners) {
            try {
                listener.accept(event);
            } catch (Exception ignored) {}
        }
    }

    private static X509Certificate extractPeerCertificate(SSLSocket sslSocket) {
        try {
            Certificate[] certs = sslSocket.getSession().getPeerCertificates();
            if (certs != null && certs.length > 0 && certs[0] instanceof X509Certificate x509) {
                return x509;
            }
            return null;
        } catch (SSLPeerUnverifiedException e) {
            return null;
        }
    }

    private record ParsedHttpRequest(String method, String path, Map<String, String> headers, byte[] bodyBytes) {}

    private static ParsedHttpRequest readHttpRequest(InputStream in) throws IOException {
        ByteArrayOutputStream headerBuf = new ByteArrayOutputStream();
        int matchState = 0;
        while (headerBuf.size() < MAX_HTTP_HEADER_BYTES) {
            int b = in.read();
            if (b == -1) {
                return null;
            }
            headerBuf.write(b);
            if ((matchState == 0 && b == '\r') || (matchState == 2 && b == '\r')) {
                matchState++;
            } else if ((matchState == 1 && b == '\n') || (matchState == 3 && b == '\n')) {
                matchState++;
                if (matchState == 4) {
                    break;
                }
            } else {
                matchState = (b == '\r') ? 1 : 0;
            }
        }
        if (matchState != 4) {
            return null;
        }
        String rawHeaders = headerBuf.toString(StandardCharsets.UTF_8);
        String[] lines = rawHeaders.split("\r\n");
        if (lines.length == 0 || lines[0].isBlank()) {
            return null;
        }
        String[] requestLine = lines[0].split(" ");
        if (requestLine.length < 2) {
            return null;
        }
        Map<String, String> headers = new HashMap<>();
        for (int i = 1; i < lines.length; i++) {
            int idx = lines[i].indexOf(':');
            if (idx > 0) {
                headers.put(
                        lines[i].substring(0, idx).trim().toLowerCase(Locale.ROOT),
                        lines[i].substring(idx + 1).trim()
                );
            }
        }
        int contentLength = 0;
        if (headers.containsKey("content-length")) {
            contentLength = Integer.parseInt(headers.get("content-length"));
            if (contentLength < 0 || contentLength > MAX_HTTP_BODY_BYTES) {
                throw new IOException("Invalid HTTP Content-Length");
            }
        }
        byte[] body = contentLength > 0 ? in.readNBytes(contentLength) : new byte[0];
        if (body.length != contentLength) {
            throw new EOFException("Incomplete HTTP request body");
        }
        return new ParsedHttpRequest(requestLine[0], requestLine[1], headers, body);
    }

    private static void writeHttpResponse(OutputStream out, int status, String jsonBody) throws IOException {
        byte[] bodyBytes = jsonBody.getBytes(StandardCharsets.UTF_8);
        String statusText = status == 200 ? "OK" : (status == 400 ? "Bad Request" : "Forbidden");
        String header = "HTTP/1.1 " + status + " " + statusText + "\r\n"
                + "Content-Type: application/json; charset=utf-8\r\n"
                + "Content-Length: " + bodyBytes.length + "\r\n"
                + "Connection: close\r\n\r\n";
        out.write(header.getBytes(StandardCharsets.UTF_8));
        out.write(bodyBytes);
        out.flush();
    }

    private record WsFrame(int opcode, byte[] payload) {}

    private static WsFrame readClientWsFrame(InputStream in) throws IOException {
        int b0 = in.read();
        if (b0 == -1) {
            return null;
        }
        int b1 = in.read();
        if (b1 == -1) {
            throw new EOFException("Truncated WebSocket frame");
        }
        int opcode = b0 & 0x0F;
        boolean masked = (b1 & 0x80) != 0;
        long len = b1 & 0x7F;
        if (len == 126) {
            byte[] ext = in.readNBytes(2);
            if (ext.length != 2) {
                throw new EOFException("Truncated 16-bit WebSocket frame length");
            }
            len = ((ext[0] & 0xFF) << 8) | (ext[1] & 0xFF);
        } else if (len == 127) {
            byte[] ext = in.readNBytes(8);
            if (ext.length != 8) {
                throw new EOFException("Truncated 64-bit WebSocket frame length");
            }
            len = 0;
            for (int i = 0; i < 8; i++) {
                len = (len << 8) | (ext[i] & 0xFF);
            }
        }
        if (len < 0 || len > MAX_WS_FRAME_BYTES) {
            throw new IOException("WebSocket frame exceeds max allowed size");
        }
        byte[] maskKey = null;
        if (masked) {
            maskKey = in.readNBytes(4);
            if (maskKey.length != 4) {
                throw new EOFException("Truncated WebSocket mask key");
            }
        }
        byte[] payload = in.readNBytes((int) len);
        if (payload.length != (int) len) {
            throw new EOFException("Incomplete WebSocket payload");
        }
        if (masked && maskKey != null) {
            for (int i = 0; i < payload.length; i++) {
                payload[i] = (byte) (payload[i] ^ maskKey[i % 4]);
            }
        }
        return new WsFrame(opcode, payload);
    }

    private static final class WsClientConnection {
        private final SSLSocket socket;
        private final OutputStream out;

        WsClientConnection(SSLSocket socket, OutputStream out) {
            this.socket = socket;
            this.out = out;
        }

        synchronized boolean sendTextFrame(String text) {
            return sendFrame(0x81, text.getBytes(StandardCharsets.UTF_8));
        }

        synchronized void sendPingFrame(byte[] payload) {
            sendFrame(0x89, payload == null ? new byte[0] : payload);
        }

        synchronized void sendPongFrame(byte[] payload) {
            sendFrame(0x8A, payload == null ? new byte[0] : payload);
        }

        synchronized void sendCloseFrame() {
            sendFrame(0x88, new byte[0]);
        }

        private synchronized boolean sendFrame(int firstByte, byte[] payload) {
            if (!isOpen() || payload == null || payload.length > MAX_WS_FRAME_BYTES) {
                return false;
            }
            try {
                out.write(firstByte);
                if (payload.length < 126) {
                    out.write(payload.length);
                } else {
                    out.write(126);
                    out.write((payload.length >> 8) & 0xFF);
                    out.write(payload.length & 0xFF);
                }
                out.write(payload);
                out.flush();
                return true;
            } catch (IOException e) {
                closeQuietly();
                return false;
            }
        }

        boolean isOpen() {
            return !socket.isClosed() && socket.isConnected();
        }

        void closeQuietly() {
            DynamicLanTlsServer.closeQuietly(socket);
        }
    }

    private static void closeQuietly(Socket s) {
        if (s != null) {
            try {
                s.close();
            } catch (IOException ignored) {}
        }
    }
}
