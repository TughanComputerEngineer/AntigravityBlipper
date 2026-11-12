package com.antigravity.blipper.desktop.security;

import com.antigravity.blipper.desktop.crypto.EphemeralKeyMaterialService;
import org.springframework.stereotype.Component;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.cert.X509Certificate;
import java.time.Duration;
import java.util.Arrays;
import java.util.HexFormat;
import java.util.Locale;
import java.util.Optional;
import java.util.concurrent.atomic.AtomicLong;

@Component
public class SessionStateRegistry {

    public static final long PAIRING_WINDOW_MS = 60_000L;
    public static final long HEARTBEAT_DEADMAN_MS = 30_000L;

    public enum State {
        CLOSED,
        PAIRING_WINDOW,
        ACTIVE_SESSION
    }

    public record PairingChallenge(
            String pinCode,
            long expiresAtMs,
            String serverCertSha256Hex,
            long sessionGeneration
    ) {}

    public record PairingOutcome(
            boolean accepted,
            String reason,
            String bearerToken,
            byte[] hmacKeyCopy,
            long sessionExpiresAtMs,
            String serverProofHex
    ) {}

    public record ActiveSessionSnapshot(
            String deviceName,
            String pinnedClientCertSha256Hex,
            long sessionExpiresAtMs,
            boolean unlimited,
            long lastHeartbeatMs,
            long sessionGeneration
    ) {}

    private final EphemeralKeyMaterialService crypto;
    private final AtomicLong generationCounter = new AtomicLong(0);

    private State state = State.CLOSED;
    private char[] activePin;
    private long pairingExpiresAtMs;
    private Duration configuredTtl;
    private EphemeralKeyMaterialService.EphemeralCertBundle serverCert;
    private String pinnedClientCertSha256Hex;
    private String pairedDeviceName;
    private byte[] bearerTokenUtf8;
    private byte[] sessionHmacKey;
    private long sessionExpiresAtMs;
    private long lastHeartbeatMs;
    private long activeGeneration;

    public SessionStateRegistry(EphemeralKeyMaterialService crypto) {
        this.crypto = crypto;
    }

    public synchronized PairingChallenge openPairingWindow(
            int codeDigits,
            Duration ttl,
            EphemeralKeyMaterialService.EphemeralCertBundle freshServerCert
    ) {
        if (codeDigits < 6) {
            throw new IllegalArgumentException("Pairing code must be at least 6 digits");
        }
        wipeInternal();
        this.activeGeneration = generationCounter.incrementAndGet();
        this.activePin = crypto.generateNumericPin(codeDigits);
        this.pairingExpiresAtMs = System.currentTimeMillis() + PAIRING_WINDOW_MS;
        this.configuredTtl = ttl;
        this.serverCert = freshServerCert;
        this.state = State.PAIRING_WINDOW;
        return new PairingChallenge(
                new String(this.activePin),
                this.pairingExpiresAtMs,
                freshServerCert.sha256Hex(),
                this.activeGeneration
        );
    }

    public synchronized PairingOutcome attemptPairing(
            X509Certificate clientCert,
            String deviceName,
            long timestampMs,
            String nonce,
            String proofHex
    ) {
        long now = System.currentTimeMillis();
        if (state != State.PAIRING_WINDOW || serverCert == null || activePin == null) {
            wipeInternal();
            return new PairingOutcome(false, "NO_ACTIVE_PAIRING_WINDOW", null, null, 0L, null);
        }
        if (now > pairingExpiresAtMs) {
            wipeInternal();
            return new PairingOutcome(false, "PAIRING_WINDOW_EXPIRED", null, null, 0L, null);
        }
        if (clientCert == null) {
            wipeInternal();
            return new PairingOutcome(false, "MISSING_CLIENT_CERT", null, null, 0L, null);
        }

        String clientSha256 = crypto.computeCertSha256Hex(clientCert);
        boolean valid = crypto.verifyPairingProof(
                activePin,
                serverCert.sha256Hex(),
                clientSha256,
                timestampMs,
                nonce,
                proofHex
        );
        if (!valid) {
            // Immediate zero-tolerance abort on wrong PIN or MITM mismatch
            wipeInternal();
            return new PairingOutcome(false, "INVALID_PAIRING_PROOF", null, null, 0L, null);
        }

        String serverProofHex = crypto.computePairingProofHex(
                activePin,
                serverCert.sha256Hex(),
                clientSha256,
                timestampMs,
                nonce + ":SERVER_ACK"
        );

        Arrays.fill(activePin, '\0');
        activePin = null;

        long pairedAt = System.currentTimeMillis();
        String tokenHex = HexFormat.of().formatHex(crypto.randomBytes(32));
        this.bearerTokenUtf8 = tokenHex.getBytes(StandardCharsets.UTF_8);
        this.sessionHmacKey = crypto.randomBytes(32);
        this.pinnedClientCertSha256Hex = clientSha256.toLowerCase(Locale.ROOT);
        this.pairedDeviceName = (deviceName == null || deviceName.isBlank()) ? "Android-Device" : deviceName.trim();
        this.sessionExpiresAtMs = (configuredTtl == null || configuredTtl.isZero() || configuredTtl.isNegative())
                ? Long.MAX_VALUE
                : (pairedAt + configuredTtl.toMillis());
        this.lastHeartbeatMs = pairedAt;
        this.state = State.ACTIVE_SESSION;

        return new PairingOutcome(
                true,
                "PAIRED",
                tokenHex,
                Arrays.copyOf(this.sessionHmacKey, this.sessionHmacKey.length),
                this.sessionExpiresAtMs,
                serverProofHex
        );
    }

    public synchronized boolean isAuthorizedSession(X509Certificate clientCert, String candidateBearerToken) {
        if (state != State.ACTIVE_SESSION || clientCert == null || candidateBearerToken == null) {
            return false;
        }
        if (System.currentTimeMillis() >= sessionExpiresAtMs) {
            wipeInternal();
            return false;
        }
        String candidateCertHex = crypto.computeCertSha256Hex(clientCert).toLowerCase(Locale.ROOT);
        byte[] expectedCertBytes = pinnedClientCertSha256Hex.getBytes(StandardCharsets.UTF_8);
        byte[] candidateCertBytes = candidateCertHex.getBytes(StandardCharsets.UTF_8);
        byte[] candidateTokenBytes = candidateBearerToken.trim().getBytes(StandardCharsets.UTF_8);

        return MessageDigest.isEqual(expectedCertBytes, candidateCertBytes)
                && MessageDigest.isEqual(bearerTokenUtf8, candidateTokenBytes);
    }

    public synchronized boolean isPinnedClientCertificate(X509Certificate clientCert) {
        if (state != State.ACTIVE_SESSION || clientCert == null || pinnedClientCertSha256Hex == null) {
            return false;
        }
        if (System.currentTimeMillis() >= sessionExpiresAtMs) {
            wipeInternal();
            return false;
        }
        String candidateCertHex = crypto.computeCertSha256Hex(clientCert).toLowerCase(Locale.ROOT);
        return MessageDigest.isEqual(
                pinnedClientCertSha256Hex.getBytes(StandardCharsets.UTF_8),
                candidateCertHex.getBytes(StandardCharsets.UTF_8)
        );
    }

    public synchronized Optional<byte[]> getSessionHmacKeyCopy() {
        if (state != State.ACTIVE_SESSION || sessionHmacKey == null) {
            return Optional.empty();
        }
        return Optional.of(Arrays.copyOf(sessionHmacKey, sessionHmacKey.length));
    }

    public synchronized Optional<EphemeralKeyMaterialService.EphemeralCertBundle> getServerCert() {
        return Optional.ofNullable(serverCert);
    }

    public synchronized void recordHeartbeat() {
        if (state == State.ACTIVE_SESSION) {
            this.lastHeartbeatMs = System.currentTimeMillis();
        }
    }

    public synchronized boolean isPairingExpired(long nowMs) {
        return state == State.PAIRING_WINDOW && nowMs > pairingExpiresAtMs;
    }

    public synchronized boolean isSessionTtlExpired(long nowMs) {
        return state == State.ACTIVE_SESSION && nowMs >= sessionExpiresAtMs;
    }

    public synchronized boolean isHeartbeatExpired(long nowMs) {
        return state == State.ACTIVE_SESSION && (nowMs - lastHeartbeatMs) > HEARTBEAT_DEADMAN_MS;
    }

    public synchronized State getState() {
        return state;
    }

    public synchronized long getActiveGeneration() {
        return activeGeneration;
    }

    public synchronized long getPairingExpiresAtMs() {
        return state == State.PAIRING_WINDOW ? pairingExpiresAtMs : 0L;
    }

    public synchronized Optional<ActiveSessionSnapshot> getActiveSessionSnapshot() {
        if (state != State.ACTIVE_SESSION) {
            return Optional.empty();
        }
        return Optional.of(new ActiveSessionSnapshot(
                pairedDeviceName,
                pinnedClientCertSha256Hex,
                sessionExpiresAtMs,
                sessionExpiresAtMs == Long.MAX_VALUE,
                lastHeartbeatMs,
                activeGeneration
        ));
    }

    public synchronized boolean wipeAll() {
        boolean wasOpen = (state != State.CLOSED);
        wipeInternal();
        return wasOpen;
    }

    private void wipeInternal() {
        if (activePin != null) {
            Arrays.fill(activePin, '\0');
            activePin = null;
        }
        if (bearerTokenUtf8 != null) {
            Arrays.fill(bearerTokenUtf8, (byte) 0);
            bearerTokenUtf8 = null;
        }
        if (sessionHmacKey != null) {
            Arrays.fill(sessionHmacKey, (byte) 0);
            sessionHmacKey = null;
        }
        pairingExpiresAtMs = 0L;
        configuredTtl = null;
        serverCert = null;
        pinnedClientCertSha256Hex = null;
        pairedDeviceName = null;
        sessionExpiresAtMs = 0L;
        lastHeartbeatMs = 0L;
        state = State.CLOSED;
        crypto.clearReplayCache();
    }
}
