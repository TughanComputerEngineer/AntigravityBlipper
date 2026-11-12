package com.antigravity.blipper.desktop.crypto;

import com.antigravity.blipper.desktop.security.SecurityAuditLogger;
import com.antigravity.blipper.desktop.security.SessionStateRegistry;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Duration;
import java.util.Arrays;
import java.util.List;
import java.util.UUID;

import static org.junit.jupiter.api.Assertions.*;

class EphemeralSecurityCoreTest {

    @Test
    void pairingProofBindsBothCertificateFingerprintsAndRejectsMitm() {
        var svc = new EphemeralKeyMaterialService();
        var server = svc.generateEphemeralEcCert("Blipper-Desktop");
        var client = svc.generateEphemeralEcCert("Blipper-Android");
        var mitm = svc.generateEphemeralEcCert("Evil-Proxy");
        char[] pin = "849271".toCharArray();
        long now = System.currentTimeMillis();

        String proof = svc.computePairingProofHex(pin, server.sha256Hex(), client.sha256Hex(), now, "nonce-1");

        assertTrue(svc.verifyPairingProof(pin, server.sha256Hex(), client.sha256Hex(), now, "nonce-1", proof));
        assertFalse(svc.verifyPairingProof(pin, mitm.sha256Hex(), client.sha256Hex(), now, "nonce-1", proof));
        assertFalse(svc.verifyPairingProof(pin, server.sha256Hex(), mitm.sha256Hex(), now, "nonce-1", proof));
        assertFalse(svc.verifyPairingProof("000000".toCharArray(), server.sha256Hex(), client.sha256Hex(), now, "nonce-1", proof));
    }

    @Test
    void envelopeVerifierRejectsReplayTamperingAndStaleTimestamp() {
        var svc = new EphemeralKeyMaterialService();
        byte[] key = new byte[32];
        Arrays.fill(key, (byte) 7);

        SignedEnvelope env = svc.signEnvelope(key, "TASK_COMPLETED", "{\"title\":\"Carbon\"}");
        assertTrue(svc.verifyEnvelope(key, env));
        // Second verification of exact same eventId must fail (anti-replay)
        assertFalse(svc.verifyEnvelope(key, env));

        // Tampered payload with fresh eventId must fail HMAC
        SignedEnvelope tampered = new SignedEnvelope(
                "TASK_COMPLETED",
                UUID.randomUUID().toString(),
                System.currentTimeMillis(),
                "{\"title\":\"Hacked\"}",
                env.hmacHex()
        );
        assertFalse(svc.verifyEnvelope(key, tampered));

        // Stale timestamp (> 30s old) must fail even with valid HMAC
        long staleTs = System.currentTimeMillis() - 60_000L;
        SignedEnvelope stale = svc.signEnvelopeAt(key, "TASK_COMPLETED", "{}", UUID.randomUUID().toString(), staleTs);
        assertFalse(svc.verifyEnvelope(key, stale));
    }

    @Test
    void sessionRegistryAbortsImmediatelyOnWrongPinEnforcesTtlAndZeroizesSecrets() throws Exception {
        var crypto = new EphemeralKeyMaterialService();
        var registry = new SessionStateRegistry(crypto);
        var serverCert = crypto.generateEphemeralEcCert("Blipper-Desktop");
        var clientCert = crypto.generateEphemeralEcCert("Blipper-Android");

        // Wrong PIN aborts window immediately
        var challenge1 = registry.openPairingWindow(6, Duration.ofHours(2), serverCert);
        assertEquals(6, challenge1.pinCode().length());
        long now = System.currentTimeMillis();
        var failedOutcome = registry.attemptPairing(
                clientCert.certificate(), "Galaxy-S24", now, "n-bad", "deadbeef");
        assertFalse(failedOutcome.accepted());
        assertEquals(SessionStateRegistry.State.CLOSED, registry.getState());

        // Valid PIN transitions to ACTIVE_SESSION and pins exact client cert + bearer token
        var challenge2 = registry.openPairingWindow(6, Duration.ofMillis(450), serverCert);
        long pairTs = System.currentTimeMillis();
        String validProof = crypto.computePairingProofHex(
                challenge2.pinCode().toCharArray(),
                serverCert.sha256Hex(),
                clientCert.sha256Hex(),
                pairTs,
                "n-good"
        );
        var okOutcome = registry.attemptPairing(
                clientCert.certificate(), "Galaxy-S24", pairTs, "n-good", validProof);
        assertTrue(okOutcome.accepted());
        assertNotNull(okOutcome.bearerToken());
        assertEquals(32, okOutcome.hmacKeyCopy().length);
        assertTrue(registry.isAuthorizedSession(clientCert.certificate(), okOutcome.bearerToken()));

        // Different client cert with stolen bearer token must be rejected!
        var rogueCert = crypto.generateEphemeralEcCert("Rogue-Phone");
        assertFalse(registry.isAuthorizedSession(rogueCert.certificate(), okOutcome.bearerToken()));

        // Wait for 450ms TTL to expire -> session automatically revokes and closes!
        Thread.sleep(500L);
        assertFalse(registry.isAuthorizedSession(clientCert.certificate(), okOutcome.bearerToken()));
        assertEquals(SessionStateRegistry.State.CLOSED, registry.getState());

        // Re-open pairing and verify explicit wipeAll() zeroizes immediately
        registry.openPairingWindow(6, Duration.ZERO, serverCert);
        assertTrue(registry.wipeAll());
        assertEquals(SessionStateRegistry.State.CLOSED, registry.getState());
    }

    @Test
    void auditLoggerMaintainsValidSha256HashChainAndDetectsTampering(@TempDir Path tempDir) throws Exception {
        Path auditFile = tempDir.resolve("Tuğhan").resolve("security-audit.jsonl");
        var logger = new SecurityAuditLogger(auditFile);

        var e1 = logger.appendTamperEvidentLog(
                "UNAUTHORIZED_TOUCH", "192.168.1.47", 54120, "HomeWiFi", "AA-BB-CC-11-22-33", "TLS rejected");
        var e2 = logger.appendTamperEvidentLog(
                "INTRUSION_EMERGENCY_SHUTDOWN", "192.168.1.47", 54120, "HomeWiFi", "AA-BB-CC-11-22-33", "Port closed by user");

        assertNotEquals(e1.entryHash(), e2.entryHash());
        assertEquals(e1.entryHash(), e2.prevHash());
        assertTrue(logger.verifyChainIntegrity());

        // Tamper with line 1 on disk -> verifyChainIntegrity must return false!
        List<String> lines = Files.readAllLines(auditFile, StandardCharsets.UTF_8);
        lines.set(0, lines.get(0).replace("192.168.1.47", "192.168.1.99"));
        Files.write(auditFile, lines, StandardCharsets.UTF_8);
        assertFalse(logger.verifyChainIntegrity());
    }
}
