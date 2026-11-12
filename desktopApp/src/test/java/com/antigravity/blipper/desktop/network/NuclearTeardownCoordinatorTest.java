package com.antigravity.blipper.desktop.network;

import com.antigravity.blipper.desktop.crypto.EphemeralKeyMaterialService;
import com.antigravity.blipper.desktop.security.SecurityAuditLogger;
import com.antigravity.blipper.desktop.security.SessionStateRegistry;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.nio.file.Path;
import java.time.Duration;
import java.time.Instant;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.Callable;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicReference;

import static org.junit.jupiter.api.Assertions.*;

class NuclearTeardownCoordinatorTest {

    @Test
    void concurrentNuclearTeardownExecutesIdempotentlyPerGenerationAndClosesPort(@TempDir Path tempDir) throws Exception {
        var crypto = new EphemeralKeyMaterialService();
        var registry = new SessionStateRegistry(crypto);
        var audit = new SecurityAuditLogger(tempDir.resolve("audit.jsonl"));
        var netSvc = new WindowsNetworkFingerprintService(
                () -> "HomeFiber|Wi-Fi|192.168.1.25|192.168.1.1|AA-BB-CC-11-22-33"
        );
        var server = new DynamicLanTlsServer(crypto, registry, netSvc);
        var coordinator = new NuclearTeardownCoordinator(registry, audit, netSvc, server);

        netSvc.approveNetworkForCurrentSession(netSvc.readCurrentNetwork().orElseThrow());
        server.startForPairing(0, 0, 6, Duration.ofHours(1));
        assertTrue(server.isListening());

        AtomicInteger listenerNotifications = new AtomicInteger(0);
        coordinator.addTeardownListener(reason -> listenerNotifications.incrementAndGet());

        // Fire 6 concurrent teardown calls (simulating simultaneous Phone teardown + PC button + watchdog)
        var pool = Executors.newFixedThreadPool(6);
        List<Callable<Void>> tasks = new ArrayList<>();
        for (int i = 0; i < 6; i++) {
            int idx = i;
            tasks.add(() -> {
                coordinator.executeNuclearTeardown("CONCURRENT_" + idx);
                return null;
            });
        }
        for (Future<Void> f : pool.invokeAll(tasks)) {
            f.get();
        }
        pool.shutdownNow();

        assertFalse(server.isListening());
        assertEquals(SessionStateRegistry.State.CLOSED, registry.getState());
        assertTrue(netSvc.getApprovedNetwork().isEmpty());
        assertEquals(1, listenerNotifications.get(), "Teardown notification must fire once per active session generation");
    }

    @Test
    void watchdogAutoNukesPortWhenNetworkChangesToCafeWifi(@TempDir Path tempDir) {
        var crypto = new EphemeralKeyMaterialService();
        var registry = new SessionStateRegistry(crypto);
        var audit = new SecurityAuditLogger(tempDir.resolve("audit.jsonl"));
        AtomicReference<String> probe = new AtomicReference<>(
                "HomeFiber|Wi-Fi|192.168.1.25|192.168.1.1|AA-BB-CC-11-22-33"
        );
        var netSvc = new WindowsNetworkFingerprintService(probe::get);
        var server = new DynamicLanTlsServer(crypto, registry, netSvc);
        var coordinator = new NuclearTeardownCoordinator(registry, audit, netSvc, server);

        netSvc.approveNetworkForCurrentSession(netSvc.readCurrentNetwork().orElseThrow());
        server.startForPairing(0, 0, 6, Duration.ofHours(2));
        assertTrue(server.isListening());

        // Switch to Café Wi-Fi -> single watchdog tick must nuke port, keys, and approved network!
        probe.set("CafePublicWiFi|Wi-Fi|10.20.0.8|10.20.0.1|DE-AD-00-11-22-33");
        coordinator.runWatchdogTick();

        assertFalse(server.isListening());
        assertEquals(SessionStateRegistry.State.CLOSED, registry.getState());
        assertFalse(netSvc.isCurrentNetworkTrusted());
    }

    @Test
    void logIntrusionAndShutdownPortAppendsForensicAuditEntryAndClosesPort(@TempDir Path tempDir) {
        var crypto = new EphemeralKeyMaterialService();
        var registry = new SessionStateRegistry(crypto);
        var audit = new SecurityAuditLogger(tempDir.resolve("security-audit.jsonl"));
        var netSvc = new WindowsNetworkFingerprintService(
                () -> "HomeFiber|Wi-Fi|192.168.1.25|192.168.1.1|AA-BB-CC-11-22-33"
        );
        var server = new DynamicLanTlsServer(crypto, registry, netSvc);
        var coordinator = new NuclearTeardownCoordinator(registry, audit, netSvc, server);

        netSvc.approveNetworkForCurrentSession(netSvc.readCurrentNetwork().orElseThrow());
        server.startForPairing(0, 0, 6, Duration.ofHours(1));
        assertTrue(server.isListening());

        IntrusionEvent intrusion = new IntrusionEvent(
                IntrusionEvent.IntrusionType.UNAUTHORIZED_TOUCH,
                "192.168.1.77",
                60123,
                "HomeFiber",
                "AA-BB-CC-11-22-33",
                Instant.now(),
                "Port scan detected",
                false
        );

        SecurityAuditLogger.AuditEntry logged = coordinator.logIntrusionAndShutdownPort(intrusion);
        assertEquals("INTRUSION_EMERGENCY_SHUTDOWN:UNAUTHORIZED_TOUCH", logged.eventType());
        assertEquals("192.168.1.77", logged.remoteIp());
        assertFalse(server.isListening());
        assertEquals(SessionStateRegistry.State.CLOSED, registry.getState());
        assertTrue(audit.verifyChainIntegrity());
    }

    @Test
    void watchdogKeepsPairedSessionAliveAcrossPhoneDozeSilenceUntilTtlExpires(@TempDir Path tempDir) throws Exception {
        var crypto = new EphemeralKeyMaterialService();
        var registry = new SessionStateRegistry(crypto);
        var audit = new SecurityAuditLogger(tempDir.resolve("audit-doze.jsonl"));
        var netSvc = new WindowsNetworkFingerprintService(
                () -> "BLIPPER_NET|HomeFiber|Wi-Fi|192.168.1.4|192.168.1.1|CC-29-BD-29-00-B0"
        );
        var server = new DynamicLanTlsServer(crypto, registry, netSvc);
        var coordinator = new NuclearTeardownCoordinator(registry, audit, netSvc, server);

        netSvc.approveNetworkForCurrentSession(netSvc.readCurrentNetwork().orElseThrow());
        var startInfo = server.startForPairing(0, 0, 6, Duration.ofHours(4));
        var clientCert = crypto.generateEphemeralEcCert("Samsung-A73");
        long now = System.currentTimeMillis();
        String proof = crypto.computePairingProofHex(
                startInfo.pinCode().toCharArray(),
                startInfo.serverCertSha256Hex(),
                clientCert.sha256Hex(),
                now,
                "nonce-doze"
        );
        var outcome = registry.attemptPairing(clientCert.certificate(), "Samsung A73", now, "nonce-doze", proof);
        assertTrue(outcome.accepted());
        assertEquals(SessionStateRegistry.State.ACTIVE_SESSION, registry.getState());

        // Simulate > 2 minutes passing without phone-originated heartbeats (Samsung screen-off Doze)
        registry.setLastHeartbeatForTest(now - 150_000L);
        coordinator.runWatchdogTick();

        assertTrue(server.isListening(), "LAN server must remain open for paired phone during authorized 4h TTL");
        assertEquals(SessionStateRegistry.State.ACTIVE_SESSION, registry.getState(),
                "Watchdog must NOT nuke paired session after 30-60s of phone screen-off Doze");
        server.stopImmediately();
    }
}
