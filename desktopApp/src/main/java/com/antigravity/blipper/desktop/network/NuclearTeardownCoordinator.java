package com.antigravity.blipper.desktop.network;

import com.antigravity.blipper.desktop.security.SecurityAuditLogger;
import com.antigravity.blipper.desktop.security.SessionStateRegistry;
import jakarta.annotation.PreDestroy;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Service;

import java.util.List;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.concurrent.atomic.AtomicLong;
import java.util.function.Consumer;

@Service
public class NuclearTeardownCoordinator {

    private final SessionStateRegistry sessionRegistry;
    private final SecurityAuditLogger auditLogger;
    private final WindowsNetworkFingerprintService networkService;
    private final DynamicLanTlsServer lanServer;
    private final List<Consumer<String>> teardownListeners = new CopyOnWriteArrayList<>();
    private final Object teardownLock = new Object();
    private final AtomicLong lastNotifiedGeneration = new AtomicLong(-1L);
    private final Thread jvmShutdownHook;

    public NuclearTeardownCoordinator(
            SessionStateRegistry sessionRegistry,
            SecurityAuditLogger auditLogger,
            WindowsNetworkFingerprintService networkService,
            DynamicLanTlsServer lanServer
    ) {
        this.sessionRegistry = sessionRegistry;
        this.auditLogger = auditLogger;
        this.networkService = networkService;
        this.lanServer = lanServer;

        this.lanServer.setOnRemoteNuclearTeardown(
                () -> executeTeardownInternal("REMOTE_PHONE_TEARDOWN", false)
        );

        this.jvmShutdownHook = new Thread(
                () -> executeTeardownInternal("JVM_SHUTDOWN_HOOK", true),
                "blipper-nuclear-shutdown-hook"
        );
        try {
            Runtime.getRuntime().addShutdownHook(this.jvmShutdownHook);
        } catch (IllegalStateException ignored) {
            // JVM already shutting down
        }
    }

    public void executeNuclearTeardown(String reason) {
        executeTeardownInternal(reason, true);
    }

    public SecurityAuditLogger.AuditEntry logIntrusionAndShutdownPort(IntrusionEvent event) {
        String typeLabel = "INTRUSION_EMERGENCY_SHUTDOWN:"
                + (event == null || event.type() == null ? "UNKNOWN" : event.type().name());
        String ip = event == null ? "unknown" : event.remoteIp();
        int port = event == null ? 0 : event.remotePort();
        String profile = event == null ? "UNKNOWN" : event.networkProfile();
        String mac = event == null ? "UNKNOWN" : event.gatewayMac();
        String detail = event == null ? "Emergency shutdown triggered" : event.detail();

        SecurityAuditLogger.AuditEntry entry = auditLogger.appendTamperEvidentLog(
                typeLabel, ip, port, profile, mac, detail
        );
        executeTeardownInternal("INTRUSION_EMERGENCY_SHUTDOWN", true);
        return entry;
    }

    @Scheduled(fixedDelay = 4000L)
    public void runWatchdogTick() {
        boolean serverOpen = lanServer.isListening();
        SessionStateRegistry.State state = sessionRegistry.getState();
        if (!serverOpen && state == SessionStateRegistry.State.CLOSED) {
            return;
        }

        long now = System.currentTimeMillis();
        if (!networkService.isCurrentNetworkTrustedForWatchdog()) {
            auditLogger.appendTamperEvidentLog(
                    "NETWORK_DRIFT_AUTO_SHUTDOWN",
                    "local",
                    lanServer.getBoundPort(),
                    "UNTRUSTED_OR_CAFE_NETWORK",
                    "MISMATCH",
                    "Network changed away from approved home fingerprint; auto-wiping keys and closing port"
            );
            executeTeardownInternal("NETWORK_CHANGED_OR_UNTRUSTED", true);
            return;
        }
        if (sessionRegistry.isPairingExpired(now)) {
            executeTeardownInternal("PAIRING_60S_TIMEOUT", false);
            return;
        }
        if (sessionRegistry.isSessionTtlExpired(now)) {
            executeTeardownInternal("SESSION_TTL_EXPIRED", true);
        }
    }

    public void addTeardownListener(Consumer<String> listener) {
        if (listener != null) {
            teardownListeners.add(listener);
        }
    }

    @PreDestroy
    public void onDestroy() {
        executeTeardownInternal("SPRING_CONTEXT_SHUTDOWN", true);
        try {
            Runtime.getRuntime().removeShutdownHook(this.jvmShutdownHook);
        } catch (IllegalStateException | SecurityException ignored) {
            // JVM already in shutdown sequence
        }
    }

    private void executeTeardownInternal(String reason, boolean notifyRemotePeer) {
        boolean shouldNotifyListeners = false;
        synchronized (teardownLock) {
            long gen = sessionRegistry.getActiveGeneration();
            boolean wasListening = lanServer.isListening();
            boolean wasSessionOpen = sessionRegistry.getState() != SessionStateRegistry.State.CLOSED;

            if (notifyRemotePeer && wasListening) {
                lanServer.sendNuclearTeardownAndStop();
            } else {
                lanServer.stopImmediately();
            }

            sessionRegistry.wipeAll();
            networkService.clearApprovedNetwork();

            if ((wasListening || wasSessionOpen) && gen > 0 && lastNotifiedGeneration.get() != gen) {
                lastNotifiedGeneration.set(gen);
                shouldNotifyListeners = true;
            }
        }

        if (shouldNotifyListeners) {
            String safeReason = (reason == null || reason.isBlank()) ? "NUCLEAR_TEARDOWN" : reason;
            for (Consumer<String> listener : teardownListeners) {
                try {
                    listener.accept(safeReason);
                } catch (Exception ignored) {}
            }
        }
    }
}
