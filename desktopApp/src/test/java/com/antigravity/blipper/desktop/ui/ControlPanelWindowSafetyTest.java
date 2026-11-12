package com.antigravity.blipper.desktop.ui;

import com.antigravity.blipper.desktop.agy.AntigravityConversationReader;
import com.antigravity.blipper.desktop.agy.LocalHookController;
import com.antigravity.blipper.desktop.crypto.EphemeralKeyMaterialService;
import com.antigravity.blipper.desktop.network.DynamicLanTlsServer;
import com.antigravity.blipper.desktop.network.IntrusionEvent;
import com.antigravity.blipper.desktop.network.NuclearTeardownCoordinator;
import com.antigravity.blipper.desktop.network.WindowsNetworkFingerprintService;
import com.antigravity.blipper.desktop.security.SecurityAuditLogger;
import com.antigravity.blipper.desktop.security.SessionStateRegistry;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import javax.swing.SwingUtilities;
import java.awt.GraphicsEnvironment;
import java.nio.file.Path;
import java.time.Instant;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicReference;

import static org.junit.jupiter.api.Assertions.*;

class ControlPanelWindowSafetyTest {

    @Test
    void controlPanelNeverRunsNetworkProbeOnEdtAndMarshalsNuclearTeardownOntoEdt(@TempDir Path tempDir) throws Exception {
        if (GraphicsEnvironment.isHeadless()) {
            return;
        }
        AtomicBoolean probeRanOnEdt = new AtomicBoolean(false);
        var crypto = new EphemeralKeyMaterialService();
        var registry = new SessionStateRegistry(crypto);
        var audit = new SecurityAuditLogger(tempDir.resolve("audit.jsonl"));
        var netSvc = new WindowsNetworkFingerprintService(() -> {
            if (SwingUtilities.isEventDispatchThread()) {
                probeRanOnEdt.set(true);
            }
            return "HomeFiber|Wi-Fi|192.168.1.25|192.168.1.1|AA-BB-CC-11-22-33";
        });
        var lanServer = new DynamicLanTlsServer(crypto, registry, netSvc);
        var coordinator = new NuclearTeardownCoordinator(registry, audit, netSvc, lanServer);
        var hookController = new LocalHookController(
                new AntigravityConversationReader(tempDir.resolve("none.db")),
                lanServer
        );

        AtomicReference<ControlPanelWindow> windowRef = new AtomicReference<>();
        SwingUtilities.invokeAndWait(() -> {
            ControlPanelWindow win = new ControlPanelWindow(
                    netSvc, registry, lanServer, coordinator, hookController, 0, 0
            );
            windowRef.set(win);
        });

        ControlPanelWindow window = windowRef.get();
        try {
            assertFalse(probeRanOnEdt.get(), "ControlPanelWindow must NEVER execute network probe synchronously on Swing EDT");

            AtomicBoolean updatedOnEdt = new AtomicBoolean(false);
            CountDownLatch labelUpdated = new CountDownLatch(1);
            SwingUtilities.invokeAndWait(() -> {
                window.getStatusBadgeLabelForTest().setText("TEMP_NON_DEFAULT");
                window.getStatusBadgeLabelForTest().addPropertyChangeListener("text", evt -> {
                    updatedOnEdt.set(SwingUtilities.isEventDispatchThread());
                    labelUpdated.countDown();
                });
            });

            // Invoke onNuclearTeardown from a non-EDT background thread (as watchdog / remote WS teardown does)
            Thread bg = new Thread(() -> window.onNuclearTeardown("REMOTE_PHONE_TEARDOWN"), "test-bg-teardown");
            bg.start();
            bg.join(2000L);

            assertTrue(labelUpdated.await(3, TimeUnit.SECONDS), "Status badge must update after nuclear teardown");
            assertTrue(updatedOnEdt.get(), "ControlPanelWindow.onNuclearTeardown must marshal Swing mutations onto the EDT");
        } finally {
            SwingUtilities.invokeAndWait(window::dispose);
        }
    }

    @Test
    void alertAndBannerStringsContainZeroSupplementaryEmojiBoxes() {
        IntrusionEvent unauth = new IntrusionEvent(
                IntrusionEvent.IntrusionType.TLS_HANDSHAKE_FAILED,
                "192.168.1.77", 51234, "SUPERONLINE_Wi-Fi", "CC-29-BD-29-00-B0",
                Instant.now(), "Rejected", false
        );
        IntrusionEvent auth = new IntrusionEvent(
                IntrusionEvent.IntrusionType.AUTHENTICATED_DEVICE_CONNECT,
                "192.168.1.3", 45060, "SUPERONLINE_Wi-Fi", "CC-29-BD-29-00-B0",
                Instant.now(), "Connected", true
        );
        assertNoSurrogates(IntrusionAlertWindow.KILL_BUTTON_LABEL);
        assertNoSurrogates(IntrusionAlertWindow.buildAlertViewModel(unauth).headline());
        assertNoSurrogates(IntrusionAlertWindow.buildAlertViewModel(auth).headline());
        assertNoSurrogates(TaskCompletedBannerWindow.formatDisplayBanner("ANTIGRAVITY: Test: Hazır"));
    }

    private static void assertNoSurrogates(String text) {
        for (int i = 0; i < text.length(); i++) {
            assertFalse(Character.isSurrogate(text.charAt(i)),
                    "Swing Segoe UI text must not contain supplementary plane emoji that renders as '□': " + text);
        }
    }
}
