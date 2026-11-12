package com.antigravity.blipper.desktop.ui;

import com.antigravity.blipper.desktop.agy.AntigravityHookInstaller;
import com.antigravity.blipper.desktop.agy.LocalHookController;
import com.antigravity.blipper.desktop.network.DynamicLanTlsServer;
import com.antigravity.blipper.desktop.network.NuclearTeardownCoordinator;
import com.antigravity.blipper.desktop.network.WindowsNetworkFingerprintService;
import com.antigravity.blipper.desktop.security.SessionStateRegistry;
import com.formdev.flatlaf.themes.FlatMacDarkLaf;
import jakarta.annotation.PostConstruct;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

import javax.swing.SwingUtilities;
import java.awt.Color;
import java.awt.Graphics2D;
import java.awt.GraphicsEnvironment;
import java.awt.MenuItem;
import java.awt.PopupMenu;
import java.awt.RenderingHints;
import java.awt.SystemTray;
import java.awt.TrayIcon;
import java.awt.image.BufferedImage;

@Component
public class DesktopUiOrchestrator {

    private final boolean uiEnabled;
    private final boolean autoInstallHook;
    private final int lanPort;
    private final int udpPort;
    private final AntigravityHookInstaller hookInstaller;
    private final LocalHookController localHookController;
    private final WindowsNetworkFingerprintService networkService;
    private final SessionStateRegistry sessionRegistry;
    private final DynamicLanTlsServer lanServer;
    private final NuclearTeardownCoordinator teardownCoordinator;

    private volatile ControlPanelWindow controlPanelWindow;

    public DesktopUiOrchestrator(
            @Value("${blipper.ui.enabled:true}") boolean uiEnabled,
            @Value("${blipper.hook.auto-install:true}") boolean autoInstallHook,
            @Value("${blipper.lan.port:58443}") int lanPort,
            @Value("${blipper.lan.udp-discovery-port:58444}") int udpPort,
            AntigravityHookInstaller hookInstaller,
            LocalHookController localHookController,
            WindowsNetworkFingerprintService networkService,
            SessionStateRegistry sessionRegistry,
            DynamicLanTlsServer lanServer,
            NuclearTeardownCoordinator teardownCoordinator
    ) {
        this.uiEnabled = uiEnabled;
        this.autoInstallHook = autoInstallHook;
        this.lanPort = lanPort;
        this.udpPort = udpPort;
        this.hookInstaller = hookInstaller;
        this.localHookController = localHookController;
        this.networkService = networkService;
        this.sessionRegistry = sessionRegistry;
        this.lanServer = lanServer;
        this.teardownCoordinator = teardownCoordinator;
    }

    @PostConstruct
    public void initialize() {
        if (autoInstallHook) {
            hookInstaller.installOrUpdateGlobalStopHook();
        }

        localHookController.addTaskCompletedListener(
                summary -> TaskCompletedBannerWindow.showBanner(summary.formattedBannerText())
        );

        lanServer.addIntrusionListener(
                event -> IntrusionAlertWindow.showFullScreenAlert(
                        event,
                        teardownCoordinator::logIntrusionAndShutdownPort
                )
        );

        if (!uiEnabled || GraphicsEnvironment.isHeadless()) {
            return;
        }

        SwingUtilities.invokeLater(() -> {
            FlatMacDarkLaf.setup();
            ControlPanelWindow window = new ControlPanelWindow(
                    networkService,
                    sessionRegistry,
                    lanServer,
                    teardownCoordinator,
                    localHookController,
                    lanPort,
                    udpPort
            );
            this.controlPanelWindow = window;
            teardownCoordinator.addTeardownListener(window::onNuclearTeardown);
            installSystemTray(window);
            window.setVisible(true);
        });
    }

    private void installSystemTray(ControlPanelWindow window) {
        if (!SystemTray.isSupported()) {
            return;
        }
        try {
            BufferedImage iconImg = new BufferedImage(16, 16, BufferedImage.TYPE_INT_ARGB);
            Graphics2D g = iconImg.createGraphics();
            g.setRenderingHint(RenderingHints.KEY_ANTIALIASING, RenderingHints.VALUE_ANTIALIAS_ON);
            g.setColor(new Color(0, 229, 255));
            g.fillRoundRect(1, 1, 14, 14, 4, 4);
            g.setColor(new Color(11, 18, 32));
            g.fillPolygon(new int[]{9, 4, 8, 7, 12, 8}, new int[]{2, 9, 9, 14, 7, 7}, 6);
            g.dispose();

            PopupMenu menu = new PopupMenu();
            MenuItem openItem = new MenuItem("Kontrol Panelini Aç");
            openItem.addActionListener(e -> SwingUtilities.invokeLater(() -> {
                window.setVisible(true);
                window.toFront();
            }));

            MenuItem nukeItem = new MenuItem("BAĞLANTIYI KES VE PORTU KAPAT");
            nukeItem.addActionListener(e -> teardownCoordinator.executeNuclearTeardown("TRAY_NUCLEAR_DISCONNECT"));

            MenuItem exitItem = new MenuItem("Tamamen Çık (Her Şeyi Sil)");
            exitItem.addActionListener(e -> {
                teardownCoordinator.executeNuclearTeardown("TRAY_EXIT");
                System.exit(0);
            });

            menu.add(openItem);
            menu.addSeparator();
            menu.add(nukeItem);
            menu.addSeparator();
            menu.add(exitItem);

            TrayIcon trayIcon = new TrayIcon(iconImg, "AntigravityBlipper", menu);
            trayIcon.setImageAutoSize(true);
            trayIcon.addActionListener(e -> SwingUtilities.invokeLater(() -> {
                window.setVisible(true);
                window.toFront();
            }));
            SystemTray.getSystemTray().add(trayIcon);
        } catch (Exception ignored) {}
    }
}
