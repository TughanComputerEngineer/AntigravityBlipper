package com.antigravity.blipper.desktop.ui;

import com.antigravity.blipper.desktop.agy.LocalHookController;
import com.antigravity.blipper.desktop.network.DynamicLanTlsServer;
import com.antigravity.blipper.desktop.network.NetworkFingerprint;
import com.antigravity.blipper.desktop.network.NuclearTeardownCoordinator;
import com.antigravity.blipper.desktop.network.WindowsNetworkFingerprintService;
import com.antigravity.blipper.desktop.security.SessionStateRegistry;

import javax.swing.BorderFactory;
import javax.swing.Box;
import javax.swing.BoxLayout;
import javax.swing.JButton;
import javax.swing.JCheckBox;
import javax.swing.JComboBox;
import javax.swing.JFrame;
import javax.swing.JLabel;
import javax.swing.JOptionPane;
import javax.swing.JPanel;
import javax.swing.JSpinner;
import javax.swing.SpinnerNumberModel;
import javax.swing.SwingConstants;
import javax.swing.Timer;
import java.awt.BorderLayout;
import java.awt.Color;
import java.awt.Cursor;
import java.awt.Dimension;
import java.awt.FlowLayout;
import java.awt.Font;
import java.time.Duration;
import java.util.Optional;

public class ControlPanelWindow extends JFrame {

    private final WindowsNetworkFingerprintService networkService;
    private final SessionStateRegistry sessionRegistry;
    private final DynamicLanTlsServer lanServer;
    private final NuclearTeardownCoordinator teardownCoordinator;
    private final LocalHookController localHookController;
    private final int configuredLanPort;
    private final int configuredUdpPort;

    private final JLabel statusBadgeLabel = new JLabel("", SwingConstants.CENTER);
    private final JLabel networkInfoLabel = new JLabel("");
    private final JLabel pinDisplayLabel = new JLabel("PORT KAPALI — Aktif eşleştirme yok", SwingConstants.CENTER);
    private final JSpinner hoursSpinner = new JSpinner(new SpinnerNumberModel(4, 1, 24, 1));
    private final JCheckBox unlimitedCheck = new JCheckBox("Sınırsız Yetki (Oturum Kapanana Kadar)");
    private final JComboBox<String> digitsCombo = new JComboBox<>(new String[]{"6 Haneli Kod", "8 Haneli Kod"});

    private volatile String currentPinDisplay = "";
    private volatile String currentHostPortDisplay = "";

    public ControlPanelWindow(
            WindowsNetworkFingerprintService networkService,
            SessionStateRegistry sessionRegistry,
            DynamicLanTlsServer lanServer,
            NuclearTeardownCoordinator teardownCoordinator,
            LocalHookController localHookController,
            int configuredLanPort,
            int configuredUdpPort
    ) {
        super("AntigravityBlipper — Sıfır Güven Masaüstü Kalkanı");
        this.networkService = networkService;
        this.sessionRegistry = sessionRegistry;
        this.lanServer = lanServer;
        this.teardownCoordinator = teardownCoordinator;
        this.localHookController = localHookController;
        this.configuredLanPort = configuredLanPort;
        this.configuredUdpPort = configuredUdpPort;

        setSize(760, 650);
        setMinimumSize(new Dimension(720, 620));
        setLocationRelativeTo(null);
        setDefaultCloseOperation(JFrame.HIDE_ON_CLOSE);

        buildLayout();
        Timer refreshTimer = new Timer(1000, e -> refreshUiState());
        refreshTimer.start();
        refreshUiState();
    }

    public void onNuclearTeardown(String reason) {
        this.currentPinDisplay = "";
        this.currentHostPortDisplay = "";
        refreshUiState();
    }

    private void buildLayout() {
        JPanel root = new JPanel(new BorderLayout(16, 16));
        root.setBorder(BorderFactory.createEmptyBorder(18, 20, 18, 20));

        statusBadgeLabel.setOpaque(true);
        statusBadgeLabel.setFont(new Font("Segoe UI", Font.BOLD, 18));
        statusBadgeLabel.setBorder(BorderFactory.createEmptyBorder(14, 16, 14, 16));
        root.add(statusBadgeLabel, BorderLayout.NORTH);

        JPanel center = new JPanel();
        center.setLayout(new BoxLayout(center, BoxLayout.Y_AXIS));

        // 1. Network Lock Card
        JPanel netCard = createSectionPanel("1. Ev Ağı & Kafe Koruması (Modem Fiziksel MAC Kilidi)");
        networkInfoLabel.setFont(new Font("Consolas", Font.PLAIN, 13));
        netCard.add(networkInfoLabel);
        netCard.add(Box.createVerticalStrut(10));

        JPanel netButtons = new JPanel(new FlowLayout(FlowLayout.LEFT, 10, 0));
        JButton approveNetBtn = new JButton("✓ Mevcut Ev Ağını Bu Oturum İçin Onayla");
        approveNetBtn.setCursor(Cursor.getPredefinedCursor(Cursor.HAND_CURSOR));
        approveNetBtn.addActionListener(e -> approveCurrentNetwork());

        JButton fwBtn = new JButton("🛡️ LocalSubnet Güvenlik Duvarı İzni Ekle");
        fwBtn.setCursor(Cursor.getPredefinedCursor(Cursor.HAND_CURSOR));
        fwBtn.addActionListener(e -> runElevatedFirewallRule(true));

        netButtons.add(approveNetBtn);
        netButtons.add(fwBtn);
        netCard.add(netButtons);

        // 2. Pairing & TTL Card
        JPanel pairCard = createSectionPanel("2. Tek Kullanımlık Eşleştirme (60 sn) & Cihaz Yetki Süresi");
        JPanel ttlRow = new JPanel(new FlowLayout(FlowLayout.LEFT, 12, 0));
        ttlRow.add(new JLabel("Yetki Süresi (1–24 Saat):"));
        ttlRow.add(hoursSpinner);
        unlimitedCheck.addActionListener(e -> hoursSpinner.setEnabled(!unlimitedCheck.isSelected()));
        ttlRow.add(unlimitedCheck);
        ttlRow.add(digitsCombo);
        pairCard.add(ttlRow);
        pairCard.add(Box.createVerticalStrut(10));

        JButton startPairBtn = new JButton("🔑 60 Saniyelik Eşleştirme Başlat (mTLS 1.3 Portunu Aç)");
        startPairBtn.setFont(new Font("Segoe UI", Font.BOLD, 15));
        startPairBtn.setBackground(new Color(2, 132, 199));
        startPairBtn.setForeground(Color.WHITE);
        startPairBtn.setCursor(Cursor.getPredefinedCursor(Cursor.HAND_CURSOR));
        startPairBtn.addActionListener(e -> startPairingSession());
        pairCard.add(startPairBtn);
        pairCard.add(Box.createVerticalStrut(12));

        pinDisplayLabel.setOpaque(true);
        pinDisplayLabel.setBackground(new Color(15, 23, 42));
        pinDisplayLabel.setForeground(new Color(56, 189, 248));
        pinDisplayLabel.setFont(new Font("Consolas", Font.BOLD, 22));
        pinDisplayLabel.setBorder(BorderFactory.createEmptyBorder(14, 14, 14, 14));
        pinDisplayLabel.setMaximumSize(new Dimension(Integer.MAX_VALUE, 70));
        pairCard.add(pinDisplayLabel);

        // 3. Test & Nuclear Wipe Card
        JPanel actionCard = createSectionPanel("3. Test & Karşılıklı Tam İmha (Kill Switch)");
        JButton testBtn = new JButton("⚡ Test Bildirimi Gönder (Masaüstü Üst Pencere + Telefona 5x Bildirim)");
        testBtn.setFont(new Font("Segoe UI", Font.BOLD, 14));
        testBtn.setCursor(Cursor.getPredefinedCursor(Cursor.HAND_CURSOR));
        testBtn.setMaximumSize(new Dimension(Integer.MAX_VALUE, 42));
        testBtn.addActionListener(e -> localHookController.triggerManualTestAlert(
                "AntigravityBlipper Test",
                "Masaüstü üst pencere ve 5x Samsung uyandırma hattı çalışıyor!"
        ));

        JButton nuclearDisconnectBtn = new JButton("💣 BAĞLANTIYI KES VE TÜM KAYITLARI SİL (PC + TELEFON)");
        nuclearDisconnectBtn.setFont(new Font("Segoe UI", Font.BOLD, 18));
        nuclearDisconnectBtn.setBackground(new Color(185, 28, 28));
        nuclearDisconnectBtn.setForeground(Color.WHITE);
        nuclearDisconnectBtn.setCursor(Cursor.getPredefinedCursor(Cursor.HAND_CURSOR));
        nuclearDisconnectBtn.setMaximumSize(new Dimension(Integer.MAX_VALUE, 64));
        nuclearDisconnectBtn.addActionListener(e -> {
            teardownCoordinator.executeNuclearTeardown("MANUAL_DESKTOP_DISCONNECT_AND_WIPE");
            refreshUiState();
        });

        JButton fullExitBtn = new JButton("🚪 Uygulamayı Tamamen Kapat (Portu Kapat & Tüm Anahtarları İmha Et)");
        fullExitBtn.setCursor(Cursor.getPredefinedCursor(Cursor.HAND_CURSOR));
        fullExitBtn.setMaximumSize(new Dimension(Integer.MAX_VALUE, 38));
        fullExitBtn.addActionListener(e -> {
            teardownCoordinator.executeNuclearTeardown("USER_EXIT_APPLICATION");
            System.exit(0);
        });

        actionCard.add(testBtn);
        actionCard.add(Box.createVerticalStrut(12));
        actionCard.add(nuclearDisconnectBtn);
        actionCard.add(Box.createVerticalStrut(10));
        actionCard.add(fullExitBtn);

        center.add(netCard);
        center.add(Box.createVerticalStrut(12));
        center.add(pairCard);
        center.add(Box.createVerticalStrut(12));
        center.add(actionCard);

        root.add(center, BorderLayout.CENTER);
        setContentPane(root);
    }

    private JPanel createSectionPanel(String title) {
        JPanel p = new JPanel();
        p.setLayout(new BoxLayout(p, BoxLayout.Y_AXIS));
        p.setBorder(BorderFactory.createCompoundBorder(
                BorderFactory.createTitledBorder(title),
                BorderFactory.createEmptyBorder(8, 12, 10, 12)
        ));
        return p;
    }

    private void approveCurrentNetwork() {
        Optional<NetworkFingerprint> fpOpt = networkService.readCurrentNetwork();
        if (fpOpt.isEmpty()) {
            JOptionPane.showMessageDialog(this,
                    "Aktif bir ağ geçidi bulunamadı. Wi-Fi veya Ethernet bağlantınızı kontrol edin.",
                    "Ağ Bulunamadı", JOptionPane.WARNING_MESSAGE);
            return;
        }
        networkService.approveNetworkForCurrentSession(fpOpt.get());
        refreshUiState();
    }

    private void startPairingSession() {
        if (!networkService.isCurrentNetworkTrusted()) {
            approveCurrentNetwork();
            if (!networkService.isCurrentNetworkTrusted()) {
                return;
            }
        }
        int digits = digitsCombo.getSelectedIndex() == 1 ? 8 : 6;
        Duration ttl = unlimitedCheck.isSelected()
                ? Duration.ZERO
                : Duration.ofHours(((Number) hoursSpinner.getValue()).intValue());
        try {
            var info = lanServer.startForPairing(configuredLanPort, configuredUdpPort, digits, ttl);
            String ip = networkService.getApprovedNetwork().map(NetworkFingerprint::ipv4Address).orElse("LAN-IP");
            this.currentPinDisplay = info.pinCode();
            this.currentHostPortDisplay = ip + ":" + info.lanPort();
            refreshUiState();
        } catch (Exception ex) {
            JOptionPane.showMessageDialog(this,
                    "Eşleştirme başlatılamadı: " + ex.getMessage(),
                    "Güvenlik Hatası", JOptionPane.ERROR_MESSAGE);
        }
    }

    private void runElevatedFirewallRule(boolean enable) {
        String cmd = networkService.buildLocalSubnetFirewallScript(configuredLanPort, configuredUdpPort, enable);
        try {
            new ProcessBuilder(
                    "powershell.exe",
                    "-NoProfile",
                    "-Command",
                    "Start-Process cmd.exe -Verb RunAs -ArgumentList '/c " + cmd.replace("'", "''") + "'"
            ).start();
        } catch (Exception ex) {
            JOptionPane.showMessageDialog(this,
                    "Güvenlik duvarı komutu çalıştırılamadı: " + ex.getMessage(),
                    "Hata", JOptionPane.ERROR_MESSAGE);
        }
    }

    private void refreshUiState() {
        Optional<NetworkFingerprint> currentNet = networkService.readCurrentNetwork();
        boolean netTrusted = networkService.isCurrentNetworkTrusted();
        if (currentNet.isPresent()) {
            NetworkFingerprint fp = currentNet.get();
            networkInfoLabel.setText(String.format(
                    "Ağ: %s (%s) | PC IP: %s | Modem MAC: %s | Durum: %s",
                    fp.profileName(), fp.interfaceAlias(), fp.ipv4Address(), fp.gatewayMac(),
                    netTrusted ? "ONAYLI EV AĞI ✓" : "ONAYSIZ (KİLİTLİ)"
            ));
        } else {
            networkInfoLabel.setText("Aktif ağ bağlantısı yok — LAN portu kilitli.");
        }

        SessionStateRegistry.State st = sessionRegistry.getState();
        long now = System.currentTimeMillis();
        if (st == SessionStateRegistry.State.CLOSED || !lanServer.isListening()) {
            statusBadgeLabel.setBackground(new Color(20, 83, 45));
            statusBadgeLabel.setForeground(new Color(220, 252, 231));
            statusBadgeLabel.setText("🔒 GÜVENLİ KİLİT AKTİF — 0 AÇIK LAN PORTU ( Sıfır Kayıtlı Anahtar )");
            pinDisplayLabel.setText("PORT KAPALI — Aktif eşleştirme kodu yok");
        } else if (st == SessionStateRegistry.State.PAIRING_WINDOW) {
            long remSec = Math.max(0L, (sessionRegistry.getPairingExpiresAtMs() - now) / 1000L);
            statusBadgeLabel.setBackground(new Color(146, 64, 14));
            statusBadgeLabel.setForeground(new Color(254, 243, 199));
            statusBadgeLabel.setText("🟡 EŞLEŞTİRME BEKLENİYOR (" + remSec + " sn kaldı) — Port: " + currentHostPortDisplay);
            pinDisplayLabel.setText("KOD:  " + currentPinDisplay + "    |    ADRES:  " + currentHostPortDisplay);
        } else {
            var snapOpt = sessionRegistry.getActiveSessionSnapshot();
            String dev = snapOpt.map(SessionStateRegistry.ActiveSessionSnapshot::deviceName).orElse("Android");
            String ttlText = snapOpt.map(s -> s.unlimited()
                    ? "Sınırsız (Oturum Boyunca)"
                    : (Math.max(0L, (s.sessionExpiresAtMs() - now) / 60_000L) + " dk kaldı"))
                    .orElse("-");
            boolean wsLive = lanServer.hasActiveAuthenticatedStream();
            statusBadgeLabel.setBackground(new Color(3, 105, 161));
            statusBadgeLabel.setForeground(Color.WHITE);
            statusBadgeLabel.setText("🟢 ŞİFRELİ mTLS 1.3 OTURUMU: " + dev
                    + (wsLive ? " [CANLI WSS BAĞLI]" : " [BAĞLANTI BEKLENİYOR]")
                    + " | Süre: " + ttlText);
            pinDisplayLabel.setText("EŞLEŞME TAMAMLANDI — Tek kullanımlık PIN bellekten silindi ✓");
        }
    }
}
