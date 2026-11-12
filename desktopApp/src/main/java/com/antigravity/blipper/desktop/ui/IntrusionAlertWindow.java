package com.antigravity.blipper.desktop.ui;

import com.antigravity.blipper.desktop.network.IntrusionEvent;

import javax.swing.BorderFactory;
import javax.swing.Box;
import javax.swing.BoxLayout;
import javax.swing.JButton;
import javax.swing.JFrame;
import javax.swing.JLabel;
import javax.swing.JPanel;
import javax.swing.JTextArea;
import javax.swing.SwingConstants;
import javax.swing.SwingUtilities;
import javax.swing.Timer;
import java.awt.BorderLayout;
import java.awt.Color;
import java.awt.Component;
import java.awt.Cursor;
import java.awt.Dimension;
import java.awt.Font;
import java.awt.GraphicsEnvironment;
import java.awt.Rectangle;
import java.time.ZoneId;
import java.time.format.DateTimeFormatter;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.function.Consumer;

public final class IntrusionAlertWindow {

    public static final String KILL_BUTTON_LABEL = "🛑 LOGLA VE PORTU ANINDA KAPAT";

    private static final DateTimeFormatter TIME_FMT =
            DateTimeFormatter.ofPattern("dd.MM.yyyy HH:mm:ss").withZone(ZoneId.systemDefault());

    public record AlertViewModel(
            String headline,
            String subtitle,
            String detailsText,
            String dismissButtonLabel
    ) {}

    private IntrusionAlertWindow() {}

    public static AlertViewModel buildAlertViewModel(IntrusionEvent event) {
        boolean authConnect = event != null && event.authorizedConnection();
        String headline = authConnect
                ? "🚨 GÜVENLİK ALARMI — PORTA CİHAZ BAĞLANDI! 🚨"
                : "🚨 GÜVENLİK ALARMI — TANINMAYAN PORT ERİŞİM GİRİŞİMİ! 🚨";
        String subtitle = authConnect
                ? "Şifreli mTLS portuna bir cihaz bağlandı. Bu bağlantıyı sen başlatmadıysan derhal aşağıdaki dev butona bas!"
                : "Tanınmayan bir cihaz Blipper LAN portuna dokundu ve reddedildi! Portu tamamen kapatmak için aşağıdaki dev butona bas!";

        String ipPort = (event == null ? "unknown" : event.remoteIp()) + ":" + (event == null ? 0 : event.remotePort());
        String net = event == null ? "UNKNOWN" : event.networkProfile();
        String mac = event == null ? "UNKNOWN" : event.gatewayMac();
        String time = event == null || event.occurredAt() == null ? "-" : TIME_FMT.format(event.occurredAt());
        String type = event == null || event.type() == null ? "UNKNOWN" : event.type().name();
        String detail = event == null ? "" : event.detail();

        String details = "Kaynak IP / Port   :  " + ipPort + "\n"
                + "Aktif Ağ Profili   :  " + net + "   (Modem MAC: " + mac + ")\n"
                + "Olay Zamanı        :  " + time + "\n"
                + "Güvenlik Sınıfı    :  " + type + "\n"
                + "Teknik Detay       :  " + detail;

        String dismiss = authConnect
                ? "[ Tanıyorum, Benim Telefonum — Sadece Uyarıyı Kapat ]"
                : "[ Uyarıyı Kapat (Bağlantı Zaten Reddedildi) ]";

        return new AlertViewModel(headline, subtitle, details, dismiss);
    }

    public static void showFullScreenAlert(IntrusionEvent event, Consumer<IntrusionEvent> onLogAndKillPort) {
        if (GraphicsEnvironment.isHeadless()) {
            return;
        }
        AtomicBoolean stopSiren = new AtomicBoolean(false);
        SoundSynthesizer.playUrgentIntrusionSiren(stopSiren);

        SwingUtilities.invokeLater(() -> {
            AlertViewModel vm = buildAlertViewModel(event);
            JFrame frame = new JFrame("AntigravityBlipper — GÜVENLİK ALARMI");
            frame.setUndecorated(true);
            frame.setAlwaysOnTop(true);
            frame.setDefaultCloseOperation(JFrame.DISPOSE_ON_CLOSE);

            Rectangle screenBounds = GraphicsEnvironment.getLocalGraphicsEnvironment()
                    .getDefaultScreenDevice()
                    .getDefaultConfiguration()
                    .getBounds();
            frame.setBounds(screenBounds);

            Color darkCrimson = new Color(24, 4, 8);
            Color borderRedA = new Color(255, 23, 68);
            Color borderRedB = new Color(110, 0, 18);

            JPanel root = new JPanel(new BorderLayout(0, 28));
            root.setBackground(darkCrimson);
            root.setBorder(BorderFactory.createCompoundBorder(
                    BorderFactory.createLineBorder(borderRedA, 12),
                    BorderFactory.createEmptyBorder(48, 64, 48, 64)
            ));

            Timer flashTimer = new Timer(360, null);
            AtomicBoolean toggle = new AtomicBoolean(false);
            flashTimer.addActionListener(e -> {
                boolean next = !toggle.get();
                toggle.set(next);
                root.setBorder(BorderFactory.createCompoundBorder(
                        BorderFactory.createLineBorder(next ? borderRedA : borderRedB, 12),
                        BorderFactory.createEmptyBorder(48, 64, 48, 64)
                ));
            });
            flashTimer.start();

            JPanel centerBox = new JPanel();
            centerBox.setOpaque(false);
            centerBox.setLayout(new BoxLayout(centerBox, BoxLayout.Y_AXIS));

            JLabel headlineLabel = new JLabel(vm.headline(), SwingConstants.CENTER);
            headlineLabel.setAlignmentX(Component.CENTER_ALIGNMENT);
            headlineLabel.setForeground(new Color(255, 82, 82));
            headlineLabel.setFont(new Font("Segoe UI", Font.BOLD, 34));

            JLabel subLabel = new JLabel(vm.subtitle(), SwingConstants.CENTER);
            subLabel.setAlignmentX(Component.CENTER_ALIGNMENT);
            subLabel.setForeground(new Color(255, 235, 238));
            subLabel.setFont(new Font("Segoe UI", Font.PLAIN, 20));

            JTextArea detailsArea = new JTextArea(vm.detailsText());
            detailsArea.setEditable(false);
            detailsArea.setFocusable(false);
            detailsArea.setBackground(new Color(45, 10, 16));
            detailsArea.setForeground(new Color(255, 248, 225));
            detailsArea.setFont(new Font("Consolas", Font.BOLD, 20));
            detailsArea.setBorder(BorderFactory.createCompoundBorder(
                    BorderFactory.createLineBorder(new Color(255, 82, 82), 2),
                    BorderFactory.createEmptyBorder(22, 28, 22, 28)
            ));
            detailsArea.setMaximumSize(new Dimension(1050, 230));
            detailsArea.setAlignmentX(Component.CENTER_ALIGNMENT);

            JButton giantKillButton = new JButton(KILL_BUTTON_LABEL);
            giantKillButton.setAlignmentX(Component.CENTER_ALIGNMENT);
            giantKillButton.setFont(new Font("Segoe UI", Font.BOLD, 30));
            giantKillButton.setForeground(Color.WHITE);
            giantKillButton.setBackground(new Color(213, 0, 0));
            giantKillButton.setFocusPainted(false);
            giantKillButton.setCursor(Cursor.getPredefinedCursor(Cursor.HAND_CURSOR));
            Dimension hugeSize = new Dimension(920, 140);
            giantKillButton.setPreferredSize(hugeSize);
            giantKillButton.setMinimumSize(hugeSize);
            giantKillButton.setMaximumSize(hugeSize);
            giantKillButton.setBorder(BorderFactory.createLineBorder(Color.WHITE, 4));
            giantKillButton.addActionListener(e -> {
                stopSiren.set(true);
                flashTimer.stop();
                try {
                    if (onLogAndKillPort != null) {
                        onLogAndKillPort.accept(event);
                    }
                } finally {
                    frame.dispose();
                }
            });

            JButton dismissBtn = new JButton(vm.dismissButtonLabel());
            dismissBtn.setAlignmentX(Component.CENTER_ALIGNMENT);
            dismissBtn.setFont(new Font("Segoe UI", Font.PLAIN, 16));
            dismissBtn.setForeground(new Color(200, 200, 200));
            dismissBtn.setBackground(new Color(55, 20, 26));
            dismissBtn.setFocusPainted(false);
            dismissBtn.setCursor(Cursor.getPredefinedCursor(Cursor.HAND_CURSOR));
            dismissBtn.setMaximumSize(new Dimension(540, 46));
            dismissBtn.addActionListener(e -> {
                stopSiren.set(true);
                flashTimer.stop();
                frame.dispose();
            });

            centerBox.add(Box.createVerticalGlue());
            centerBox.add(headlineLabel);
            centerBox.add(Box.createVerticalStrut(14));
            centerBox.add(subLabel);
            centerBox.add(Box.createVerticalStrut(30));
            centerBox.add(detailsArea);
            centerBox.add(Box.createVerticalStrut(38));
            centerBox.add(giantKillButton);
            centerBox.add(Box.createVerticalStrut(22));
            centerBox.add(dismissBtn);
            centerBox.add(Box.createVerticalGlue());

            root.add(centerBox, BorderLayout.CENTER);
            frame.setContentPane(root);
            frame.getRootPane().setDefaultButton(giantKillButton);
            frame.setVisible(true);
            frame.toFront();
            frame.requestFocus();
        });
    }
}
