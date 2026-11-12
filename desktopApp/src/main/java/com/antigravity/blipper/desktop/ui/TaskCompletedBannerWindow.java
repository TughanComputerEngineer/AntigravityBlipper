package com.antigravity.blipper.desktop.ui;

import javax.swing.BorderFactory;
import javax.swing.JButton;
import javax.swing.JDialog;
import javax.swing.JLabel;
import javax.swing.JPanel;
import javax.swing.SwingUtilities;
import java.awt.BorderLayout;
import java.awt.Color;
import java.awt.Cursor;
import java.awt.Dimension;
import java.awt.Font;
import java.awt.GraphicsEnvironment;
import java.awt.Rectangle;

public final class TaskCompletedBannerWindow {

    private static volatile JDialog activeBanner;

    private TaskCompletedBannerWindow() {}

    public static String formatDisplayBanner(String rawBannerText) {
        String text = (rawBannerText == null || rawBannerText.isBlank())
                ? "ANTIGRAVITY: Aktif Sohbet: Görev tamamlandı"
                : rawBannerText.trim();
        return "►  " + text;
    }

    public static void showBanner(String formattedBannerText) {
        if (GraphicsEnvironment.isHeadless()) {
            return;
        }
        SoundSynthesizer.playTaskCompletedChime();
        SwingUtilities.invokeLater(() -> {
            JDialog prev = activeBanner;
            if (prev != null) {
                prev.dispose();
            }

            JDialog dialog = new JDialog();
            dialog.setUndecorated(true);
            dialog.setAlwaysOnTop(true);
            dialog.setFocusableWindowState(false);

            JPanel root = new JPanel(new BorderLayout(16, 0));
            root.setBackground(new Color(11, 18, 32));
            root.setBorder(BorderFactory.createCompoundBorder(
                    BorderFactory.createLineBorder(new Color(0, 229, 255), 3),
                    BorderFactory.createEmptyBorder(14, 22, 14, 18)
            ));

            JLabel messageLabel = new JLabel(formatDisplayBanner(formattedBannerText));
            messageLabel.setForeground(new Color(240, 249, 255));
            messageLabel.setFont(new Font("Segoe UI", Font.BOLD, 17));
            root.add(messageLabel, BorderLayout.CENTER);

            JButton closeBtn = new JButton("✕");
            closeBtn.setFont(new Font("Segoe UI", Font.BOLD, 16));
            closeBtn.setForeground(new Color(255, 255, 255));
            closeBtn.setBackground(new Color(30, 41, 59));
            closeBtn.setFocusPainted(false);
            closeBtn.setCursor(Cursor.getPredefinedCursor(Cursor.HAND_CURSOR));
            closeBtn.setPreferredSize(new Dimension(44, 36));
            closeBtn.addActionListener(e -> dialog.dispose());
            root.add(closeBtn, BorderLayout.EAST);

            dialog.setContentPane(root);
            dialog.pack();

            Rectangle screen = GraphicsEnvironment.getLocalGraphicsEnvironment()
                    .getDefaultScreenDevice()
                    .getDefaultConfiguration()
                    .getBounds();
            int width = Math.min(Math.max(dialog.getWidth() + 30, 680), screen.width - 60);
            int height = Math.max(dialog.getHeight(), 68);
            dialog.setSize(width, height);
            int x = screen.x + (screen.width - width) / 2;
            int y = screen.y + 14;
            dialog.setLocation(x, y);

            activeBanner = dialog;
            dialog.setVisible(true);
            dialog.toFront();
        });
    }
}
