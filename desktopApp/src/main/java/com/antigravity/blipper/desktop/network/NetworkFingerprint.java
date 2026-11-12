package com.antigravity.blipper.desktop.network;

import java.util.Locale;

public record NetworkFingerprint(
        String profileName,
        String interfaceAlias,
        String ipv4Address,
        String gatewayIp,
        String gatewayMac
) {
    public NetworkFingerprint {
        profileName = profileName == null ? "" : profileName.trim();
        interfaceAlias = interfaceAlias == null ? "" : interfaceAlias.trim();
        ipv4Address = ipv4Address == null ? "" : ipv4Address.trim();
        gatewayIp = gatewayIp == null ? "" : gatewayIp.trim();
        gatewayMac = normalizeMac(gatewayMac);
    }

    public static String normalizeMac(String rawMac) {
        if (rawMac == null || rawMac.isBlank()) {
            return "";
        }
        return rawMac.trim()
                .replace(':', '-')
                .replace('.', '-')
                .toUpperCase(Locale.ROOT);
    }

    public boolean isValidForLock() {
        return !profileName.isBlank() && !gatewayMac.isBlank() && !gatewayMac.equals("00-00-00-00-00-00");
    }
}
