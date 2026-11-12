package com.antigravity.blipper.desktop.network;

import java.util.Locale;
import java.util.regex.Pattern;

public record NetworkFingerprint(
        String profileName,
        String interfaceAlias,
        String ipv4Address,
        String gatewayIp,
        String gatewayMac
) {
    private static final Pattern VALID_MAC_PATTERN =
            Pattern.compile("^[0-9A-F]{2}(-[0-9A-F]{2}){5}$");

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
        return !profileName.isBlank()
                && !ipv4Address.isBlank()
                && VALID_MAC_PATTERN.matcher(gatewayMac).matches()
                && !gatewayMac.equals("00-00-00-00-00-00")
                && !gatewayMac.equals("FF-FF-FF-FF-FF-FF");
    }
}
