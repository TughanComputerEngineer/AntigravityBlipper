package com.antigravity.blipper.desktop.network;

import java.time.Instant;

public record IntrusionEvent(
        IntrusionType type,
        String remoteIp,
        int remotePort,
        String networkProfile,
        String gatewayMac,
        Instant occurredAt,
        String detail,
        boolean authorizedConnection
) {
    public enum IntrusionType {
        UNAUTHORIZED_TOUCH,
        TLS_HANDSHAKE_FAILED,
        INVALID_PIN,
        AUTHENTICATED_DEVICE_CONNECT,
        REPLAY_OR_TOKEN_VIOLATION
    }
}
