package com.antigravity.blipper.desktop.crypto;

public record SignedEnvelope(
        String type,
        String eventId,
        long timestampMs,
        String payloadJson,
        String hmacHex
) {
    public String canonicalSigningInput() {
        return (type == null ? "" : type) + "\n"
                + (eventId == null ? "" : eventId) + "\n"
                + timestampMs + "\n"
                + (payloadJson == null ? "" : payloadJson);
    }
}
