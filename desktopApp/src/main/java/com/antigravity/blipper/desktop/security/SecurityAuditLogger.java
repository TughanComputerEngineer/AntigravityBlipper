package com.antigravity.blipper.desktop.security;

import com.fasterxml.jackson.databind.ObjectMapper;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.nio.file.StandardOpenOption;
import java.security.MessageDigest;
import java.time.Instant;
import java.util.HexFormat;
import java.util.List;

@Component
public class SecurityAuditLogger {

    private static final String GENESIS_HASH = "GENESIS_00000000000000000000000000000000000000000000000000000000";

    public record AuditEntry(
            String timestampIso,
            String eventType,
            String remoteIp,
            int remotePort,
            String networkProfile,
            String gatewayMac,
            String detail,
            String prevHash,
            String entryHash
    ) {}

    private final Path auditFilePath;
    private final ObjectMapper objectMapper = new ObjectMapper();

    @Autowired
    public SecurityAuditLogger() {
        this(Paths.get(System.getProperty("user.home"), ".antigravity-blipper", "security-audit.jsonl"));
    }

    public SecurityAuditLogger(Path auditFilePath) {
        this.auditFilePath = auditFilePath;
    }

    public synchronized AuditEntry appendTamperEvidentLog(
            String eventType,
            String remoteIp,
            int remotePort,
            String networkProfile,
            String gatewayMac,
            String detail
    ) {
        try {
            Path parent = auditFilePath.getParent();
            if (parent != null) {
                Files.createDirectories(parent);
            }
            String prevHash = readLastHash();
            String ts = Instant.now().toString();
            String safeEvent = nullSafe(eventType);
            String safeIp = nullSafe(remoteIp);
            String safeProfile = nullSafe(networkProfile);
            String safeMac = nullSafe(gatewayMac);
            String safeDetail = nullSafe(detail);

            String entryHash = computeEntryHash(ts, safeEvent, safeIp, remotePort, safeProfile, safeMac, safeDetail, prevHash);
            AuditEntry entry = new AuditEntry(
                    ts, safeEvent, safeIp, remotePort, safeProfile, safeMac, safeDetail, prevHash, entryHash
            );
            String line = objectMapper.writeValueAsString(entry) + System.lineSeparator();
            Files.writeString(
                    auditFilePath,
                    line,
                    StandardCharsets.UTF_8,
                    StandardOpenOption.CREATE,
                    StandardOpenOption.WRITE,
                    StandardOpenOption.APPEND
            );
            return entry;
        } catch (IOException e) {
            throw new IllegalStateException("Failed to append security audit entry", e);
        }
    }

    public synchronized boolean verifyChainIntegrity() {
        if (!Files.exists(auditFilePath)) {
            return true;
        }
        try {
            List<String> lines = Files.readAllLines(auditFilePath, StandardCharsets.UTF_8);
            String expectedPrev = GENESIS_HASH;
            for (String line : lines) {
                if (line.isBlank()) {
                    continue;
                }
                AuditEntry entry = objectMapper.readValue(line, AuditEntry.class);
                if (!expectedPrev.equals(entry.prevHash())) {
                    return false;
                }
                String recomputed = computeEntryHash(
                        entry.timestampIso(),
                        entry.eventType(),
                        entry.remoteIp(),
                        entry.remotePort(),
                        entry.networkProfile(),
                        entry.gatewayMac(),
                        entry.detail(),
                        entry.prevHash()
                );
                if (!MessageDigest.isEqual(
                        recomputed.getBytes(StandardCharsets.UTF_8),
                        nullSafe(entry.entryHash()).getBytes(StandardCharsets.UTF_8)
                )) {
                    return false;
                }
                expectedPrev = entry.entryHash();
            }
            return true;
        } catch (Exception e) {
            return false;
        }
    }

    public Path getAuditFilePath() {
        return auditFilePath;
    }

    private String readLastHash() throws IOException {
        if (!Files.exists(auditFilePath)) {
            return GENESIS_HASH;
        }
        List<String> lines = Files.readAllLines(auditFilePath, StandardCharsets.UTF_8);
        for (int i = lines.size() - 1; i >= 0; i--) {
            String line = lines.get(i).trim();
            if (!line.isEmpty()) {
                AuditEntry last = objectMapper.readValue(line, AuditEntry.class);
                return last.entryHash();
            }
        }
        return GENESIS_HASH;
    }

    private static String computeEntryHash(
            String ts,
            String eventType,
            String remoteIp,
            int remotePort,
            String networkProfile,
            String gatewayMac,
            String detail,
            String prevHash
    ) {
        try {
            String canonical = ts + "|" + eventType + "|" + remoteIp + "|" + remotePort + "|"
                    + networkProfile + "|" + gatewayMac + "|" + detail + "|" + prevHash;
            MessageDigest md = MessageDigest.getInstance("SHA-256");
            return HexFormat.of().formatHex(md.digest(canonical.getBytes(StandardCharsets.UTF_8)));
        } catch (Exception e) {
            throw new IllegalStateException("SHA-256 unavailable", e);
        }
    }

    private static String nullSafe(String s) {
        return s == null ? "" : s;
    }
}
