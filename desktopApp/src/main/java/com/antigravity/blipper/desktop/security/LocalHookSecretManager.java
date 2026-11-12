package com.antigravity.blipper.desktop.security;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.nio.file.StandardOpenOption;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.util.HexFormat;

@Component
public class LocalHookSecretManager {

    public static final String HEADER_NAME = "X-Blipper-Local-Secret";

    private final Path secretFilePath;
    private final SecureRandom secureRandom = new SecureRandom();
    private volatile String cachedSecret;

    @Autowired
    public LocalHookSecretManager() {
        this(Paths.get(System.getProperty("user.home"), ".antigravity-blipper", "local-hook.secret"));
    }

    public LocalHookSecretManager(Path secretFilePath) {
        this.secretFilePath = secretFilePath;
    }

    public synchronized String getOrCreateSecret() {
        if (cachedSecret != null && cachedSecret.length() >= 64) {
            return cachedSecret;
        }
        try {
            if (Files.exists(secretFilePath)) {
                String existing = Files.readString(secretFilePath, StandardCharsets.UTF_8).trim();
                if (existing.length() >= 64) {
                    cachedSecret = existing;
                    return cachedSecret;
                }
            }
            Path parent = secretFilePath.getParent();
            if (parent != null) {
                Files.createDirectories(parent);
            }
            byte[] random = new byte[32];
            secureRandom.nextBytes(random);
            String generated = HexFormat.of().formatHex(random);
            Files.writeString(
                    secretFilePath,
                    generated,
                    StandardCharsets.UTF_8,
                    StandardOpenOption.CREATE,
                    StandardOpenOption.TRUNCATE_EXISTING,
                    StandardOpenOption.WRITE
            );
            cachedSecret = generated;
            return cachedSecret;
        } catch (IOException e) {
            throw new IllegalStateException("Failed to initialize local hook secret", e);
        }
    }

    public boolean matchesSecret(String candidate) {
        if (candidate == null || candidate.isBlank()) {
            return false;
        }
        String expected = getOrCreateSecret();
        return MessageDigest.isEqual(
                expected.getBytes(StandardCharsets.UTF_8),
                candidate.trim().getBytes(StandardCharsets.UTF_8)
        );
    }

    public Path getSecretFilePath() {
        return secretFilePath;
    }
}
