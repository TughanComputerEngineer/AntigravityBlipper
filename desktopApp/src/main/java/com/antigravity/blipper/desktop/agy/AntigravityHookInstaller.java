package com.antigravity.blipper.desktop.agy;

import com.antigravity.blipper.desktop.security.LocalHookSecretManager;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.SerializationFeature;
import com.fasterxml.jackson.databind.node.ArrayNode;
import com.fasterxml.jackson.databind.node.ObjectNode;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.nio.file.StandardOpenOption;

@Service
public class AntigravityHookInstaller {

    public static final String HOOK_ENTRY_NAME = "antigravity-blipper";

    private final Path hooksJsonPath;
    private final Path hookCmdPath;
    private final LocalHookSecretManager secretManager;
    private final int loopbackPort;
    private final ObjectMapper mapper = new ObjectMapper().enable(SerializationFeature.INDENT_OUTPUT);

    @Autowired
    public AntigravityHookInstaller(
            LocalHookSecretManager secretManager,
            @Value("${server.port:49871}") int loopbackPort
    ) {
        this(
                Paths.get(System.getProperty("user.home"), ".gemini", "config", "hooks.json"),
                Paths.get(System.getProperty("user.home"), ".antigravity-blipper", "agy-stop-hook.cmd"),
                secretManager,
                loopbackPort
        );
    }

    public AntigravityHookInstaller(
            Path hooksJsonPath,
            Path hookCmdPath,
            LocalHookSecretManager secretManager,
            int loopbackPort
    ) {
        this.hooksJsonPath = hooksJsonPath;
        this.hookCmdPath = hookCmdPath;
        this.secretManager = secretManager;
        this.loopbackPort = loopbackPort;
    }

    public synchronized Path installOrUpdateGlobalStopHook() {
        try {
            String secret = secretManager.getOrCreateSecret();
            Path cmdParent = hookCmdPath.getParent();
            if (cmdParent != null) {
                Files.createDirectories(cmdParent);
            }

            String cmdScript = "@echo off\r\n"
                    + "\"%SystemRoot%\\System32\\curl.exe\" --connect-timeout 1 --max-time 2 -s -o NUL "
                    + "-X POST \"http://127.0.0.1:" + loopbackPort + "/local/v1/agy-stop\" "
                    + "-H \"Content-Type: application/json; charset=utf-8\" "
                    + "-H \"" + LocalHookSecretManager.HEADER_NAME + ": " + secret + "\" "
                    + "--data-binary @- >nul 2>&1\r\n"
                    + "echo {}\r\n"
                    + "exit /b 0\r\n";

            Files.writeString(
                    hookCmdPath,
                    cmdScript,
                    StandardCharsets.UTF_8,
                    StandardOpenOption.CREATE,
                    StandardOpenOption.TRUNCATE_EXISTING,
                    StandardOpenOption.WRITE
            );

            Path hooksParent = hooksJsonPath.getParent();
            if (hooksParent != null) {
                Files.createDirectories(hooksParent);
            }

            ObjectNode root;
            if (Files.exists(hooksJsonPath)) {
                String raw = Files.readString(hooksJsonPath, StandardCharsets.UTF_8).trim();
                root = raw.isEmpty() ? mapper.createObjectNode() : (ObjectNode) mapper.readTree(raw);
            } else {
                root = mapper.createObjectNode();
            }

            ObjectNode blipperHook = mapper.createObjectNode();
            blipperHook.put("enabled", true);
            ArrayNode stopHandlers = mapper.createArrayNode();
            ObjectNode handler = mapper.createObjectNode();
            handler.put("type", "command");
            handler.put("command", "\"" + hookCmdPath.toAbsolutePath() + "\"");
            handler.put("timeout", 5);
            stopHandlers.add(handler);
            blipperHook.set("Stop", stopHandlers);

            root.set(HOOK_ENTRY_NAME, blipperHook);
            Files.writeString(
                    hooksJsonPath,
                    mapper.writeValueAsString(root),
                    StandardCharsets.UTF_8,
                    StandardOpenOption.CREATE,
                    StandardOpenOption.TRUNCATE_EXISTING,
                    StandardOpenOption.WRITE
            );
            return hookCmdPath;
        } catch (IOException e) {
            throw new IllegalStateException("Failed to install Antigravity Stop hook", e);
        }
    }
}
