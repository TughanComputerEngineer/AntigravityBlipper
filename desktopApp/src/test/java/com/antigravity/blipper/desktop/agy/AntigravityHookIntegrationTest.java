package com.antigravity.blipper.desktop.agy;

import com.antigravity.blipper.desktop.crypto.EphemeralKeyMaterialService;
import com.antigravity.blipper.desktop.network.DynamicLanTlsServer;
import com.antigravity.blipper.desktop.network.WindowsNetworkFingerprintService;
import com.antigravity.blipper.desktop.security.LocalHookSecretManager;
import com.antigravity.blipper.desktop.security.SessionStateRegistry;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.io.OutputStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.Statement;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.concurrent.TimeUnit;

import static org.junit.jupiter.api.Assertions.*;

class AntigravityHookIntegrationTest {

    private final ObjectMapper mapper = new ObjectMapper();

    @Test
    void readerResolvesSqliteWalTitleSanitizesMarkdownAndIgnoresSubagentsOrCanceledRuns(@TempDir Path tempDir) throws Exception {
        Path unicodeDir = tempDir.resolve("Tuğhan").resolve(".gemini").resolve("antigravity");
        Files.createDirectories(unicodeDir);
        Path dbFile = unicodeDir.resolve("conversation_summaries.db");

        try (Connection conn = DriverManager.getConnection("jdbc:sqlite:" + dbFile.toAbsolutePath());
             Statement st = conn.createStatement()) {
            st.execute("PRAGMA journal_mode=WAL;");
            st.execute("CREATE TABLE conversation_summaries ("
                    + "conversation_id TEXT PRIMARY KEY, "
                    + "title TEXT NOT NULL DEFAULT '', "
                    + "parent_conversation_id TEXT NOT NULL DEFAULT '')");
            st.execute("INSERT INTO conversation_summaries VALUES ('conv-root-1', 'Carbon Merhaba Greeting', '')");
            st.execute("INSERT INTO conversation_summaries VALUES ('conv-sub-2', 'Subagent Worker', 'conv-root-1')");
            st.execute("INSERT INTO conversation_summaries VALUES ('conv-untitled', '', '')");
        }

        Path transcriptFile = unicodeDir.resolve("transcript.jsonl");
        String jsonl = """
                {"step_index":0,"type":"USER_INPUT","content":"Bana güvenlik modülünü yaz"}
                {"step_index":1,"type":"PLANNER_RESPONSE","content":"### Tamamlandı!\\n**Güvenlik modülü** ve `mTLS 1.3` katmanı başarıyla kuruldu.\\nDetaylar aşağıda..."}
                """;
        Files.writeString(transcriptFile, jsonl, StandardCharsets.UTF_8);

        var reader = new AntigravityConversationReader(dbFile);

        // 1. Normal root conversation completion
        Optional<AntigravityConversationReader.CompletedTaskSummary> ok = reader.resolveStopPayload(Map.of(
                "conversationId", "conv-root-1",
                "terminationReason", "NO_TOOL_CALL",
                "transcriptPath", transcriptFile.toString(),
                "lastUserInput", "Bana güvenlik modülünü yaz"
        ));
        assertTrue(ok.isPresent());
        assertEquals("Carbon Merhaba Greeting", ok.get().conversationTitle());
        assertTrue(ok.get().taskSummary().contains("Güvenlik modülü ve mTLS 1.3 katmanı başarıyla kuruldu."));
        assertFalse(ok.get().taskSummary().contains("\n"));
        assertTrue(ok.get().formattedBannerText().startsWith("ANTIGRAVITY: Carbon Merhaba Greeting: "));

        // 2. Child subagent conversation -> ignored!
        Optional<AntigravityConversationReader.CompletedTaskSummary> sub = reader.resolveStopPayload(Map.of(
                "conversationId", "conv-sub-2",
                "terminationReason", "NO_TOOL_CALL",
                "transcriptPath", transcriptFile.toString()
        ));
        assertTrue(sub.isEmpty());

        // 3. Canceled / Error termination -> ignored!
        Optional<AntigravityConversationReader.CompletedTaskSummary> canceled = reader.resolveStopPayload(Map.of(
                "conversationId", "conv-root-1",
                "terminationReason", "USER_CANCELED",
                "transcriptPath", transcriptFile.toString()
        ));
        assertTrue(canceled.isEmpty());

        // 4. Blank title falls back cleanly to "Aktif Sohbet"
        Optional<AntigravityConversationReader.CompletedTaskSummary> untitled = reader.resolveStopPayload(Map.of(
                "conversationId", "conv-untitled",
                "terminationReason", "NO_TOOL_CALL",
                "lastUserInput", "Hızlı düzeltme"
        ));
        assertTrue(untitled.isPresent());
        assertEquals("Aktif Sohbet", untitled.get().conversationTitle());
        assertEquals("Hızlı düzeltme", untitled.get().taskSummary());
    }

    @Test
    void hookInstallerPreservesExistingHooksAndGeneratedCmdSucceedsFastWhenDesktopOffline(@TempDir Path tempDir) throws Exception {
        Path userDir = tempDir.resolve("Tuğhan");
        Path hooksJsonPath = userDir.resolve(".gemini").resolve("config").resolve("hooks.json");
        Path blipperDir = userDir.resolve(".antigravity-blipper");
        Files.createDirectories(hooksJsonPath.getParent());
        Files.writeString(hooksJsonPath, "{\"existing-hook\":{\"PreInvocation\":[{\"command\":\"echo hi\"}]}}", StandardCharsets.UTF_8);

        var secretMgr = new LocalHookSecretManager(blipperDir.resolve("local-hook.secret"));
        // Use an unused loopback port (59997) to prove offline resilience
        var installer = new AntigravityHookInstaller(hooksJsonPath, blipperDir.resolve("agy-stop-hook.cmd"), secretMgr, 59997);

        Path cmdFile = installer.installOrUpdateGlobalStopHook();
        assertTrue(Files.exists(cmdFile));

        JsonNode merged = mapper.readTree(Files.readString(hooksJsonPath, StandardCharsets.UTF_8));
        assertTrue(merged.has("existing-hook"), "Must preserve user's existing hooks");
        assertTrue(merged.has("antigravity-blipper"), "Must register antigravity-blipper Stop hook");
        assertTrue(merged.path("antigravity-blipper").path("Stop").isArray());

        // Execute the generated .cmd hook via cmd.exe /c while port 59997 is CLOSED!
        Process proc = new ProcessBuilder("cmd.exe", "/c", cmdFile.toAbsolutePath().toString())
                .redirectErrorStream(false)
                .start();
        try (OutputStream stdin = proc.getOutputStream()) {
            stdin.write("{\"conversationId\":\"123\",\"terminationReason\":\"NO_TOOL_CALL\"}".getBytes(StandardCharsets.UTF_8));
        }
        boolean finishedFast = proc.waitFor(4, TimeUnit.SECONDS);
        assertTrue(finishedFast, "Hook script must never hang Antigravity when desktopApp is offline");
        assertEquals(0, proc.exitValue(), "Hook script must exit 0 even when desktopApp is offline");
        String stdout = new String(proc.getInputStream().readAllBytes(), StandardCharsets.UTF_8).trim();
        assertEquals("{}", stdout, "Stop hook stdout must be valid JSON {} so Antigravity allows normal stop");
    }

    @Test
    void localHookControllerDispatchesDesktopBannerCallback(@TempDir Path tempDir) throws Exception {
        Path dbFile = tempDir.resolve("summaries.db");
        var reader = new AntigravityConversationReader(dbFile);
        var crypto = new EphemeralKeyMaterialService();
        var registry = new SessionStateRegistry(crypto);
        var netSvc = new WindowsNetworkFingerprintService(() -> "");
        var lanServer = new DynamicLanTlsServer(crypto, registry, netSvc);
        var controller = new LocalHookController(reader, lanServer);

        List<AntigravityConversationReader.CompletedTaskSummary> dispatched = new ArrayList<>();
        controller.addTaskCompletedListener(dispatched::add);

        var resp = controller.handleAntigravityStop(Map.of(
                "conversationId", "c-1",
                "terminationReason", "NO_TOOL_CALL",
                "lastUserInput", "Veritabanı şemasını oluştur"
        ));
        assertEquals(200, resp.getStatusCode().value());
        assertEquals(1, dispatched.size());
        assertEquals("ANTIGRAVITY: Aktif Sohbet: Veritabanı şemasını oluştur", dispatched.get(0).formattedBannerText());
    }
}
