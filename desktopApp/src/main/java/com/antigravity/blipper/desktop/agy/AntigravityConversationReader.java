package com.antigravity.blipper.desktop.agy;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;
import org.sqlite.SQLiteConfig;

import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.util.List;
import java.util.Map;
import java.util.Optional;

@Service
public class AntigravityConversationReader {

    private static final int MAX_TITLE_CHARS = 80;
    private static final int MAX_SUMMARY_CHARS = 140;

    public record CompletedTaskSummary(
            String conversationId,
            String conversationTitle,
            String taskSummary,
            String formattedBannerText
    ) {}

    private record DbConversationRow(String title, String parentConversationId) {}

    private final Path summariesDbPath;
    private final ObjectMapper mapper = new ObjectMapper();

    @Autowired
    public AntigravityConversationReader() {
        this(Paths.get(System.getProperty("user.home"), ".gemini", "antigravity", "conversation_summaries.db"));
    }

    public AntigravityConversationReader(Path summariesDbPath) {
        this.summariesDbPath = summariesDbPath;
    }

    public Optional<CompletedTaskSummary> resolveStopPayload(Map<String, Object> stopHookJson) {
        if (stopHookJson == null) {
            return Optional.empty();
        }
        String terminationReason = asString(stopHookJson.get("terminationReason"));
        if (!"NO_TOOL_CALL".equals(terminationReason)) {
            return Optional.empty();
        }

        String conversationId = asString(stopHookJson.get("conversationId"));
        Optional<DbConversationRow> dbRow = queryConversationRow(conversationId);
        if (dbRow.isPresent() && !dbRow.get().parentConversationId().isBlank()) {
            // Subagent completion; do not trigger user-level root conversation alert
            return Optional.empty();
        }

        String rawTitle = dbRow.map(DbConversationRow::title).orElse("");
        String cleanTitle = sanitizeText(rawTitle, MAX_TITLE_CHARS);
        if (cleanTitle.isBlank()) {
            cleanTitle = "Aktif Sohbet";
        }

        String transcriptPathStr = asString(stopHookJson.get("transcriptPath"));
        String rawSummary = extractLastPlannerResponseFromTranscript(transcriptPathStr);
        if (rawSummary.isBlank()) {
            rawSummary = asString(stopHookJson.get("lastUserInput"));
        }
        String cleanSummary = sanitizeText(rawSummary, MAX_SUMMARY_CHARS);
        if (cleanSummary.isBlank()) {
            cleanSummary = "Görev tamamlandı";
        }

        String banner = "ANTIGRAVITY: " + cleanTitle + ": " + cleanSummary;
        return Optional.of(new CompletedTaskSummary(conversationId, cleanTitle, cleanSummary, banner));
    }

    private Optional<DbConversationRow> queryConversationRow(String conversationId) {
        if (conversationId == null || conversationId.isBlank() || !Files.exists(summariesDbPath)) {
            return Optional.empty();
        }
        try {
            SQLiteConfig config = new SQLiteConfig();
            config.setReadOnly(true);
            config.setBusyTimeout(1500);
            String url = "jdbc:sqlite:" + summariesDbPath.toAbsolutePath();
            try (Connection conn = DriverManager.getConnection(url, config.toProperties());
                 PreparedStatement ps = conn.prepareStatement(
                         "SELECT title, parent_conversation_id FROM conversation_summaries WHERE conversation_id = ?")) {
                ps.setString(1, conversationId);
                try (ResultSet rs = ps.executeQuery()) {
                    if (rs.next()) {
                        String title = rs.getString(1);
                        String parentId = rs.getString(2);
                        return Optional.of(new DbConversationRow(
                                title == null ? "" : title,
                                parentId == null ? "" : parentId
                        ));
                    }
                }
            }
        } catch (Exception ignored) {
            // Fall back gracefully to "Aktif Sohbet" if DB is missing or locked
        }
        return Optional.empty();
    }

    private String extractLastPlannerResponseFromTranscript(String transcriptPathStr) {
        if (transcriptPathStr == null || transcriptPathStr.isBlank()) {
            return "";
        }
        try {
            Path p = Paths.get(transcriptPathStr);
            if (!Files.exists(p)) {
                return "";
            }
            List<String> lines = Files.readAllLines(p, StandardCharsets.UTF_8);
            for (int i = lines.size() - 1; i >= 0; i--) {
                String line = lines.get(i).trim();
                if (line.isEmpty()) {
                    continue;
                }
                JsonNode node = mapper.readTree(line);
                if ("PLANNER_RESPONSE".equals(node.path("type").asText(""))) {
                    String content = node.path("content").asText("");
                    if (!content.isBlank()) {
                        return content;
                    }
                }
            }
        } catch (Exception ignored) {}
        return "";
    }

    public static String sanitizeText(String raw, int maxChars) {
        if (raw == null || raw.isBlank()) {
            return "";
        }
        String s = raw
                // Convert markdown links [label](url) -> label
                .replaceAll("\\[([^\\]]+)]\\([^)]+\\)", "$1")
                // Strip markdown headings, bold, backticks, blockquotes
                .replaceAll("(?m)^\\s{0,3}#+\\s*", "")
                .replace("**", "")
                .replace("__", "")
                .replace("`", "")
                .replaceAll("[\\r\\n\\t]+", " ")
                .replaceAll("\\s{2,}", " ")
                .trim();
        if (s.length() > maxChars) {
            return s.substring(0, maxChars - 1).trim() + "…";
        }
        return s;
    }

    private static String asString(Object val) {
        return val == null ? "" : String.valueOf(val).trim();
    }
}
