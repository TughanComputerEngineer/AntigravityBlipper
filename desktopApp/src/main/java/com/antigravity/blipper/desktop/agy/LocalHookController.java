package com.antigravity.blipper.desktop.agy;

import com.antigravity.blipper.desktop.network.DynamicLanTlsServer;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RestController;

import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.function.Consumer;

@RestController
public class LocalHookController {

    private final AntigravityConversationReader conversationReader;
    private final DynamicLanTlsServer lanServer;
    private final List<Consumer<AntigravityConversationReader.CompletedTaskSummary>> taskListeners =
            new CopyOnWriteArrayList<>();

    public LocalHookController(
            AntigravityConversationReader conversationReader,
            DynamicLanTlsServer lanServer
    ) {
        this.conversationReader = conversationReader;
        this.lanServer = lanServer;
    }

    @PostMapping("/local/v1/agy-stop")
    public ResponseEntity<Map<String, Object>> handleAntigravityStop(@RequestBody Map<String, Object> stopPayload) {
        Optional<AntigravityConversationReader.CompletedTaskSummary> resolved =
                conversationReader.resolveStopPayload(stopPayload);
        if (resolved.isEmpty()) {
            return ResponseEntity.ok(Map.of("dispatched", false));
        }
        boolean lanSent = dispatchSummary(resolved.get());
        return ResponseEntity.ok(Map.of("dispatched", true, "lanSent", lanSent));
    }

    public boolean triggerManualTestAlert(String conversationTitle, String taskSummary) {
        String cleanTitle = AntigravityConversationReader.sanitizeText(conversationTitle, 80);
        if (cleanTitle.isBlank()) {
            cleanTitle = "Test Sohbeti";
        }
        String cleanSummary = AntigravityConversationReader.sanitizeText(taskSummary, 140);
        if (cleanSummary.isBlank()) {
            cleanSummary = "Test bildirimi başarıyla tetiklendi";
        }
        var summary = new AntigravityConversationReader.CompletedTaskSummary(
                "manual-test",
                cleanTitle,
                cleanSummary,
                "ANTIGRAVITY: " + cleanTitle + ": " + cleanSummary
        );
        return dispatchSummary(summary);
    }

    public void addTaskCompletedListener(Consumer<AntigravityConversationReader.CompletedTaskSummary> listener) {
        if (listener != null) {
            taskListeners.add(listener);
        }
    }

    private boolean dispatchSummary(AntigravityConversationReader.CompletedTaskSummary summary) {
        for (Consumer<AntigravityConversationReader.CompletedTaskSummary> listener : taskListeners) {
            try {
                listener.accept(summary);
            } catch (Exception ignored) {}
        }
        return lanServer.sendTaskCompleted(summary.conversationTitle(), summary.taskSummary());
    }
}
