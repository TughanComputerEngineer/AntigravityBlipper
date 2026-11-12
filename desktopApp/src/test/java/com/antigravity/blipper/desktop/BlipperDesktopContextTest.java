package com.antigravity.blipper.desktop;

import com.antigravity.blipper.desktop.network.DynamicLanTlsServer;
import com.antigravity.blipper.desktop.network.IntrusionEvent;
import com.antigravity.blipper.desktop.security.LocalHookSecretManager;
import com.antigravity.blipper.desktop.security.SessionStateRegistry;
import com.antigravity.blipper.desktop.ui.IntrusionAlertWindow;
import com.antigravity.blipper.desktop.ui.TaskCompletedBannerWindow;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.http.MediaType;
import org.springframework.test.web.servlet.MockMvc;

import java.time.Instant;

import static org.junit.jupiter.api.Assertions.*;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

@SpringBootTest(
        classes = BlipperDesktopApplication.class,
        properties = {
                "blipper.ui.enabled=false",
                "blipper.hook.auto-install=false"
        }
)
@AutoConfigureMockMvc
class BlipperDesktopContextTest {

    @Autowired
    private MockMvc mockMvc;

    @Autowired
    private LocalHookSecretManager secretManager;

    @Autowired
    private DynamicLanTlsServer lanServer;

    @Autowired
    private SessionStateRegistry sessionRegistry;

    @Test
    void springBootContextStartsWithZeroOpenLanPortsAndProtectedLoopbackEndpoint() throws Exception {
        assertFalse(lanServer.isListening(), "LAN server must start CLOSED (0 open LAN ports)");
        assertEquals(SessionStateRegistry.State.CLOSED, sessionRegistry.getState());

        // Missing secret -> 403 Forbidden
        mockMvc.perform(post("/local/v1/agy-stop")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{\"conversationId\":\"1\",\"terminationReason\":\"NO_TOOL_CALL\"}"))
                .andExpect(status().isForbidden());

        // Valid secret on 127.0.0.1 -> 200 OK
        mockMvc.perform(post("/local/v1/agy-stop")
                        .with(req -> {
                            req.setRemoteAddr("127.0.0.1");
                            return req;
                        })
                        .header(LocalHookSecretManager.HEADER_NAME, secretManager.getOrCreateSecret())
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{\"conversationId\":\"1\",\"terminationReason\":\"NO_TOOL_CALL\",\"lastUserInput\":\"Görev testi\"}"))
                .andExpect(status().isOk());
    }

    @Test
    void uiViewModelsProduceExactRequiredTurkishSecurityAndBannerCopy() {
        IntrusionEvent unauthorized = new IntrusionEvent(
                IntrusionEvent.IntrusionType.UNAUTHORIZED_TOUCH,
                "192.168.1.99",
                51234,
                "Cafe_WiFi",
                "DE-AD-BE-EF-00-01",
                Instant.now(),
                "Tanınmayan sertifika",
                false
        );
        var alertVm = IntrusionAlertWindow.buildAlertViewModel(unauthorized);
        assertEquals("[!] LOGLA VE PORTU ANINDA KAPAT", IntrusionAlertWindow.KILL_BUTTON_LABEL);
        assertTrue(alertVm.headline().contains("GÜVENLİK ALARMI"));
        assertTrue(alertVm.detailsText().contains("192.168.1.99:51234"));
        assertTrue(alertVm.detailsText().contains("Cafe_WiFi"));

        String banner = TaskCompletedBannerWindow.formatDisplayBanner(
                "ANTIGRAVITY: Carbon Merhaba Greeting: Güvenlik modülü tamamlandı"
        );
        assertTrue(banner.contains("ANTIGRAVITY: Carbon Merhaba Greeting: Güvenlik modülü tamamlandı"));
    }
}
