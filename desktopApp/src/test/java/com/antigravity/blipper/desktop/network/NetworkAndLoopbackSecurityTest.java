package com.antigravity.blipper.desktop.network;

import com.antigravity.blipper.desktop.security.LocalHookSecretManager;
import com.antigravity.blipper.desktop.security.LoopbackSecurityConfig;
import jakarta.servlet.FilterChain;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;

import java.nio.file.Path;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicReference;

import static org.junit.jupiter.api.Assertions.*;

class NetworkAndLoopbackSecurityTest {

    @Test
    void evilTwinSameProfileNameWithDifferentGatewayMacIsRejected() {
        AtomicReference<String> mockProbeOutput = new AtomicReference<>(
                "HomeFiber|Wi-Fi|192.168.1.25|192.168.1.1|aa:bb:cc:11:22:33"
        );
        var svc = new WindowsNetworkFingerprintService(mockProbeOutput::get);

        assertFalse(svc.isCurrentNetworkTrusted());
        NetworkFingerprint home = svc.readCurrentNetwork().orElseThrow();
        assertEquals("HomeFiber", home.profileName());
        assertEquals("AA-BB-CC-11-22-33", home.gatewayMac());

        svc.approveNetworkForCurrentSession(home);
        assertTrue(svc.isCurrentNetworkTrusted());

        // Café Evil-Twin spoofing exact Wi-Fi name "HomeFiber" & gateway IP, but different physical router MAC!
        mockProbeOutput.set("HomeFiber|Wi-Fi|192.168.1.44|192.168.1.1|DE-AD-BE-EF-00-01");
        assertFalse(svc.isCurrentNetworkTrusted());

        // Different café network name
        mockProbeOutput.set("Starbucks_Free|Wi-Fi|10.0.0.15|10.0.0.1|AA-BB-CC-11-22-33");
        assertFalse(svc.isCurrentNetworkTrusted());

        // Restore home network -> trusted until clearApprovedNetwork() is called
        mockProbeOutput.set("HomeFiber|Wi-Fi|192.168.1.25|192.168.1.1|AA-BB-CC-11-22-33");
        assertTrue(svc.isCurrentNetworkTrusted());
        svc.clearApprovedNetwork();
        assertFalse(svc.isCurrentNetworkTrusted());
    }

    @Test
    void backgroundRefreshRunsOffCallerThreadAndThrottlesRapidUiPolls() throws Exception {
        java.util.concurrent.atomic.AtomicInteger probeCount = new java.util.concurrent.atomic.AtomicInteger(0);
        AtomicReference<String> probeThreadName = new AtomicReference<>("");
        String callerThread = Thread.currentThread().getName();

        var svc = new WindowsNetworkFingerprintService(() -> {
            probeCount.incrementAndGet();
            probeThreadName.set(Thread.currentThread().getName());
            try {
                Thread.sleep(120L);
            } catch (InterruptedException ignored) {
                Thread.currentThread().interrupt();
            }
            return "HomeFiber|Wi-Fi|192.168.1.25|192.168.1.1|AA-BB-CC-11-22-33";
        });

        long t0 = System.nanoTime();
        for (int i = 0; i < 10; i++) {
            svc.requestBackgroundRefreshIfStale(3000L);
        }
        long elapsedMs = (System.nanoTime() - t0) / 1_000_000L;
        assertTrue(elapsedMs < 80L, "UI polling must never block caller/EDT thread on PowerShell probe");

        long deadline = System.currentTimeMillis() + 2000L;
        while (svc.getCachedSnapshot().isEmpty() && System.currentTimeMillis() < deadline) {
            Thread.sleep(20L);
        }
        NetworkFingerprint cached = svc.getCachedSnapshot().orElseThrow();
        assertEquals("HomeFiber", cached.profileName());
        assertEquals(1, probeCount.get(), "10 rapid UI polls within TTL must trigger only 1 probe");
        assertNotEquals(callerThread, probeThreadName.get(), "Probe must run on background worker, not caller/EDT");

        svc.approveNetworkForCurrentSession(cached);
        assertTrue(svc.matchesApprovedNetwork(cached));
        assertEquals(1, probeCount.get(), "matchesApprovedNetwork must evaluate in-memory with 0 extra probes");
    }

    @Test
    void firewallHelperScopesStrictlyToLocalSubnet() {
        var svc = new WindowsNetworkFingerprintService(() -> "");
        String enableCmd = svc.buildLocalSubnetFirewallScript(58443, 58444, true);
        assertTrue(enableCmd.contains("remoteip=localsubnet"));
        assertTrue(enableCmd.contains("localport=58443"));
        assertTrue(enableCmd.contains("localport=58444"));

        String disableCmd = svc.buildLocalSubnetFirewallScript(58443, 58444, false);
        assertTrue(disableCmd.contains("delete rule"));
    }

    @Test
    void localHookSecretPersistsOnUnicodePathAndLoopbackFilterBlocksExternalOrUnauthenticatedRequests(
            @TempDir Path tempDir
    ) throws Exception {
        Path secretFile = tempDir.resolve("Tuğhan").resolve("local-hook.secret");
        var secretMgr = new LocalHookSecretManager(secretFile);
        String secret = secretMgr.getOrCreateSecret();
        assertTrue(secret.length() >= 64);
        assertTrue(secretMgr.matchesSecret(secret));
        assertFalse(secretMgr.matchesSecret("wrong-secret"));

        var filter = new LoopbackSecurityConfig.LocalHookAuthenticationFilter(secretMgr);

        // 1. Valid loopback + valid header -> passes filter chain
        var okReq = new MockHttpServletRequest("POST", "/local/v1/agy-stop");
        okReq.setRemoteAddr("127.0.0.1");
        okReq.addHeader(LocalHookSecretManager.HEADER_NAME, secret);
        var okRes = new MockHttpServletResponse();
        AtomicBoolean chainCalled = new AtomicBoolean(false);
        FilterChain chain = (req, res) -> chainCalled.set(true);
        filter.doFilter(okReq, okRes, chain);
        assertTrue(chainCalled.get());
        assertEquals(200, okRes.getStatus());

        // 2. Non-loopback LAN IP even WITH valid secret -> 403 Forbidden!
        var lanReq = new MockHttpServletRequest("POST", "/local/v1/agy-stop");
        lanReq.setRemoteAddr("192.168.1.50");
        lanReq.addHeader(LocalHookSecretManager.HEADER_NAME, secret);
        var lanRes = new MockHttpServletResponse();
        AtomicBoolean lanChainCalled = new AtomicBoolean(false);
        filter.doFilter(lanReq, lanRes, (req, res) -> lanChainCalled.set(true));
        assertFalse(lanChainCalled.get());
        assertEquals(403, lanRes.getStatus());

        // 3. Loopback IP with wrong/missing secret -> 403 Forbidden!
        var badSecretReq = new MockHttpServletRequest("POST", "/local/v1/agy-stop");
        badSecretReq.setRemoteAddr("127.0.0.1");
        badSecretReq.addHeader(LocalHookSecretManager.HEADER_NAME, "forged");
        var badSecretRes = new MockHttpServletResponse();
        filter.doFilter(badSecretReq, badSecretRes, (req, res) -> fail("Should not reach controller"));
        assertEquals(403, badSecretRes.getStatus());
    }
}
