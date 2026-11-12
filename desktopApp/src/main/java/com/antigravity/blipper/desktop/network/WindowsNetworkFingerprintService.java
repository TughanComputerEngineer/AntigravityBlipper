package com.antigravity.blipper.desktop.network;

import jakarta.annotation.PreDestroy;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.Optional;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicLong;
import java.util.function.Supplier;

@Service
public class WindowsNetworkFingerprintService {

    private static final String POWERSHELL_PROBE_SCRIPT =
            "[Console]::OutputEncoding = [System.Text.Encoding]::UTF8; "
            + "$cfg = Get-NetIPConfiguration | Where-Object { $_.IPv4DefaultGateway -ne $null -and $_.NetAdapter.Status -eq 'Up' } | Select-Object -First 1; "
            + "if ($null -ne $cfg) { "
            + "  $prof = [string]$cfg.NetProfile.Name; "
            + "  $alias = [string]$cfg.InterfaceAlias; "
            + "  $ip = [string]($cfg.IPv4Address | Select-Object -First 1).IPAddress; "
            + "  $gw = [string]$cfg.IPv4DefaultGateway.NextHop; "
            + "  $mac = [string](Get-NetNeighbor -IPAddress $gw -ErrorAction SilentlyContinue | Where-Object { $_.LinkLayerAddress } | Select-Object -First 1).LinkLayerAddress; "
            + "  if ([string]::IsNullOrWhiteSpace($mac)) { "
            + "    $null = Test-Connection -ComputerName $gw -Count 1 -Quiet -ErrorAction SilentlyContinue; "
            + "    $mac = [string](Get-NetNeighbor -IPAddress $gw -ErrorAction SilentlyContinue | Where-Object { $_.LinkLayerAddress } | Select-Object -First 1).LinkLayerAddress; "
            + "  } "
            + "  Write-Output \"$prof|$alias|$ip|$gw|$mac\" "
            + "}";

    private final Supplier<String> rawProbeSupplier;
    private final ExecutorService backgroundProbeExecutor = Executors.newSingleThreadExecutor(r -> {
        Thread t = new Thread(r, "blipper-net-probe");
        t.setDaemon(true);
        return t;
    });
    private final AtomicBoolean refreshInFlight = new AtomicBoolean(false);
    private final AtomicLong lastRefreshStartedAtMs = new AtomicLong(0L);

    private volatile NetworkFingerprint approvedNetwork;
    private volatile NetworkFingerprint cachedSnapshot;

    @Autowired
    public WindowsNetworkFingerprintService() {
        this(WindowsNetworkFingerprintService::executeWindowsCimProbe);
    }

    public WindowsNetworkFingerprintService(Supplier<String> rawProbeSupplier) {
        this.rawProbeSupplier = rawProbeSupplier;
    }

    public Optional<NetworkFingerprint> readCurrentNetwork() {
        try {
            String line = rawProbeSupplier.get();
            if (line == null || line.isBlank()) {
                this.cachedSnapshot = null;
                this.lastRefreshStartedAtMs.set(System.currentTimeMillis());
                return Optional.empty();
            }
            String[] parts = line.trim().split("\\|", -1);
            if (parts.length < 5) {
                this.cachedSnapshot = null;
                this.lastRefreshStartedAtMs.set(System.currentTimeMillis());
                return Optional.empty();
            }
            NetworkFingerprint fp = new NetworkFingerprint(parts[0], parts[1], parts[2], parts[3], parts[4]);
            if (fp.isValidForLock()) {
                this.cachedSnapshot = fp;
                this.lastRefreshStartedAtMs.set(System.currentTimeMillis());
                return Optional.of(fp);
            }
            this.cachedSnapshot = null;
            this.lastRefreshStartedAtMs.set(System.currentTimeMillis());
            return Optional.empty();
        } catch (Exception e) {
            this.cachedSnapshot = null;
            return Optional.empty();
        }
    }

    public Optional<NetworkFingerprint> getCachedSnapshot() {
        return Optional.ofNullable(cachedSnapshot);
    }

    public void requestBackgroundRefreshIfStale(long minIntervalMs) {
        requestBackgroundRefreshIfStale(minIntervalMs, null);
    }

    public void requestBackgroundRefreshIfStale(long minIntervalMs, Runnable onCompleteCallback) {
        long now = System.currentTimeMillis();
        long last = lastRefreshStartedAtMs.get();
        if (minIntervalMs > 0L && last > 0L && (now - last) < minIntervalMs) {
            return;
        }
        if (!refreshInFlight.compareAndSet(false, true)) {
            return;
        }
        lastRefreshStartedAtMs.set(now);
        try {
            backgroundProbeExecutor.submit(() -> {
                try {
                    readCurrentNetwork();
                } finally {
                    refreshInFlight.set(false);
                    if (onCompleteCallback != null) {
                        try {
                            onCompleteCallback.run();
                        } catch (Exception ignored) {}
                    }
                }
            });
        } catch (Exception e) {
            refreshInFlight.set(false);
        }
    }

    public synchronized void approveNetworkForCurrentSession(NetworkFingerprint fingerprint) {
        if (fingerprint == null || !fingerprint.isValidForLock()) {
            throw new IllegalArgumentException("Cannot approve incomplete network fingerprint");
        }
        this.approvedNetwork = fingerprint;
        this.cachedSnapshot = fingerprint;
    }

    public synchronized Optional<NetworkFingerprint> getApprovedNetwork() {
        return Optional.ofNullable(approvedNetwork);
    }

    public boolean matchesApprovedNetwork(NetworkFingerprint candidate) {
        NetworkFingerprint approved = this.approvedNetwork;
        if (approved == null || !approved.isValidForLock() || candidate == null || !candidate.isValidForLock()) {
            return false;
        }
        boolean profileMatches = MessageDigest.isEqual(
                approved.profileName().getBytes(StandardCharsets.UTF_8),
                candidate.profileName().getBytes(StandardCharsets.UTF_8)
        );
        boolean macMatches = MessageDigest.isEqual(
                approved.gatewayMac().getBytes(StandardCharsets.UTF_8),
                candidate.gatewayMac().getBytes(StandardCharsets.UTF_8)
        );
        return profileMatches && macMatches;
    }

    public boolean isCurrentNetworkTrusted() {
        NetworkFingerprint approved = this.approvedNetwork;
        if (approved == null || !approved.isValidForLock()) {
            return false;
        }
        Optional<NetworkFingerprint> currentOpt = readCurrentNetwork();
        return currentOpt.filter(this::matchesApprovedNetwork).isPresent();
    }

    public synchronized void clearApprovedNetwork() {
        this.approvedNetwork = null;
    }

    @PreDestroy
    public void shutdown() {
        backgroundProbeExecutor.shutdownNow();
    }

    public String buildLocalSubnetFirewallScript(int lanPort, int udpPort, boolean enable) {
        if (enable) {
            return "netsh advfirewall firewall delete rule name=\"AntigravityBlipper-LAN-TLS\" >nul 2>&1 & "
                    + "netsh advfirewall firewall delete rule name=\"AntigravityBlipper-UDP-Pair\" >nul 2>&1 & "
                    + "netsh advfirewall firewall add rule name=\"AntigravityBlipper-LAN-TLS\" "
                    + "dir=in action=allow protocol=TCP localport=" + lanPort + " remoteip=localsubnet profile=private,public & "
                    + "netsh advfirewall firewall add rule name=\"AntigravityBlipper-UDP-Pair\" "
                    + "dir=in action=allow protocol=UDP localport=" + udpPort + " remoteip=localsubnet profile=private,public";
        }
        return "netsh advfirewall firewall delete rule name=\"AntigravityBlipper-LAN-TLS\" & "
                + "netsh advfirewall firewall delete rule name=\"AntigravityBlipper-UDP-Pair\"";
    }

    private static String executeWindowsCimProbe() {
        Process process = null;
        try {
            process = new ProcessBuilder(
                    "powershell.exe",
                    "-NoProfile",
                    "-NonInteractive",
                    "-ExecutionPolicy", "Bypass",
                    "-Command", POWERSHELL_PROBE_SCRIPT
            ).redirectErrorStream(true).start();

            StringBuilder out = new StringBuilder();
            try (BufferedReader reader = new BufferedReader(
                    new InputStreamReader(process.getInputStream(), StandardCharsets.UTF_8))) {
                String line;
                while ((line = reader.readLine()) != null) {
                    if (line.contains("|")) {
                        out.setLength(0);
                        out.append(line.trim());
                    }
                }
            }
            boolean finished = process.waitFor(3500, TimeUnit.MILLISECONDS);
            if (!finished) {
                process.destroyForcibly();
                return "";
            }
            return out.toString();
        } catch (Exception e) {
            return "";
        } finally {
            if (process != null && process.isAlive()) {
                process.destroyForcibly();
            }
        }
    }
}
