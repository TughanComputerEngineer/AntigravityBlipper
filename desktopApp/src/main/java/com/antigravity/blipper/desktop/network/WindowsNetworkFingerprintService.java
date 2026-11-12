package com.antigravity.blipper.desktop.network;

import jakarta.annotation.PreDestroy;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.Base64;
import java.util.Optional;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicLong;
import java.util.function.Supplier;

@Service
public class WindowsNetworkFingerprintService {

    public static final String PROBE_PREFIX = "BLIPPER_NET|";
    private static final int MAX_CONSECUTIVE_EMPTY_PROBES_BEFORE_UNTRUSTED = 3;

    private static final String POWERSHELL_PROBE_SCRIPT =
            "$ProgressPreference = 'SilentlyContinue'\n"
            + "[Console]::OutputEncoding = [System.Text.Encoding]::UTF8\n"
            + "$nic = [System.Net.NetworkInformation.NetworkInterface]::GetAllNetworkInterfaces() | Where-Object {\n"
            + "  $_.OperationalStatus -eq 'Up' -and $_.NetworkInterfaceType -ne 'Loopback' -and "
            + "  ($_.GetIPProperties().GatewayAddresses | Where-Object { $_.Address.AddressFamily -eq 'InterNetwork' -and $_.Address.IPAddressToString -ne '0.0.0.0' })\n"
            + "} | Select-Object -First 1\n"
            + "if ($null -ne $nic) {\n"
            + "  $props = $nic.GetIPProperties()\n"
            + "  $idx = $props.GetIPv4Properties().Index\n"
            + "  $gw = ($props.GatewayAddresses | Where-Object { $_.Address.AddressFamily -eq 'InterNetwork' -and $_.Address.IPAddressToString -ne '0.0.0.0' } | Select-Object -First 1).Address.IPAddressToString\n"
            + "  $ip = ($props.UnicastAddresses | Where-Object { $_.Address.AddressFamily -eq 'InterNetwork' } | Select-Object -First 1).Address.IPAddressToString\n"
            + "  $cimProf = Get-CimInstance -Namespace root/StandardCimv2 -ClassName MSFT_NetConnectionProfile -Filter \"InterfaceIndex = $idx\" -ErrorAction SilentlyContinue | Select-Object -First 1\n"
            + "  $prof = if ($cimProf -and $cimProf.Name) { [string]$cimProf.Name } else { [string]$nic.Description }\n"
            + "  $arpLine = (arp -a $gw 2>$null | Select-String '([0-9a-fA-F]{2}[:-]){5}[0-9a-fA-F]{2}' | Select-Object -First 1)\n"
            + "  if (-not $arpLine) {\n"
            + "    $null = ping -n 1 -w 400 $gw 2>$null\n"
            + "    $arpLine = (arp -a $gw 2>$null | Select-String '([0-9a-fA-F]{2}[:-]){5}[0-9a-fA-F]{2}' | Select-Object -First 1)\n"
            + "  }\n"
            + "  $mac = if ($arpLine) { $arpLine.Matches[0].Value.ToUpper() } else { '' }\n"
            + "  [Console]::Out.WriteLine(('BLIPPER_NET|{0}|{1}|{2}|{3}|{4}' -f $prof, $nic.Name, $ip, $gw, $mac))\n"
            + "}\n";

    private static final String ENCODED_POWERSHELL_PROBE =
            Base64.getEncoder().encodeToString(POWERSHELL_PROBE_SCRIPT.getBytes(StandardCharsets.UTF_16LE));

    private final Supplier<String> rawProbeSupplier;
    private final ExecutorService backgroundProbeExecutor = Executors.newSingleThreadExecutor(r -> {
        Thread t = new Thread(r, "blipper-net-probe");
        t.setDaemon(true);
        return t;
    });
    private final AtomicBoolean refreshInFlight = new AtomicBoolean(false);
    private final AtomicLong lastRefreshStartedAtMs = new AtomicLong(0L);
    private final AtomicInteger consecutiveEmptyProbes = new AtomicInteger(0);

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
            String raw = rawProbeSupplier.get();
            if (raw == null || raw.isBlank()) {
                this.cachedSnapshot = null;
                this.lastRefreshStartedAtMs.set(System.currentTimeMillis());
                return Optional.empty();
            }
            String trimmed = raw.trim();
            String payload = trimmed.startsWith(PROBE_PREFIX)
                    ? trimmed.substring(PROBE_PREFIX.length())
                    : trimmed;
            String[] parts = payload.split("\\|", -1);
            if (parts.length != 5) {
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
        this.consecutiveEmptyProbes.set(0);
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

    /**
     * Used by the periodic watchdog: immediately rejects any different SSID or gateway MAC on the first check,
     * while tolerating up to 2 transient empty probe timeouts under heavy CPU load before declaring loss of trust.
     */
    public boolean isCurrentNetworkTrustedForWatchdog() {
        NetworkFingerprint approved = this.approvedNetwork;
        if (approved == null || !approved.isValidForLock()) {
            return false;
        }
        Optional<NetworkFingerprint> currentOpt = readCurrentNetwork();
        if (currentOpt.isPresent()) {
            consecutiveEmptyProbes.set(0);
            return matchesApprovedNetwork(currentOpt.get());
        }
        int misses = consecutiveEmptyProbes.incrementAndGet();
        return misses < MAX_CONSECUTIVE_EMPTY_PROBES_BEFORE_UNTRUSTED;
    }

    public synchronized void clearApprovedNetwork() {
        this.approvedNetwork = null;
        this.consecutiveEmptyProbes.set(0);
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
                    "-NoLogo",
                    "-NoProfile",
                    "-NonInteractive",
                    "-OutputFormat", "Text",
                    "-ExecutionPolicy", "Bypass",
                    "-EncodedCommand", ENCODED_POWERSHELL_PROBE
            ).redirectError(ProcessBuilder.Redirect.DISCARD).start();

            String matchedLine = "";
            try (BufferedReader reader = new BufferedReader(
                    new InputStreamReader(process.getInputStream(), StandardCharsets.UTF_8))) {
                String line;
                while ((line = reader.readLine()) != null) {
                    int idx = line.indexOf(PROBE_PREFIX);
                    if (idx >= 0) {
                        matchedLine = line.substring(idx).trim();
                    }
                }
            }
            boolean finished = process.waitFor(6000, TimeUnit.MILLISECONDS);
            if (!finished) {
                process.destroyForcibly();
                return "";
            }
            return matchedLine;
        } catch (Exception e) {
            return "";
        } finally {
            if (process != null && process.isAlive()) {
                process.destroyForcibly();
            }
        }
    }
}
