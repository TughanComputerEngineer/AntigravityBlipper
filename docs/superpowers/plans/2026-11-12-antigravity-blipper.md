# AntigravityBlipper Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Build the native Windows `desktopApp` (Java 21 + Spring Boot 3 + Spring Security + FlatLaf Swing UI) and native `androidApp` (Kotlin + Jetpack Compose + Hardware KeyStore + OkHttp mTLS + Samsung Wake/5x Burst Engine) connected via zero-persistence, full-paranoia mTLS 1.3 LAN security and wired into Antigravity's `Stop` lifecycle hook without a single line of Python or browser UI.

**Architecture:** `desktopApp` runs a headless-false Spring Boot JVM with two isolated transports: an always-local `127.0.0.1:49871` Spring Security loopback listener for Antigravity `Stop` hooks (reading `conversation_summaries.db` via read-only `sqlite-jdbc`) and a dynamically startable/stoppable `0.0.0.0:58443` TLS 1.3 server with raw-socket intrusion detection, RAM-only ECDSA P-256 keys, 6+ digit `PBKDF2-HMAC-SHA256` pairing, Windows Network Profile + Gateway MAC pinning, Always-On-Top task banners, and Full-Screen Red Security Alarms. `androidApp` opens zero inbound ports, pairs via hardware-backed `AndroidKeyStore` ECDSA keys, maintains a `WifiLock` + 15s-heartbeat outbound WSS stream inside a `specialUse` `ForegroundService` only while paired, wakes locked Samsung screens via `FullScreenIntent` (`WakeAlertActivity`), fires >= 5 distinct high-priority notifications sequentially, and executes mutual scorched-earth key/port teardown whenever either side disconnects, expires, changes networks, or closes.

**Tech Stack:**
- **Desktop:** OpenJDK 21 (`C:\Program Files\Android\Android Studio\jbr`), Gradle 8.13, Spring Boot `3.4.5` (`spring-boot-starter-web`, `spring-boot-starter-security`, `spring-boot-starter-websocket`), BouncyCastle `bcpkix-jdk18on:1.80`, `org.xerial:sqlite-jdbc:3.49.1.0`, FlatLaf `com.formdev:flatlaf:3.5.4`, JUnit 5.
- **Android:** Gradle `9.5.1`, Android Gradle Plugin `9.1.1`, Kotlin Compose Plugin `2.4.20`, `compileSdk = 37`, `minSdk = 29`, `targetSdk = 36`, Jetpack Compose Material 3 (`compose-bom:2025.02.00` or cached compatible), OkHttp `4.12.0`, BouncyCastle `bcpkix-jdk18on:1.80` (for unit-testable cert helpers), JUnit 4 + Kotlin Coroutines Test.

**Spec:** `c:\AntigravityBlipper\docs\superpowers\specs\2026-11-12-antigravity-blipper-design.md`

## Global Constraints

- **Zero Python / Zero PHP / Zero Browser UI:** No `.py`, `.php`, Electron, or browser tabs anywhere in `desktopApp`, `androidApp`, build scripts, or `~/.gemini/config/hooks.json`.
- **UTF-8 & Turkish Path Safety:** User profile contains `Tuğhan` (`C:\Users\Tuğhan\...`); always resolve user home via `System.getProperty("user.home")` + `java.nio.file.Path` and explicit `StandardCharsets.UTF_8`.
- **Default LAN State = CLOSED (`0` Open LAN Ports):** `desktopApp` starts with LAN port `58443` and UDP `58444` closed; `androidApp` never opens any `ServerSocket`.
- **Zero Persistent Pairing Material:** Desktop stores all ECDSA keys, certificates, PINs, tokens, and session secrets strictly in RAM (`byte[]`/`char[]` zeroized on teardown). Android deletes its `AndroidKeyStore` entry and clears RAM session state on every disconnect, TTL expiry (`1–24h` or `UNLIMITED`), app/service exit, or 30s heartbeat loss.
- **Wire Crypto Parameters:** TLS `TLSv1.3` only; ECDSA `secp256r1` (`SHA256withECDSA`); pairing KDF `PBKDF2WithHmacSHA256` with `210_000` iterations over UTF-8 PIN chars and salt `UTF8(serverCertSha256Hex + ":" + clientCertSha256Hex)`; message auth `HmacSHA256` with `±30_000ms` timestamp window and bounded UUID replay cache.
- **Full Paranoia Alarm Policy:** Every unauthorized TCP/TLS/PIN/token event AND every authenticated device WSS connection triggers `IntrusionAlertWindow` with giant `"🛑 LOGLA VE PORTU ANINDA KAPAT"` button (except the single in-progress `/api/v1/pair/complete` TLS request during an active 60s pairing window while verifying a valid PIN).
- **Minimum 5 Real Android Notifications:** Every `TASK_COMPLETED` burst dispatches at least `5` distinct `IMPORTANCE_HIGH` / `CATEGORY_ALARM` notifications spaced `900ms` apart (`[1/N]`..`[N/N]`) plus a `FullScreenIntent` to `WakeAlertActivity`.

## Review Focus

1. **Non-ASCII Windows user path (`C:\Users\Tuğhan`) + SQLite WAL lock / blank conversation title / markdown-heavy transcript:** `AntigravityConversationReader` must read SQLite read-only alongside active WAL files without locking Antigravity, fall back to `"Aktif Sohbet"` when `title` is empty, and sanitize multi-line markdown into a single clean summary line (`<= 140` chars). *(Tested in Task 5)*
2. **Raw TCP port scan or plaintext HTTP probe on `58443` that aborts before TLS completes:** Custom `IntrusionSensingServerSocketFactory` / `SSLSocket` handshake listener must capture `remoteIp:remotePort` and fire `IntrusionAlertWindow` even when Spring MVC is never reached. *(Tested in Task 3)*
3. **Antigravity `Stop` hook execution when `desktopApp` is closed:** Hook command in `hooks.json` must swallow `curl.exe` connection refusal on `127.0.0.1:49871`, print `{}` to stdout, and exit `0` within `2s` so Antigravity never hangs or errors. *(Tested in Task 5)*
4. **Simultaneous bidirectional `NUCLEAR_TEARDOWN` race condition:** Calling teardown concurrently from WSS receive, UI button, and shutdown hook must execute cleanup once without deadlocking or echoing infinite teardown frames. *(Tested in Task 4 & Task 7)*
5. **Android notification coalescing suppressing notifications 2..5:** `AlertBurstEngine` must emit `5` strictly distinct notification IDs without group-summary alert suppression so Samsung posts all 5 audibly even while locked. *(Tested in Task 8)*

---

## File Map

### Workspace Root
- Create: `.gitignore`

### `desktopApp/` (`com.antigravity.blipper.desktop`)
- Create: `desktopApp/settings.gradle.kts`
- Create: `desktopApp/build.gradle.kts`
- Create: `desktopApp/gradle.properties`
- Create: `desktopApp/src/main/resources/application.properties`
- Create: `desktopApp/src/main/java/com/antigravity/blipper/desktop/BlipperDesktopApplication.java`
- Create: `desktopApp/src/main/java/com/antigravity/blipper/desktop/crypto/EphemeralKeyMaterialService.java`
- Create: `desktopApp/src/main/java/com/antigravity/blipper/desktop/crypto/SignedEnvelope.java`
- Create: `desktopApp/src/main/java/com/antigravity/blipper/desktop/security/SessionStateRegistry.java`
- Create: `desktopApp/src/main/java/com/antigravity/blipper/desktop/security/SecurityAuditLogger.java`
- Create: `desktopApp/src/main/java/com/antigravity/blipper/desktop/security/LocalHookSecretManager.java`
- Create: `desktopApp/src/main/java/com/antigravity/blipper/desktop/security/LoopbackSecurityConfig.java`
- Create: `desktopApp/src/main/java/com/antigravity/blipper/desktop/network/NetworkFingerprint.java`
- Create: `desktopApp/src/main/java/com/antigravity/blipper/desktop/network/WindowsNetworkFingerprintService.java`
- Create: `desktopApp/src/main/java/com/antigravity/blipper/desktop/network/IntrusionEvent.java`
- Create: `desktopApp/src/main/java/com/antigravity/blipper/desktop/network/UdpDiscoveryResponder.java`
- Create: `desktopApp/src/main/java/com/antigravity/blipper/desktop/network/DynamicLanTlsServer.java`
- Create: `desktopApp/src/main/java/com/antigravity/blipper/desktop/network/NuclearTeardownCoordinator.java`
- Create: `desktopApp/src/main/java/com/antigravity/blipper/desktop/agy/AntigravityConversationReader.java`
- Create: `desktopApp/src/main/java/com/antigravity/blipper/desktop/agy/AntigravityHookInstaller.java`
- Create: `desktopApp/src/main/java/com/antigravity/blipper/desktop/agy/LocalHookController.java`
- Create: `desktopApp/src/main/java/com/antigravity/blipper/desktop/ui/SoundSynthesizer.java`
- Create: `desktopApp/src/main/java/com/antigravity/blipper/desktop/ui/TaskCompletedBannerWindow.java`
- Create: `desktopApp/src/main/java/com/antigravity/blipper/desktop/ui/IntrusionAlertWindow.java`
- Create: `desktopApp/src/main/java/com/antigravity/blipper/desktop/ui/ControlPanelWindow.java`
- Create: `desktopApp/src/main/java/com/antigravity/blipper/desktop/ui/DesktopUiOrchestrator.java`

### `androidApp/` (`com.antigravity.blipper.android`)
- Create: `androidApp/settings.gradle.kts`
- Create: `androidApp/build.gradle.kts`
- Create: `androidApp/gradle.properties`
- Create: `androidApp/local.properties`
- Create: `androidApp/app/build.gradle.kts`
- Create: `androidApp/app/src/main/AndroidManifest.xml`
- Create: `androidApp/app/src/main/java/com/antigravity/blipper/android/crypto/PairingCryptoEngine.kt`
- Create: `androidApp/app/src/main/java/com/antigravity/blipper/android/crypto/HardwareKeyManager.kt`
- Create: `androidApp/app/src/main/java/com/antigravity/blipper/android/crypto/EphemeralSessionStore.kt`
- Create: `androidApp/app/src/main/java/com/antigravity/blipper/android/network/LanDiscoveryClient.kt`
- Create: `androidApp/app/src/main/java/com/antigravity/blipper/android/network/BlipperSecureWsClient.kt`
- Create: `androidApp/app/src/main/java/com/antigravity/blipper/android/alert/AlertBurstEngine.kt`
- Create: `androidApp/app/src/main/java/com/antigravity/blipper/android/service/BlipperConnectionService.kt`
- Create: `androidApp/app/src/main/java/com/antigravity/blipper/android/service/ShutdownWipeReceiver.kt`
- Create: `androidApp/app/src/main/java/com/antigravity/blipper/android/ui/WakeAlertActivity.kt`
- Create: `androidApp/app/src/main/java/com/antigravity/blipper/android/ui/MainActivity.kt`
- Create: `androidApp/app/src/main/java/com/antigravity/blipper/android/ui/BlipperMainScreen.kt`
- Create: `androidApp/app/src/main/java/com/antigravity/blipper/android/ui/PermissionHelper.kt`

---

### Task 1: Workspace Git Init, Desktop Spring Boot Scaffold & Ephemeral Crypto/Session Core

**Files:**
- Create: `.gitignore`
- Create: `desktopApp/settings.gradle.kts`
- Create: `desktopApp/build.gradle.kts`
- Create: `desktopApp/gradle.properties`
- Create: `desktopApp/src/main/resources/application.properties`
- Create: `desktopApp/src/main/java/com/antigravity/blipper/desktop/crypto/SignedEnvelope.java`
- Create: `desktopApp/src/main/java/com/antigravity/blipper/desktop/crypto/EphemeralKeyMaterialService.java`
- Create: `desktopApp/src/main/java/com/antigravity/blipper/desktop/security/SessionStateRegistry.java`
- Create: `desktopApp/src/main/java/com/antigravity/blipper/desktop/security/SecurityAuditLogger.java`
- Test: `desktopApp/src/test/java/com/antigravity/blipper/desktop/crypto/EphemeralSecurityCoreTest.java`

**Interfaces:**
- Produces:
  - `SignedEnvelope(String type, String eventId, long timestampMs, String payloadJson, String hmacHex)`
  - `EphemeralKeyMaterialService`:
    - `EphemeralCertBundle generateEphemeralEcCert(String commonName)` (`KeyPair`, `X509Certificate`, `String sha256Hex`)
    - `String computeCertSha256Hex(X509Certificate cert)`
    - `String computePairingProofHex(char[] pin, String serverCertSha256Hex, String clientCertSha256Hex, long timestampMs, String nonce)`
    - `boolean verifyPairingProof(char[] pin, String serverCertSha256Hex, String clientCertSha256Hex, long timestampMs, String nonce, String candidateHex)`
    - `SignedEnvelope signEnvelope(byte[] hmacKey, String type, String payloadJson)`
    - `boolean verifyEnvelope(byte[] hmacKey, SignedEnvelope envelope)` (enforces `±30_000ms` window + bounded `ReplayNonceCache`)
  - `SessionStateRegistry`:
    - `PairingChallenge openPairingWindow(int codeDigits, Duration ttl, EphemeralCertBundle serverCert)` (60s window, `codeDigits >= 6`)
    - `PairingOutcome attemptPairing(X509Certificate clientCert, String deviceName, long timestampMs, String nonce, String proofHex)` (rejects expired window, wrong proof, or MITM cert mismatch; aborts window immediately on wrong proof)
    - `boolean isAuthorizedSession(X509Certificate clientCert, String bearerToken)`
    - `void recordHeartbeat()` / `boolean isHeartbeatExpired(long nowMs)` (`> 30_000ms`)
    - `boolean wipeAll()` (zeroizes PIN `char[]`, `hmacKey` `byte[]`, bearer token, and server private key reference; returns `true` when state transitioned to `CLOSED`)
  - `SecurityAuditLogger`:
    - `AuditEntry appendTamperEvidentLog(String eventType, String remoteIp, int remotePort, String networkProfile, String gatewayMac, String detail)`
    - `boolean verifyChainIntegrity()`

- [ ] **Step 1: Initialize git repo, `.gitignore`, and `desktopApp` Gradle wrapper + `build.gradle.kts`**

Generate Gradle `8.13` wrapper in `desktopApp/` using cached `gradle.bat` and `JAVA_HOME=C:\Program Files\Android\Android Studio\jbr`. Configure `desktopApp/build.gradle.kts` with Spring Boot `3.4.5`, Java `21`, `spring-boot-starter-web`, `spring-boot-starter-security`, `spring-boot-starter-websocket`, `org.bouncycastle:bcpkix-jdk18on:1.80`, `org.xerial:sqlite-jdbc:3.49.1.0`, `com.formdev:flatlaf:3.5.4`, and `spring-boot-starter-test`. Set `application.properties` to `server.address=127.0.0.1` and `server.port=49871`.

- [ ] **Step 2: Write the failing tests in `EphemeralSecurityCoreTest.java`**

```java
@Test
void pairingProofBindsBothCertificateFingerprintsAndRejectsMitm() {
    var svc = new EphemeralKeyMaterialService();
    var server = svc.generateEphemeralEcCert("Blipper-Desktop");
    var client = svc.generateEphemeralEcCert("Blipper-Android");
    var mitm = svc.generateEphemeralEcCert("Evil-Proxy");
    char[] pin = "849271".toCharArray();
    long now = System.currentTimeMillis();
    String proof = svc.computePairingProofHex(pin, server.sha256Hex(), client.sha256Hex(), now, "n-1");

    assertTrue(svc.verifyPairingProof(pin, server.sha256Hex(), client.sha256Hex(), now, "n-1", proof));
    assertFalse(svc.verifyPairingProof(pin, mitm.sha256Hex(), client.sha256Hex(), now, "n-1", proof));
    assertFalse(svc.verifyPairingProof("000000".toCharArray(), server.sha256Hex(), client.sha256Hex(), now, "n-1", proof));
}

@Test
void envelopeVerifierRejectsReplayAndStaleTimestamp() {
    var svc = new EphemeralKeyMaterialService();
    byte[] key = new byte[32];
    Arrays.fill(key, (byte) 7);
    SignedEnvelope env = svc.signEnvelope(key, "TASK_COMPLETED", "{\"title\":\"Demo\"}");
    assertTrue(svc.verifyEnvelope(key, env));
    assertFalse(svc.verifyEnvelope(key, env)); // replay of same eventId rejected
    SignedEnvelope stale = new SignedEnvelope("TASK_COMPLETED", UUID.randomUUID().toString(),
            System.currentTimeMillis() - 60_000L, "{}", env.hmacHex());
    assertFalse(svc.verifyEnvelope(key, stale));
}

@Test
void sessionRegistryAbortsOnWrongPinEnforcesTtlAndZeroizesSecrets() { ... }

@Test
void auditLoggerMaintainsValidSha256HashChainAndDetectsTampering(@TempDir Path tempDir) { ... }
```

- [ ] **Step 3: Run Gradle test to verify failure**

Run: `$env:JAVA_HOME="C:\Program Files\Android\Android Studio\jbr"; .\desktopApp\gradlew.bat -p desktopApp test --tests "*EphemeralSecurityCoreTest"`
Expected: FAIL (classes do not exist yet).

- [ ] **Step 4: Implement `SignedEnvelope`, `EphemeralKeyMaterialService`, `SessionStateRegistry`, and `SecurityAuditLogger`**

Use BouncyCastle `JcaX509v3CertificateBuilder` + `JcaContentSignerBuilder("SHA256withECDSA")` in RAM (no `KeyStore` files on disk), `PBKDF2WithHmacSHA256` (`210_000` iterations), `MessageDigest.isEqual` for all secret comparisons, and `Arrays.fill` zeroization inside `wipeAll()`.

- [ ] **Step 5: Run tests to verify PASS**

Run: `$env:JAVA_HOME="C:\Program Files\Android\Android Studio\jbr"; .\desktopApp\gradlew.bat -p desktopApp test --tests "*EphemeralSecurityCoreTest"`
Expected: `BUILD SUCCESSFUL`, all tests PASS.

- [ ] **Step 6: Commit**

```powershell
git add .gitignore desktopApp
git commit -m "feat(desktop): scaffold Spring Boot 3 app and ephemeral crypto/audit core"
```

---

### Task 2: Windows Network Profile + Gateway MAC Lock & Loopback Spring Security

**Files:**
- Create: `desktopApp/src/main/java/com/antigravity/blipper/desktop/network/NetworkFingerprint.java`
- Create: `desktopApp/src/main/java/com/antigravity/blipper/desktop/network/WindowsNetworkFingerprintService.java`
- Create: `desktopApp/src/main/java/com/antigravity/blipper/desktop/security/LocalHookSecretManager.java`
- Create: `desktopApp/src/main/java/com/antigravity/blipper/desktop/security/LoopbackSecurityConfig.java`
- Test: `desktopApp/src/test/java/com/antigravity/blipper/desktop/network/NetworkAndLoopbackSecurityTest.java`

**Interfaces:**
- Consumes: `SessionStateRegistry`
- Produces:
  - `NetworkFingerprint(String profileName, String interfaceAlias, String ipv4Address, String gatewayIp, String gatewayMac)`
  - `WindowsNetworkFingerprintService`:
    - `Optional<NetworkFingerprint> readCurrentNetwork()` (runs PowerShell CIM `Get-NetIPConfiguration` + `Get-NetNeighbor` without Windows Location Services; injectable command runner for deterministic unit tests)
    - `void approveNetworkForCurrentSession(NetworkFingerprint fp)`
    - `boolean isCurrentNetworkTrusted()` (checks exact match on `profileName` + normalized `gatewayMac`; false if disconnected, different Wi-Fi, or Evil-Twin gateway MAC mismatch)
    - `void clearApprovedNetwork()`
    - `String buildLocalSubnetFirewallScript(int lanPort, int udpPort, boolean enable)` (generates exact elevated `netsh advfirewall firewall` command scoped strictly to `remoteip=localsubnet` for home setups whose Windows network category is `Public`)
  - `LocalHookSecretManager`:
    - `String getOrCreateSecret()` (`~/.antigravity-blipper/local-hook.secret`, UTF-8 path safe)
    - `boolean matchesSecret(String candidate)`
  - `LoopbackSecurityConfig`: Spring Security `SecurityFilterChain` rejecting any request lacking valid `X-Blipper-Local-Secret` or originating from non-loopback remote address with HTTP `403`.

- [ ] **Step 1: Write failing tests in `NetworkAndLoopbackSecurityTest.java`**

```java
@Test
void evilTwinSameProfileNameWithDifferentGatewayMacIsRejected() {
    AtomicReference<String> mockOutput = new AtomicReference<>("HomeFiber|Wi-Fi|192.168.1.25|192.168.1.1|AA-BB-CC-11-22-33");
    var svc = new WindowsNetworkFingerprintService(mockOutput::get);
    NetworkFingerprint home = svc.readCurrentNetwork().orElseThrow();
    svc.approveNetworkForCurrentSession(home);
    assertTrue(svc.isCurrentNetworkTrusted());

    // Attacker spoofs SSID/profile name "HomeFiber" in a café with different router MAC
    mockOutput.set("HomeFiber|Wi-Fi|192.168.1.44|192.168.1.1|DE-AD-BE-EF-00-01");
    assertFalse(svc.isCurrentNetworkTrusted());
}

@Test
void loopbackFilterRejectsMissingOrWrongSecretWith403() { ... }
```

- [ ] **Step 2: Run test to verify failure**

Run: `$env:JAVA_HOME="C:\Program Files\Android\Android Studio\jbr"; .\desktopApp\gradlew.bat -p desktopApp test --tests "*NetworkAndLoopbackSecurityTest"`
Expected: FAIL.

- [ ] **Step 3: Implement `NetworkFingerprint`, `WindowsNetworkFingerprintService`, `LocalHookSecretManager`, and `LoopbackSecurityConfig`**

Query Windows network state via a single fast PowerShell one-liner (`Get-NetIPConfiguration` + `Get-NetNeighbor` for the IPv4 default gateway LinkLayerAddress, 2s timeout, UTF-8 output) so Windows Location Services is never needed. Configure `SecurityFilterChain` with stateless sessions, CSRF disabled for machine-token API, and `OncePerRequestFilter` enforcing `InetAddress.isLoopbackAddress()` + constant-time `X-Blipper-Local-Secret`.

- [ ] **Step 4: Run test to verify PASS**

Run: `$env:JAVA_HOME="C:\Program Files\Android\Android Studio\jbr"; .\desktopApp\gradlew.bat -p desktopApp test --tests "*NetworkAndLoopbackSecurityTest"`
Expected: PASS.

- [ ] **Step 5: Commit**

```powershell
git add desktopApp
git commit -m "feat(desktop): add Evil-Twin-resistant network lock and loopback Spring Security"
```

---

### Task 3: Dynamic TLS 1.3 LAN Server, Raw-Socket Intrusion Sensor, 60s UDP Discovery & WSS Protocol

**Files:**
- Create: `desktopApp/src/main/java/com/antigravity/blipper/desktop/network/IntrusionEvent.java`
- Create: `desktopApp/src/main/java/com/antigravity/blipper/desktop/network/UdpDiscoveryResponder.java`
- Create: `desktopApp/src/main/java/com/antigravity/blipper/desktop/network/DynamicLanTlsServer.java`
- Test: `desktopApp/src/test/java/com/antigravity/blipper/desktop/network/DynamicLanTlsServerTest.java`

**Interfaces:**
- Consumes: `EphemeralKeyMaterialService`, `SessionStateRegistry`, `WindowsNetworkFingerprintService`
- Produces:
  - `IntrusionEvent(IntrusionType type, String remoteIp, int remotePort, String networkProfile, String gatewayMac, Instant occurredAt, String detail, boolean authorizedConnection)`
  - `DynamicLanTlsServer`:
    - `PairingStartInfo startForPairing(int lanPort, int udpPort, int codeDigits, Duration ttl)` (starts TLS 1.3 `SSLServerSocket` on `lanPort` + `UdpDiscoveryResponder` on `udpPort` for 60s; throws `IllegalStateException` if `WindowsNetworkFingerprintService.isCurrentNetworkTrusted()` is false)
    - `boolean isListening()`
    - `boolean hasActiveAuthenticatedStream()`
    - `boolean sendTaskCompleted(String conversationTitle, String taskSummary)`
    - `void sendNuclearTeardownAndStop()`
    - `void stopImmediately()` (`ServerSocket.close()` + closes active client socket + stops UDP `58444` -> `0` open LAN ports)
    - `void addIntrusionListener(Consumer<IntrusionEvent> listener)`
    - `void setOnRemoteNuclearTeardown(Runnable callback)`

- [ ] **Step 1: Write failing tests in `DynamicLanTlsServerTest.java`**

```java
@Test
void startsClosedAndRawPlaintextTcpProbeFiresUnauthorizedIntrusionEvent() throws Exception {
    // 1. Verify server.isListening() is false at startup (0 open LAN ports)
    // 2. Start pairing on ephemeral test port (0), open raw Socket and send "GET / HTTP/1.1\r\n\r\n"
    // 3. Assert IntrusionEvent of type TLS_HANDSHAKE_FAILED / UNAUTHORIZED_TOUCH fires with 127.0.0.1 and port
}

@Test
void validSixDigitPairingUpgradesToPinnedMtlsWssAndFiresFullParanoiaConnectAlert() throws Exception {
    // 1. Start pairing, complete POST /api/v1/pair/complete with valid PBKDF2-HMAC proof + client ECDSA cert
    // 2. Verify a rogue client with a different ECDSA cert is rejected at TLS/auth and triggers UNAUTHORIZED_TOUCH
    // 3. Connect legitimate paired client to /ws/v1/stream -> verify AUTHENTICATED_DEVICE_CONNECT alert fires (Full Paranoia!),
    //    receive signed TASK_COMPLETED frame, and verify stopImmediately() closes port (new Socket throws ConnectException).
}
```

- [ ] **Step 2: Run test to verify failure**

Run: `$env:JAVA_HOME="C:\Program Files\Android\Android Studio\jbr"; .\desktopApp\gradlew.bat -p desktopApp test --tests "*DynamicLanTlsServerTest"`
Expected: FAIL.

- [ ] **Step 3: Implement `IntrusionEvent`, `UdpDiscoveryResponder`, and `DynamicLanTlsServer`**

Implement `DynamicLanTlsServer` directly over `SSLContext.getInstance("TLSv1.3")` (`SSLServerSocket` with `setEnabledProtocols(new String[]{"TLSv1.3"})`) + minimal RFC 6455 WebSocket & `/api/v1/pair/complete` HTTP/1.1 handler over TLS sockets so **every** `accept()`, TLS handshake failure (`SSLHandshakeException`), unpinned client cert, invalid PIN, and authenticated `/ws/v1/stream` upgrade is deterministically intercepted on the exact socket with full `InetSocketAddress` metadata, and `stopImmediately()` closes `SSLServerSocket` synchronously (`0` open LAN ports). `UdpDiscoveryResponder` replies to `"BLIPPER_DISCOVER_V1"` with `{"proto":"blipper-v1","port":58443,"serverCertSha256":"..."}` strictly while `SessionStateRegistry` is in `PAIRING_WINDOW`, auto-closing at 60s or pairing completion.

- [ ] **Step 4: Run test to verify PASS**

Run: `$env:JAVA_HOME="C:\Program Files\Android\Android Studio\jbr"; .\desktopApp\gradlew.bat -p desktopApp test --tests "*DynamicLanTlsServerTest"`
Expected: PASS.

- [ ] **Step 5: Commit**

```powershell
git add desktopApp
git commit -m "feat(desktop): implement dynamic TLS 1.3 mTLS server, raw intrusion sensor, and 60s UDP discovery"
```

---

### Task 4: Nuclear Teardown Coordinator, Dead-Man Switch & Audit-Log-And-Kill Action

**Files:**
- Create: `desktopApp/src/main/java/com/antigravity/blipper/desktop/network/NuclearTeardownCoordinator.java`
- Test: `desktopApp/src/test/java/com/antigravity/blipper/desktop/network/NuclearTeardownCoordinatorTest.java`

**Interfaces:**
- Consumes: `SessionStateRegistry`, `SecurityAuditLogger`, `WindowsNetworkFingerprintService`, `DynamicLanTlsServer`
- Produces:
  - `NuclearTeardownCoordinator`:
    - `void executeNuclearTeardown(String reason)` (idempotent per active session: sends `NUCLEAR_TEARDOWN` if stream open, stops `DynamicLanTlsServer`, wipes `SessionStateRegistry`, clears approved network, notifies UI listeners)
    - `AuditEntry logIntrusionAndShutdownPort(IntrusionEvent event)` (powers the giant `"🛑 LOGLA VE PORTU ANINDA KAPAT"` button: appends tamper-evident forensic log entry AND calls `executeNuclearTeardown("INTRUSION_EMERGENCY_SHUTDOWN")`)
    - `@Scheduled(fixedDelay = 3000)` watchdog checking network fingerprint drift, TTL expiry, and 30s heartbeat dead-man timeout
    - `@PreDestroy` + JVM `ShutdownHook` ensuring PC app exit sends `NUCLEAR_TEARDOWN` to phone and wipes RAM

- [ ] **Step 1: Write failing tests in `NuclearTeardownCoordinatorTest.java`**

Include concurrency race test firing `executeNuclearTeardown` from 4 threads simultaneously (simulating simultaneous phone teardown + PC button + watchdog), network-change auto-wipe test, 30s dead-man timeout test, and `logIntrusionAndShutdownPort` forensic audit + port closure test.

- [ ] **Step 2: Run test to verify failure**

Run: `$env:JAVA_HOME="C:\Program Files\Android\Android Studio\jbr"; .\desktopApp\gradlew.bat -p desktopApp test --tests "*NuclearTeardownCoordinatorTest"`
Expected: FAIL.

- [ ] **Step 3: Implement `NuclearTeardownCoordinator`**

Guard active teardown transitions with a session generation counter / `AtomicBoolean` so concurrent triggers never loop or deadlock, while always guaranteeing `lanServer.isListening() == false` and `sessionRegistry` wiped on return.

- [ ] **Step 4: Run test to verify PASS**

Run: `$env:JAVA_HOME="C:\Program Files\Android\Android Studio\jbr"; .\desktopApp\gradlew.bat -p desktopApp test --tests "*NuclearTeardownCoordinatorTest"`
Expected: PASS.

- [ ] **Step 5: Commit**

```powershell
git add desktopApp
git commit -m "feat(desktop): add mutual nuclear teardown coordinator and dead-man watchdog"
```

---

### Task 5: Zero-Python Antigravity `Stop` Hook Installer, SQLite/Transcript Reader & Loopback Controller

**Files:**
- Create: `desktopApp/src/main/java/com/antigravity/blipper/desktop/agy/AntigravityConversationReader.java`
- Create: `desktopApp/src/main/java/com/antigravity/blipper/desktop/agy/AntigravityHookInstaller.java`
- Create: `desktopApp/src/main/java/com/antigravity/blipper/desktop/agy/LocalHookController.java`
- Test: `desktopApp/src/test/java/com/antigravity/blipper/desktop/agy/AntigravityHookIntegrationTest.java`

**Interfaces:**
- Consumes: `LocalHookSecretManager`, `DynamicLanTlsServer`
- Produces:
  - `CompletedTaskSummary(String conversationId, String conversationTitle, String taskSummary, String formattedBannerText)` where `formattedBannerText` is `"ANTIGRAVITY: " + conversationTitle + ": " + taskSummary`
  - `AntigravityConversationReader`:
    - `Optional<CompletedTaskSummary> resolveStopPayload(Map<String, Object> stopHookJson)` (ignores events where `terminationReason != "NO_TOOL_CALL"`; reads `title` from read-only `conversation_summaries.db` and ignores child subagent conversations when `parent_conversation_id` is non-empty; extracts clean single-line summary `<= 140` chars from `transcriptPath` last `PLANNER_RESPONSE` `content`, falling back to `lastUserInput`)
  - `AntigravityHookInstaller`:
    - `Path installOrUpdateGlobalStopHook()` (merges `"antigravity-blipper"` entry into `~/.gemini/config/hooks.json` invoking a zero-Python Windows `.cmd` helper `~/.antigravity-blipper/agy-stop-hook.cmd` that posts stdin via `C:\Windows\System32\curl.exe --max-time 2 -s -X POST ...` and **always** echoes `{}` + `exit /b 0` even if `desktopApp` is offline!)
  - `LocalHookController`: `POST /local/v1/agy-stop` dispatching `CompletedTaskSummary` to Desktop Banner listener + `DynamicLanTlsServer.sendTaskCompleted(...)`.

- [ ] **Step 1: Write failing tests in `AntigravityHookIntegrationTest.java`**

Include:
1. Non-ASCII directory path (`tempDir.resolve("Tuğhan/.gemini/antigravity")`) with SQLite WAL-mode `conversation_summaries.db` + multi-line markdown `transcript.jsonl` -> resolves exact `"ANTIGRAVITY: Carbon Merhaba Greeting: Güvenlik modülü tamamlandı"`.
2. Subagent conversation (`parent_conversation_id` populated) or `terminationReason = "USER_CANCELED"` -> ignored cleanly.
3. Executing generated `agy-stop-hook.cmd` via `cmd.exe /c` when port `49871` is NOT listening -> completes in `< 2.5s`, prints `{}`, exits with code `0`.

- [ ] **Step 2: Run test to verify failure**

Run: `$env:JAVA_HOME="C:\Program Files\Android\Android Studio\jbr"; .\desktopApp\gradlew.bat -p desktopApp test --tests "*AntigravityHookIntegrationTest"`
Expected: FAIL.

- [ ] **Step 3: Implement `AntigravityConversationReader`, `AntigravityHookInstaller`, and `LocalHookController`**

Open SQLite via `SQLiteConfig` (`setReadOnly(true)`, `busyTimeout = 1500`). Write `agy-stop-hook.cmd` using `chcp 65001 >nul` + temporary `%TEMP%\blipper-hook-%RANDOM%.json` piped from stdin so `System32\curl.exe --data-binary @file` handles arbitrary JSON quotes/UTF-8 safely, deletes the temp file immediately, prints `{}`, and exits `0`.

- [ ] **Step 4: Run test to verify PASS**

Run: `$env:JAVA_HOME="C:\Program Files\Android\Android Studio\jbr"; .\desktopApp\gradlew.bat -p desktopApp test --tests "*AntigravityHookIntegrationTest"`
Expected: PASS.

- [ ] **Step 5: Commit**

```powershell
git add desktopApp
git commit -m "feat(desktop): add zero-Python Antigravity Stop hook installer and SQLite/transcript reader"
```

---

### Task 6: Native Windows Desktop UI (Top Task Banner, Full-Screen Red Intrusion Alarm, Control Panel & System Tray)

**Files:**
- Create: `desktopApp/src/main/java/com/antigravity/blipper/desktop/ui/SoundSynthesizer.java`
- Create: `desktopApp/src/main/java/com/antigravity/blipper/desktop/ui/TaskCompletedBannerWindow.java`
- Create: `desktopApp/src/main/java/com/antigravity/blipper/desktop/ui/IntrusionAlertWindow.java`
- Create: `desktopApp/src/main/java/com/antigravity/blipper/desktop/ui/ControlPanelWindow.java`
- Create: `desktopApp/src/main/java/com/antigravity/blipper/desktop/ui/DesktopUiOrchestrator.java`
- Create: `desktopApp/src/main/java/com/antigravity/blipper/desktop/BlipperDesktopApplication.java`
- Test: `desktopApp/src/test/java/com/antigravity/blipper/desktop/BlipperDesktopContextTest.java`

**Interfaces:**
- Consumes: All `desktopApp` services from Tasks 1–5
- Produces:
  - `TaskCompletedBannerWindow.showBanner(String bannerText)` (`JDialog`/`JWindow`, `setAlwaysOnTop(true)`, centered at `y = 12` top of primary screen, high-contrast electric cyan/amber border, `"ANTIGRAVITY: <Sohbet Adı>: <Tamamlanan Görev>"`, `[✕]` dismiss button + chime)
  - `IntrusionAlertWindow.showFullScreenAlert(IntrusionEvent event, Runnable onLogAndKillPort)`:
    - Covers full screen (`GraphicsEnvironment` bounds, `setAlwaysOnTop(true)`), flashing crimson border + urgent synthesized siren
    - Displays IP, port, network profile, gateway MAC verification state, timestamp, and event classification
    - Giant red button **`🛑 LOGLA VE PORTU ANINDA KAPAT`** (`minHeight = 110px`, bold 28pt font) invoking `NuclearTeardownCoordinator.logIntrusionAndShutdownPort(event)`
    - Secondary button `[ Tanıyorum, Sadece Uyarıyı Kapat ]`
  - `ControlPanelWindow`: Live security badge (`0 AÇIK PORT` vs `EŞLEŞTİRME (60 sn)` vs `AKTİF ŞİFRELİ OTURUM`), current network approval button, one-click `LocalSubnet` Windows Firewall rule enable/remove helper button, TTL selector (`1–24 Saat` spinner + `Sınırsız` toggle), 6-digit PIN display, *"Test Bildirimi Gönder (Masaüstü + Telefon 5x)"* button, and giant **`BAĞLANTIYI KES VE TÜM KAYITLARI SİL`** button + `SystemTray` icon.
  - `BlipperDesktopApplication`: `SpringApplicationBuilder` launching with `.headless(false)` (honoring `-Dblipper.ui.enabled=false` in CI/unit tests) and auto-installing the Antigravity `Stop` hook on startup.

- [ ] **Step 1: Write failing Spring Boot context & UI wiring test in `BlipperDesktopContextTest.java`**

Verify full Spring context boots cleanly with `blipper.ui.enabled=false`, loopback endpoint `/local/v1/agy-stop` enforces secret auth, LAN server starts closed (`isListening() == false`), and UI model formatters render exact Turkish copy (`"🛑 LOGLA VE PORTU ANINDA KAPAT"`, `"ANTIGRAVITY: ..."`).

- [ ] **Step 2: Run test to verify failure**

Run: `$env:JAVA_HOME="C:\Program Files\Android\Android Studio\jbr"; .\desktopApp\gradlew.bat -p desktopApp test --tests "*BlipperDesktopContextTest"`
Expected: FAIL.

- [ ] **Step 3: Implement `SoundSynthesizer`, `TaskCompletedBannerWindow`, `IntrusionAlertWindow`, `ControlPanelWindow`, `DesktopUiOrchestrator`, and `BlipperDesktopApplication`**

Use `FlatMacDarkLaf.setup()` on the Swing EDT, synthesize non-blocking PCM audio via `AudioSystem.getSourceDataLine`, and assemble executable fat JAR via `bootJar`.

- [ ] **Step 4: Run all `desktopApp` tests and build executable `bootJar`**

Run: `$env:JAVA_HOME="C:\Program Files\Android\Android Studio\jbr"; .\desktopApp\gradlew.bat -p desktopApp check bootJar`
Expected: `BUILD SUCCESSFUL`, fat JAR created under `desktopApp/build/libs/`.

- [ ] **Step 5: Commit**

```powershell
git add desktopApp
git commit -m "feat(desktop): build native Always-On-Top banner, full-screen intrusion alarm, and control UI"
```

---

### Task 7: Android Native Kotlin Project Scaffold, Hardware KeyStore Crypto & Outbound mTLS WSS Client

**Files:**
- Create: `androidApp/settings.gradle.kts`
- Create: `androidApp/build.gradle.kts`
- Create: `androidApp/gradle.properties`
- Create: `androidApp/local.properties`
- Create: `androidApp/app/build.gradle.kts`
- Create: `androidApp/app/src/main/java/com/antigravity/blipper/android/crypto/PairingCryptoEngine.kt`
- Create: `androidApp/app/src/main/java/com/antigravity/blipper/android/crypto/HardwareKeyManager.kt`
- Create: `androidApp/app/src/main/java/com/antigravity/blipper/android/crypto/EphemeralSessionStore.kt`
- Create: `androidApp/app/src/main/java/com/antigravity/blipper/android/network/LanDiscoveryClient.kt`
- Create: `androidApp/app/src/main/java/com/antigravity/blipper/android/network/BlipperSecureWsClient.kt`
- Test: `androidApp/app/src/test/java/com/antigravity/blipper/android/crypto/AndroidSecurityProtocolTest.kt`

**Interfaces:**
- Consumes: Exact wire protocol from Tasks 1 & 3 (`TLSv1.3`, `PBKDF2WithHmacSHA256` `210_000` iter, `SignedEnvelope` JSON format, `/api/v1/pair/complete`, `/ws/v1/stream`, UDP `"BLIPPER_DISCOVER_V1"`)
- Produces:
  - `PairingCryptoEngine`: byte-identical KDF, `computePairingProofHex`, `signEnvelope`, and `verifyEnvelope` (`±30_000ms` + replay cache) matching `desktopApp`'s `EphemeralKeyMaterialService`
  - `HardwareKeyManager`: generates ECDSA P-256 keypair inside `AndroidKeyStore` (`alias = "blipper_ephemeral_session_key"`), builds pinned `SSLContext` + `X509TrustManager` accepting **only** `pinnedServerCertSha256Hex`, and `wipeAllKeys()` deleting the `AndroidKeyStore` entry immediately
  - `EphemeralSessionStore`: in-memory `StateFlow<SessionUiState>` holding active session metadata, TTL countdown, burst count (`5..10`, default `5`), and idempotent `wipeEverything()`
  - `LanDiscoveryClient.discoverDesktop(timeoutMs: Long = 2500L): DiscoveredDesktop?` (single outbound UDP query, closes socket immediately in `use {}`)
  - `BlipperSecureWsClient`: outbound-only OkHttp 4.12 mTLS client performing `/api/v1/pair/complete`, opening `/ws/v1/stream`, running 15s ping/signed-heartbeat + 30s dead-man timeout, emitting verified `TASK_COMPLETED` events, and executing `sendNuclearTeardownAndClose()` idempotently.

- [ ] **Step 1: Scaffold `androidApp` with Gradle `9.5.1`, AGP `9.1.1`, Kotlin Compose `2.4.20`, `compileSdk = 37`, `minSdk = 29`, `targetSdk = 36`, and `sdk.dir=C:\\AndroidSDK`**

Remember AGP `9.1.1` has built-in Kotlin support (apply `com.android.application` + `org.jetbrains.kotlin.plugin.compose`, do NOT apply legacy `org.jetbrains.kotlin.android`). Add OkHttp `4.12.0`, Compose Material 3, and JUnit 4 test dependencies.

- [ ] **Step 2: Write failing tests in `AndroidSecurityProtocolTest.kt`**

Verify:
1. Exact cross-platform test vector parity: given known `pin = "849271"`, `serverCertSha256`, `clientCertSha256`, `timestampMs`, and `nonce`, `PairingCryptoEngine.computePairingProofHex` produces the exact expected hex string and rejects tampered server fingerprints.
2. `verifyEnvelope` rejects replayed `eventId`, forged HMAC, and stale timestamps (`> 30_000ms`).
3. Concurrent calls to `EphemeralSessionStore.wipeEverything()` + teardown trigger execute cleanup once and zeroize session secrets.

- [ ] **Step 3: Run Android unit tests to verify failure**

Run: `$env:JAVA_HOME="C:\Program Files\Android\Android Studio\jbr"; .\androidApp\gradlew.bat -p androidApp testDebugUnitTest --tests "*AndroidSecurityProtocolTest"`
Expected: FAIL.

- [ ] **Step 4: Implement `PairingCryptoEngine.kt`, `HardwareKeyManager.kt`, `EphemeralSessionStore.kt`, `LanDiscoveryClient.kt`, and `BlipperSecureWsClient.kt`**

Ensure zero `ServerSocket` usage anywhere in `androidApp`, strict TLS 1.3 cipher/protocol config on `OkHttpClient.Builder`, and zero disk persistence of session keys.

- [ ] **Step 5: Run Android unit tests to verify PASS**

Run: `$env:JAVA_HOME="C:\Program Files\Android\Android Studio\jbr"; .\androidApp\gradlew.bat -p androidApp testDebugUnitTest --tests "*AndroidSecurityProtocolTest"`
Expected: PASS.

- [ ] **Step 6: Commit**

```powershell
git add androidApp
git commit -m "feat(android): scaffold native Kotlin app with KeyStore mTLS client and crypto engine"
```

---

### Task 8: Samsung-Proof Foreground Service, Screen Wakeup (`WakeAlertActivity`) & >=5x Sequential Notification Engine

**Files:**
- Create: `androidApp/app/src/main/java/com/antigravity/blipper/android/alert/AlertBurstEngine.kt`
- Create: `androidApp/app/src/main/java/com/antigravity/blipper/android/service/BlipperConnectionService.kt`
- Create: `androidApp/app/src/main/java/com/antigravity/blipper/android/service/ShutdownWipeReceiver.kt`
- Create: `androidApp/app/src/main/java/com/antigravity/blipper/android/ui/WakeAlertActivity.kt`
- Create: `androidApp/app/src/main/java/com/antigravity/blipper/android/ui/PermissionHelper.kt`
- Create: `androidApp/app/src/main/java/com/antigravity/blipper/android/ui/BlipperMainScreen.kt`
- Create: `androidApp/app/src/main/java/com/antigravity/blipper/android/ui/MainActivity.kt`
- Create: `androidApp/app/src/main/AndroidManifest.xml`
- Test: `androidApp/app/src/test/java/com/antigravity/blipper/android/alert/AlertBurstEngineTest.kt`

**Interfaces:**
- Consumes: `HardwareKeyManager`, `EphemeralSessionStore`, `LanDiscoveryClient`, `BlipperSecureWsClient`
- Produces:
  - `AlertBurstEngine(dispatcher: BurstNotificationDispatcher, delayMs: Long = 900L)`:
    - `suspend fun triggerTaskCompletedBurst(eventId: String, conversationTitle: String, taskSummary: String, count: Int = 5)`:
      - Enforces `effectiveCount = maxOf(5, count)`
      - Acquires 15s `PARTIAL_WAKE_LOCK` (via `BurstNotificationDispatcher`)
      - Immediately triggers `WakeAlertActivity` full-screen wakeup (`FullScreenIntent`)
      - Emits `effectiveCount` sequential notifications (`900ms` apart) with strictly distinct integer IDs, unique tags, `IMPORTANCE_HIGH`, `CATEGORY_ALARM`, title `"ANTIGRAVITY [$i/$effectiveCount]: $conversationTitle"`, body `taskSummary`, and releases `WakeLock` in `finally`
  - `BlipperConnectionService`: `ForegroundService` (`foregroundServiceType="specialUse"` with required `<property android:name="android.app.PROPERTY_SPECIAL_USE_FGS_SUBTYPE" .../>`), acquires `WifiLock(WIFI_MODE_FULL_LOW_LATENCY)`, handles `ACTION_NUCLEAR_DISCONNECT`, `onTaskRemoved`, TTL expiry, and 30s dead-man switch -> sends `NUCLEAR_TEARDOWN` to PC, deletes `AndroidKeyStore` keys, wipes session, and calls `stopSelf()`
  - `ShutdownWipeReceiver`: listens for `Intent.ACTION_SHUTDOWN` and triggers immediate nuclear teardown so PC port closes when phone powers off
  - `WakeAlertActivity`: `setShowWhenLocked(true)`, `setTurnScreenOn(true)`, `FLAG_KEEP_SCREEN_ON`, dark high-contrast full-screen wakeup card with *"GÖRDÜM / SUSTUR"* button
  - `BlipperMainScreen` + `PermissionHelper`: Samsung 3-permission status cards (`POST_NOTIFICATIONS`, `REQUEST_IGNORE_BATTERY_OPTIMIZATIONS`, `USE_FULL_SCREEN_INTENT`), LAN discovery button + manual IP input + 6-digit PIN field + burst count selector (`5..10`) + giant red **`BAĞLANTIYI KES VE HER ŞEYİ SİL`** button.

- [ ] **Step 1: Write failing unit tests in `AlertBurstEngineTest.kt`**

```kotlin
@Test
fun `triggerTaskCompletedBurst enforces minimum 5 distinct notification IDs and wakes screen first`() = runTest {
    val fakeDispatcher = FakeBurstDispatcher()
    val engine = AlertBurstEngine(fakeDispatcher, delayMs = 900L)

    // Even if caller passes count = 2, spec requires >= 5!
    engine.triggerTaskCompletedBurst("evt-1", "Carbon Merhaba Greeting", "Modül tamamlandı", count = 2)

    assertTrue(fakeDispatcher.wakeLockAcquired)
    assertTrue(fakeDispatcher.wakeScreenTriggeredFirst)
    assertEquals(5, fakeDispatcher.postedNotifications.size)
    assertEquals(5, fakeDispatcher.postedNotifications.map { it.notificationId }.toSet().size)
    assertEquals("ANTIGRAVITY [1/5]: Carbon Merhaba Greeting", fakeDispatcher.postedNotifications.first().title)
    assertEquals("ANTIGRAVITY [5/5]: Carbon Merhaba Greeting", fakeDispatcher.postedNotifications.last().title)
    assertTrue(fakeDispatcher.wakeLockReleased)
}
```

- [ ] **Step 2: Run test to verify failure**

Run: `$env:JAVA_HOME="C:\Program Files\Android\Android Studio\jbr"; .\androidApp\gradlew.bat -p androidApp testDebugUnitTest --tests "*AlertBurstEngineTest"`
Expected: FAIL.

- [ ] **Step 3: Implement `AlertBurstEngine`, `BlipperConnectionService`, `ShutdownWipeReceiver`, `WakeAlertActivity`, `PermissionHelper`, `BlipperMainScreen`, `MainActivity`, and `AndroidManifest.xml`**

Declare `FOREGROUND_SERVICE`, `FOREGROUND_SERVICE_SPECIAL_USE`, `WAKE_LOCK`, `ACCESS_WIFI_STATE`, `INTERNET`, `POST_NOTIFICATIONS`, `REQUEST_IGNORE_BATTERY_OPTIMIZATIONS`, and `USE_FULL_SCREEN_INTENT` in `AndroidManifest.xml` (zero `ACCESS_FINE_LOCATION` or unnecessary invasive permissions!).

- [ ] **Step 4: Run Android unit tests and assemble installable `debug` APK**

Run: `$env:JAVA_HOME="C:\Program Files\Android\Android Studio\jbr"; .\androidApp\gradlew.bat -p androidApp testDebugUnitTest assembleDebug`
Expected: `BUILD SUCCESSFUL`, APK produced at `androidApp/app/build/outputs/apk/debug/app-debug.apk`.

- [ ] **Step 5: Commit**

```powershell
git add androidApp
git commit -m "feat(android): add Samsung wake/5x burst engine, specialUse foreground service, and Compose UI"
```

---

### Task 9: End-to-End Desktop <-> Android Wire Protocol Verification & Launch Scripts

**Files:**
- Create: `desktopApp/src/test/java/com/antigravity/blipper/desktop/e2e/EndToEndBlipperFlowTest.java`
- Create: `start-desktop.bat`

**Interfaces:**
- Consumes: Built `desktopApp` Spring Boot context + exact Android pairing/WSS frame sequence + `AntigravityHookInstaller`
- Produces:
  - Automated end-to-end verification test proving the complete lifecycle:
    1. Boot starts with `0` open LAN ports.
    2. Trusted Home Network approved -> 60s pairing opened -> UDP discovery returns `serverCertSha256` -> simulated Android client pairs with 6-digit PIN + ECDSA cert -> upgrades to pinned mTLS 1.3 WSS -> Full Paranoia `IntrusionAlertWindow` event fires for connection.
    3. Simulated Antigravity `Stop` hook posts to `127.0.0.1:49871/local/v1/agy-stop` -> Desktop banner receives `"ANTIGRAVITY: <Sohbet Adı>: <Tamamlanan Görev>"` AND Android WSS stream receives signed `TASK_COMPLETED` envelope -> sends signed `ACK`.
    4. Simulated rogue socket touches LAN port -> `IntrusionEvent` logged via `logIntrusionAndShutdownPort` -> `NUCLEAR_TEARDOWN` delivered to Android client -> LAN port closes (`0` open ports) -> all secrets zeroized -> hash chain in `security-audit.jsonl` validates `true`.
  - `start-desktop.bat`: one-click native Windows launcher using OpenJDK 21 (`jbr\bin\javaw.exe -jar desktopApp\build\libs\...`) with zero console clutter or Python.

- [ ] **Step 1: Write `EndToEndBlipperFlowTest.java` covering the full 4-stage lifecycle above**

- [ ] **Step 2: Run full test suites across both `desktopApp` and `androidApp` and create `start-desktop.bat`**

Run:
```powershell
$env:JAVA_HOME="C:\Program Files\Android\Android Studio\jbr"
.\desktopApp\gradlew.bat -p desktopApp test bootJar
.\androidApp\gradlew.bat -p androidApp testDebugUnitTest assembleDebug
```
Expected: `BUILD SUCCESSFUL` on both projects, `0` test failures, zero `.py` or `.php` files in repository (`Get-ChildItem -Recurse -Include *.py,*.php` returns empty).

- [ ] **Step 3: Commit**

```powershell
git add desktopApp start-desktop.bat
git commit -m "test(e2e): verify full Antigravity hook, mTLS pairing, 5x alert, and nuclear teardown flow"
```
