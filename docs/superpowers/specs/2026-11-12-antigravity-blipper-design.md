# AntigravityBlipper — Tasarım Dokümanı (Design Specification)

**Tarih:** 2026-11-12  
**Durum:** Teknik Denetim Tamamlandı — Kullanıcı Onayı Bekliyor  
**Çalışma Alanı:** `c:\AntigravityBlipper` (`desktopApp/`, `androidApp/`)

---

## 1. Amaç ve Neden (Intent & Why)

Antigravity ile proje geliştirirken bir görev tamamlandığında standart bildirim yeterince dikkat çekmiyor; ayrıca kullanıcı bilgisayar başından kalktığında (ev içinde başka odadayken) görevin bittiğini kesin olarak duymak ve görmek istiyor.

Bu proje aynı anda iki gerçek dünya problemini sıfır tavizle çözer:
1. **Samsung (One UI) Bildirim Biriktirme Sorunu:** Samsung telefonlarda pil ayarı "Kısıtlanmamış" yapılsa ve arka plan izinleri verilse bile, sıradan arka plan soketleri ekran kapandığında **Freecess / Doze** tarafından dondurulur; uygulama bildirimleri içinde biriktirip ancak kullanıcı uygulamayı elle açtığında oluşturur. AntigravityBlipper, telefon kilitli ve ekranı kapalı olsa bile dürtüldüğü anda ekranı uyandıracak ve **en az 5 kez üst üste gerçek bildirim** fırlatacaktır.
2. **Sıfır Güven ("Güvenlik > Birkaç Tıklama") Mimari:** Ev içi Wi-Fi haberleşmesi kafe gibi ortak ağlarda en ufak bir siber güvenlik açığı yaratmamalıdır. Hem masaüstü hem Android uygulaması **Tam Paranoya** ve **Karşılıklı Tam İmha (Zero-Persistence)** prensibiyle çalışır: bağlantı kesildiğinde veya taraflardan biri kapatıldığında her iki cihazda da tüm portlar/servisler kapanır ve tüm eşleşme anahtarları/kayıtları tamamen silinir.

---

## 2. Hedefler, Kapsam Dışı Olanlar ve Kesin Yasaklar

### Hedefler (Goals)
1. **Antigravity Görev Bitişini Anında Yakalama (Sıfır Python):** Antigravity'nin resmi `Stop` hook mekanizması (`~/.gemini/config/hooks.json`) üzerinden görev bittiği salisede sohbet adını (`conversation_summaries.db`) ve tamamlanan görev özetini (`transcript.jsonl`) doğrudan Java içinden yakalamak.
2. **Masaüstü En Üst Görev Penceresi (`desktopApp`):** Bilgisayar ekranının en üstünde, tüm pencerelerin üzerinde (`Always-On-Top`) `"ANTIGRAVITY: <Sohbet Adı>: <Tamamlanan Görev>"` gösteren yerel masaüstü penceresi çıkarmak.
3. **Samsung Uyumlu Anında Dürtme & Ekran Uyandırma (`androidApp`):** Bilgisayar dürttüğünde ekran kapalı/kilitli olsa bile ekranı açmak (`Full-Screen Intent` + `WakeLock` + `TurnScreenOn`) ve **en az 5 adet** ayrı, sesli/titreşimli yüksek öncelikli bildirimi arka arkaya (birleştirilmeden) düşürmek.
4. **Tam Paranoya & Karşılıklı İmha Güvenlik Modeli:**
   - **Varsayılan Olarak Kapalı LAN Portu & Gizli Mod:** Uygulama açıldığında LAN portu **kapalı** başlar (`0` açık LAN portu) ve ağda hiçbir yayın yapılmaz. Keşif ve eşleşme yalnızca kullanıcı *"Eşleştirme Başlat"* dediğinde **60 saniyeliğine** açılır.
   - **En Az 6 Haneli Tek Kullanımlık Kod:** Kriptografik rastgele (`SecureRandom`) en az 6 haneli kod ile eşleşme; yanlış kod denemesinde anında alarm ve iptal (maksimum 3 deneme tavanı, her hatada kırmızı alarm).
   - **Geçici (Ephemeral) mTLS 1.3 + Sertifika Sabitleme + Spring Security:** Her yeni eşleşmede sıfırdan tek kullanımlık ECDSA P-256 anahtar çifti ve X.509 sertifikası üretilir; diskte kalıcı eşleşme verisi tutulmaz.
   - **Yetki Süresi (TTL):** Eşleşme sırasında cihaza **1–24 saat arası** (kullanıcı seçimi) veya **Sınırsız** (oturum açık kaldığı sürece) izin verilir; süre dolduğu salise iki tarafta da bağlantı kesilir ve tüm anahtarlar imha edilir.
   - **Ev Ağı Kilidi & Kafe Koruması:** LAN portu yalnızca kullanıcının o oturum için onayladığı Ev Ağı profilinde ve aynı fiziksel modem MAC adresinde (`Gateway MAC`) açık kalabilir; ağ değiştiği anda (ör. Kafe Wi-Fi) port otomatik kapanır ve tüm anahtarlar silinir. Telefonda ise hiçbir zaman dinleyen port açılmaz (`%100 outbound`).
   - **Tam Paranoya Kırmızı Güvenlik Alarmı & Dev `"LOGLA VE PORTU ANINDA KAPAT"` Butonu:**
     - LAN portuna tanınmayan bir cihazdan gelen **herhangi bir** temas (port taraması, geçersiz TLS el sıkışması, bilinmeyen sertifika, yanlış kod) **VEYA** doğrulanmış kendi telefonunun **her bağlanışı / her yeniden bağlanışı** bilgisayarda tüm ekranı kaplayan, sesli **Tam Ekran Kırmızı Alarm** penceresini tetikler.
     - Ekrandaki devasa **`🛑 LOGLA VE PORTU ANINDA KAPAT`** butonuna basıldığı anda tüm izler güvenlik loguna yazılır, LAN portu kapatılır ve her iki cihazdaki tüm anahtarlar/kayıtlar silinir.
   - **Karşılıklı Tam İmha (`Bağlantıyı Kes` / `Kapat` / `Çıkış`):**
     - **Bilgisayardan** *"Bağlantıyı Kes / Kapat"* basılırsa veya bilgisayar uygulaması kapatılırsa: telefona imzalı imha sinyali gönderilir, bilgisayarın LAN portu kapanır, bilgisayardaki ve telefondaki **tüm kayıtlı cihazlar, eşleşmeler ve şifreli anahtarlar tamamen silinir**, telefonun arka plan servisi durdurulur.
     - **Telefondan** *"Bağlantıyı Kes / Kapat"* basılırsa veya telefon/uygulama kapatılırsa: bilgisayara imzalı imha sinyali gönderilir, **bilgisayarın LAN portu da anında kapatılır**, her iki cihazdaki **tüm kayıtlı cihazlar, eşleşmeler ve şifreli anahtarlar tamamen silinir**.
     - Beklenmedik fiziksel kopmalarda (ör. fiş çekilmesi veya Wi-Fi'nin tamamen kesilmesi; kısa 30 sn nabız zaman aşımı aşıldığında) karşı taraf da otomatik olarak kendi portunu/servisini kapatır ve tüm anahtarlarını sıfırlar.

### Kapsam Dışı (Non-Goals)
- Bulut sunucusu, Firebase veya internet üzerinden uzaktan bildirim (%100 yerel ağ mimarisi).
- Kalıcı cihaz rehberi veya otomatik hatırla özelliği (kullanıcı kararıyla güvenlik için her oturum sıfırdan eşleşir).

### Kesin Yasaklar (Anti-Goals)
- **Web uygulaması veya tarayıcı tabanlı arayüz KESİNLİKLE YOKTUR** (saf masaüstü pencere arayüzü + saf Native Kotlin Android uygulaması).
- **Python veya PHP KESİNLİKLE YOKTUR** (hook tetikleyicisi, ağ kontrolü ve SQLite okuma dahil hiçbir yerde tek satır Python/PHP kullanılmayacak).
- Şifresiz (plaintext HTTP/TCP) yerel ağ iletişimi kesinlikle olmayacak.
- Bildirimlerin Samsung'da uygulama açılana kadar içeride birikmesi kesinlikle kabul edilemez.

---

## 3. Ortam ve Kısıtlar (Constraints)

- **İşletim Sistemi (Desktop):** Windows 11 (`C:\Users\Tuğhan\...` — Türkçe karakterli yollar UTF-8 ve `java.nio.file.Path` ile güvenli işlenecek).
- **Windows Konum Servisi Durumu:** Hedef bilgisayarda Windows Konum Servisi kapalıdır (`netsh wlan show interfaces` Konum izni olmadan `Error 5` döndürür). Bu nedenle ağ kilidi Konum izni gerektirmeyen Windows Ağ Profili + Modem Fiziksel MAC (`Gateway ARP MAC`) doğrulamasıyla çalışacaktır.
- **Mevcut Araçlar:**
  - **JDK:** OpenJDK 21 (`C:\Program Files\Android\Android Studio\jbr`, `21.0.10` LTS).
  - **Android SDK:** `C:\AndroidSDK` (`platforms/android-36.1`, `build-tools/36.1.0`).
  - **Gradle Önbelleği:** Gradle 9.x dağıtımları kullanıcı makinesinde hazır.
  - **Windows Yerleşik Araçlar:** `System32\curl.exe`, PowerShell / CIM ağ sorguları (`arp.exe` / `Get-NetConnectionProfile`).

---

## 4. Değerlendirilen Yaklaşımlar ve Seçim (Approaches)

1. **Yaklaşım 1 — %100 Yerel Wi-Fi + Ev Ağı Kilidi + Java Spring Boot mTLS + Tam Paranoya & Karşılıklı İmha *(SEÇİLEN)*:**
   - **Özeti:** Telefon `0` açık portla yalnızca dışarıya (`outbound` WSS/mTLS) bağlanır. Bilgisayar ise Spring Boot + Spring Security + mTLS 1.3 portunu sadece onaylı Ev Ağında ve yalnızca eşleşme/aktif oturum süresince açar. Her bağlantıda ve her yabancı temasta Tam Ekran Kırmızı Alarm devreye girer; bağlantı kesildiğinde veya kapatıldığında iki taraf da kendini sıfırlar.
   - **Artısı:** Sıfır bulut bağımlılığı, sıfır kalıcı saldırı yüzeyi, milisaniye altı gecikme, tam fiziksel port kontrolü.
   - **Ödünü:** Her kapatma/kesme sonrasında yeniden 6 haneli kodla eşleşme gerekir (kullanıcı tarafından bilinçli olarak tercih edildi: *"Güvenlik > Birkaç tıklama"*).

2. **Yaklaşım 2 — Bulut Röleli "Cloudflare Tunnel" Modeli (%100 Çift Taraflı Outbound):**
   - **Neden elendi:** Üçüncü parti bulut/internet bağımlılığı gerektiriyor; kullanıcı yerel ağda tam fiziksel kontrol ve Spring Security zırhı seçti.

---

## 5. Mimari ve Güvenlik Tasarımı

### 5.1 Genel Sistem Akışı

```text
[Antigravity Stop Hook (cmd + System32\curl.exe, 0 Python)]
        │  POST http://127.0.0.1:49871/local/v1/agy-stop (X-Blipper-Local-Secret)
        ▼
[desktopApp: Java 21 + Spring Boot 3 + Spring Security (Headless=false Native Swing/FlatLaf UI)]
   ├─► SQLite Salt-Okunur Okuyucu (`sqlite-jdbc`) -> `conversation_summaries.db` + `transcript.jsonl`
   ├─► Masaüstü Always-On-Top Üst Pencere -> "ANTIGRAVITY: <Sohbet Adı>: <Tamamlanan Görev>"
   └─► Dinamik LAN mTLS 1.3 Sunucusu (`58443`, Varsayılan KAPALI, Yalnızca Bellekte Geçici Anahtarlar)
           │  ├─► [Ham Soket + TLS + Oturum Denetçisi (Tam Paranoya)]
           │  │     -> Yabancı temas ANINDA engellenir + TAM EKRAN KIRMIZI ALARM
           │  │     -> Doğrulanmış cihazın HER bağlanışında da TAM EKRAN KIRMIZI ALARM
           │  │     -> [ 🛑 LOGLA VE PORTU ANINDA KAPAT ] => Logla + İki Cihazda Her Şeyi Sil + Portu Kapat!
           │  ▼  Şifreli WSS (mTLS 1.3 + Spring Security Token + HMAC + Anti-Replay Nonce)
[androidApp: Native Kotlin + Jetpack Compose + OkHttp mTLS + ForegroundService]
   ├─► Donanım `AndroidKeyStore` Geçici Anahtar (Kapanışta/Kesmede Tamamen Silinir)
   ├─► `WifiLock` + `PARTIAL_WAKE_LOCK` + 15 sn Nabız (Samsung Freecess/Doze engeli)
   ├─► Kapalı Ekranı Açma (`Full-Screen Intent` -> `WakeAlertActivity` + `setTurnScreenOn(true)`)
   └─► En Az 5 Ardışık Yüksek Öncelikli Gerçek Bildirim (900ms aralıkla, ayrı ID'lerle, ses + titreşim)
```

### 5.2 `desktopApp` — Java 21 + Spring Boot 3 + Spring Security Masaüstü Uygulaması

- **Çalışma Modu *(Mühendislik Kararı)*:** `SpringApplicationBuilder` ile `headless(false)` modunda çalışan tek bir JVM masaüstü uygulaması. Tarayıcı kesinlikle kullanılmaz; **Swing/AWT + FlatLaf Modern Dark** ile yerel Windows pencereleri (`JWindow` / `JFrame` / `SystemTray`) kullanılır.
- **Sıfır Kalıcı Sır (RAM-Only Ephemeral Identity):**
  - Masaüstü uygulamasında eşleşme anahtarları, geçici X.509 sertifikaları, oturum jetonları ve bağlı cihaz bilgileri **yalnızca RAM üzerinde (`char[]` / `byte[]` sıfırlanabilir bellek yapıların içinde)** tutulur; diske hiçbir eşleşme anahtarı yazılmaz!
  - Diskte yalnızca iki yerel dosya bulunur:
    1. `~/.antigravity-blipper/local-hook.secret`: Sadece `127.0.0.1` loopback Antigravity hook doğrulaması için 256-bit yerel sır (her uygulama açılışında tazelenebilir veya kullanıcı ACL korumalı tutulur).
    2. `~/.antigravity-blipper/security-audit.jsonl`: `"LOGLA VE PORTU ANINDA KAPAT"` ve saldırı girişimlerinin SHA-256 zincirli adli güvenlik kayıtları.
- **Çift Port İzolasyonu *(Mühendislik Kararı)*:**
  1. **Yerel Hook Portu (`127.0.0.1:49871`):** Sadece loopback arayüzüne bağlıdır; dış ağdan fiziksel olarak ulaşılamaz. Spring Security `LocalHookAuthenticationFilter` ile `X-Blipper-Local-Secret` başlığını sabit zamanlı (`MessageDigest.isEqual`) doğrular. LAN portu tamamen kapalıyken bile masaüstündeki üst bildirim penceresi çalışmaya devam eder.
  2. **Dinamik LAN Güvenlik Sunucusu (`0.0.0.0:58443`):** Uygulama açıldığında **KAPALIDIR**. Yalnızca kullanıcı Ev Ağını onaylayıp *"Eşleştirme Başlat (60 sn)"* dediğinde açılır; eşleşme iptal edildiğinde, bağlantı kesildiğinde, süre (`1–24 saat`) dolduğunda, ağ değiştiğinde veya her iki cihazdan biri kapatıldığında `ServerSocket` fiziksel olarak kapatılır (`netstat` üzerinde `0` açık LAN portu). *(İlk kurulumda Windows Güvenlik Duvarı `Public` profil engeline takılmamak için yalnızca `LocalSubnet` kapsamlı kural ekleme/kaldırma yardımcısı sunulur.)*
- **Windows Konum Servisi Kapalıyken Çalışan Ev Ağı + Modem MAC Kilidi *(Mühendislik Kararı)*:**
  - Windows Konum Servisi'ni açtırmaya gerek kalmadan, mevcut aktif ağın **Ağ Profil Adı** (`MSFT_NetConnectionProfile` — Wi-Fi'de SSID adıdır, kabloluda Ethernet profil adıdır), **Alt Ağ Öneki** ve **Varsayılan Ağ Geçidi Fiziksel MAC Adresi (`Gateway ARP MAC`)** birlikte parmak izi olarak alınır.
  - Kullanıcı eşleştirme öncesi mevcut ağı *"Mevcut Ağı Bu Oturum İçin Onayla"* ile onaylar. Arka plan bekçisi her 3 saniyede ağ profilini ve modem MAC adresini kontrol eder; kafede başka bir Wi-Fi'ye geçildiği anda (veya aynı Wi-Fi adını taklit eden sahte bir modem/Evil Twin algılandığında) LAN portu salisesinde kapatılır ve tüm bellek anahtarları silinir!
- **Antigravity Entegrasyonu (Sıfır Python):**
  - `~/.gemini/config/hooks.json` içindeki `Stop` hook'u Windows yerleşik `System32\curl.exe` komutuyla `stdin` JSON verisini `http://127.0.0.1:49871/local/v1/agy-stop` adresine iletir ve anında `{}` / izin çıktısı döndürür.
  - `terminationReason == "NO_TOOL_CALL"` (ve `fullyIdle == true` veya kök sohbet tamamlanması) durumunda `sqlite-jdbc` ile `~/.gemini/antigravity/conversation_summaries.db` (`?mode=ro` salt-okunur) üzerinden `title` (Sohbet Adı) okunur; `transcriptPath` JSONL dosyasındaki son model yanıtından tamamlanan görev özeti çıkarılır.
- **Masaüstü Pencereleri:**
  1. **Üst Görev Tamamlandı Penceresi (`TaskCompletedBannerWindow`):** Ekranın en üst ortasında, `Always-On-Top`, dikkat çekici ses ve parlak vurguyla:
     `"ANTIGRAVITY: <Sohbet Adı>: <Tamamlanan Görev Özeti>"` + `[✕]` kapatma butonu.
  2. **Tam Ekran Kırmızı Güvenlik Alarmı (`IntrusionAlertWindow` — Tam Paranoya Modu):**
     - **Tetikleyiciler:**
       - Tanınmayan bir IP'den gelen herhangi bir TCP/TLS teması, port taraması, geçersiz sertifika, geçersiz oturum jetonu veya hatalı 6 haneli kod -> **Bağlantı anında reddedilir + Tam Ekran Kırmızı Alarm + Siren!**
       - Doğrulanmış eşleşmiş telefonun **her bağlanışı ve her yeniden bağlanışı** -> **Tam Ekran Kırmızı Alarm + Sesli Uyarı!** *(Doğrulanmış bağlantıda kullanıcı masaya gelene kadar bildirim akışı kesilmez; ancak ekrandaki dev buton her an tek tıkla her şeyi imha etmeye hazırdır. Yalnızca 60 saniyelik aktif eşleştirme penceresinde ilk `/pair` isteği kod kontrolünü bekler ki ekrandaki 6 haneli kod kapanmasın; kod yanlışsa veya eşleşme bittiğinde bağlantı kurulurken alarm yine anında açılır.)*
     - **Görünüm & Aksiyonlar:**
       - Tüm monitörü kaplar (`Always-On-Top`), kaynak IP, port, ağ adı, modem MAC durumu, zaman ve bağlantı/tehdit türünü dev puntolarla gösterir.
       - **Devasa Buton — `🛑 LOGLA VE PORTU ANINDA KAPAT`:** Basıldığı anda olayı `security-audit.jsonl` dosyasına yazar, bağlı cihaza (varsa) imha sinyali yollar, LAN portunu fiziksel olarak kapatır ve RAM'deki tüm anahtarları sıfırlar!
       - İkincil Buton — `[ Tanıyorum, Sadece Uyarıyı Kapat ]`: Yalnızca doğrulanmış kendi cihazının bağlantı uyarısını ekrandan kaldırmak için kullanılır (yabancı/reddedilen temaslarda ise port zaten o IP'yi reddetmiştir; kullanıcı dilerse tek tıkla portu tamamen kapatır).
  3. **Ana Kontrol Paneli & Sistem Tepsisi (`ControlPanelWindow` + `SystemTray`):**
     - Canlı Port & Güvenlik Durumu (`KAPALI — 0 AÇIK PORT` / `EŞLEŞTİRME BEKLİYOR (60sn)` / `AKTİF ŞİFRELİ OTURUM`).
     - Yetki Süresi Seçici: `1–24 Saat` (`JSpinner` / hızlı seçim butonları: `1s, 2s, 4s, 8s, 12s, 24s`) ve `Sınırsız`.
     - **"Eşleştirme Başlat (60 sn)"** butonu (en az 6 haneli tek kullanımlık kod üretir).
     - **Dev `"BAĞLANTIYI KES VE TÜM KAYITLARI SİL"` Butonu:** Hem bilgisayarı hem telefonu anında sıfırlar ve LAN portunu kapatır.
     - **"Test Bildirimi Gönder (Masaüstü + Telefon 5x)"** butonu.

### 5.3 Kriptografik Eşleşme, Spring Security ve Karşılıklı İmha Protokolü

1. **60 Saniyelik Gizli Keşif + 6+ Haneli MITM Korumalı Eşleşme:**
   - Masaüstünde *"Eşleştirme Başlat"* tıklandığında RAM'de taze bir **ECDSA P-256** sunucu anahtar çifti üretilir, yalnızca 60 saniye boyunca yerel alt ağda UDP keşif yanıtlayıcısı (`58444`) açılır (yalnızca port ve `serverCertSha256` döner; kod asla ağdan geçmez).
   - Telefon da `AndroidKeyStore` içinde taze bir **ECDSA P-256** istemci anahtar çifti üretir, TLS 1.3 üzerinden bağlanır ve `PBKDF2-HMAC-SHA256(6_haneli_kod, salt = serverCertSha256 || clientCertSha256, iter = 210_000)` ile türetilmiş kanıtı sunar.
   - Yanlış kod girildiği anda eşleşme iptal edilir, port kilitlenir ve Tam Ekran Kırmızı Alarm patlar.
2. **Spring Security Katmanları (Masaüstü) & Kotlin Security Interceptor (Android):**
   - **Katman 1 — Ağ & Fiziksel Modem MAC Kilidi:** Onaylı ağ dışına çıkıldığı an her şey silinir ve port kapanır.
   - **Katman 2 — mTLS 1.3 (`clientAuth = NEED`) & Çift Yönlü Sertifika Sabitleme (`SHA-256` Pinning):** Eşleşme bittiği salise sunucu sadece o tek istemci sertifikasını, telefon da sadece o tek sunucu sertifikasını kabul eder.
   - **Katman 3 — Spring Security Oturum Filtresi & TTL Bekçisi:** Her çerçevede `sessionId`, `deviceId`, `expiresAt` (`1–24 saat` veya `Sınırsız`) doğrulanır.
   - **Katman 4 — Mesaj Seviyesi İmza & Anti-Replay:** Her WebSocket (`WSS`) mesajı `eventId (UUID)` + `timestamp (±30 sn)` + `HMAC-SHA256` taşır; tekrar oynatılan paketler anında reddedilir ve alarm üretir.
3. **Karşılıklı Tam İmha (`NUCLEAR_WIPE_AND_SHUTDOWN`) Garantisi:**
   - Aşağıdaki olaylardan **herhangi biri** gerçekleştiğinde karşılıklı imha protokolü çalışır:
     1. Bilgisayarda *"Bağlantıyı Kes"*, *"Portu Kapat"* veya *"LOGLA VE PORTU ANINDA KAPAT"* tıklanması,
     2. Bilgisayar uygulamasının kapatılması (`JVM ShutdownHook` + `@PreDestroy`) veya bilgisayarın kapanması,
     3. Telefonda *"Bağlantıyı Kes / Kapat"* tıklanması, telefon uygulamasının/servisinin kapatılması (`Service.onTaskRemoved` / durdurma aksiyonu) veya telefonun kapanması (`ACTION_SHUTDOWN` BroadcastReceiver),
     4. Seçilen yetki süresinin (`1–24 saat`) dolması,
     5. Ağ bağlantısının 30 saniyeden uzun süre tamamen kopması (terk edilmiş açık port kalmaması için!).
   - **Sonuç:** Aktif taraf karşı tarafa imzalı `NUCLEAR_TEARDOWN` çerçevesi yollar -> **Bilgisayar** LAN portunu (`58443`) kapatır ve RAM'deki tüm anahtarları/oturumları sıfırlar -> **Telefon** `AndroidKeyStore` anahtarını siler, tüm şifreli oturum belleğini temizler ve `BlipperConnectionService` ön plan servisini tamamen durdurur (`0` açık port, `0` kayıtlı cihaz, `0` anahtar!).

### 5.4 `androidApp` — Native Kotlin + Samsung Uyumlu Uyandırma & Güvenlik Mimarisi

- **Teknoloji:** **%100 Native Kotlin**, **Jetpack Compose (Material 3 koyu güvenlik teması)**, `minSdk = 29` (Android 10+), `targetSdk = 36`.
- **Android Güvenlik Mimarisi (Spring Security Eşdeğeri Katmanlar):**
  - `0` dinleyen port (`ServerSocket` kesinlikle yoktur).
  - Donanım destekli `AndroidKeyStore` ECDSA P-256 anahtar üretimi ve iş bitince `keyStore.deleteEntry(...)` ile kriptografik imha.
  - Özel `X509TrustManager` ile sertifika sabitleme (sistem CA'larına güvenmez, sadece o oturumdaki masaüstü `SHA-256` özetine güvenir).
  - Gelen her `TASK_COMPLETED` ve `NUCLEAR_TEARDOWN` paketinde sabit zamanlı `HMAC-SHA256`, zaman penceresi (`±30 sn`) ve `ReplayCache` doğrulaması (`SecurityFrameVerifier`).
- **Samsung One UI Bildirim Biriktirmesini Kesen Mekanizma:**
  1. **Ön Plan Servisi (`BlipperConnectionService`, `specialUse`):** Yalnızca aktif eşleşme süresince çalışır; bağlantı kesildiği anda servis tamamen kapanır (boşta arka planda bile çalışmaz!). Aktifken `WifiLock(WIFI_MODE_FULL_LOW_LATENCY)` ve 15 saniyelik şifreli WSS ping/pong nabzı ile Samsung Freecess'in soketi dondurmasını engeller.
  2. **İlk Açılış Samsung İzin Kontrol Kartı:** `POST_NOTIFICATIONS`, `REQUEST_IGNORE_BATTERY_OPTIMIZATIONS` ve kilit ekranını uyandırmak için zorunlu `USE_FULL_SCREEN_INTENT` (`canUseFullScreenIntent()`) izinlerini tek ekranda kontrol edip tek dokunuşla ilgili ayar sayfasına yönlendirir.
  3. **Kapalı Ekranı Uyandırma + En Az 5 Gerçek Bildirim (`AlertBurstEngine`):**
     - İmzası doğrulanmış `TASK_COMPLETED` paketi geldiği salise 15 saniyelik `PowerManager.PARTIAL_WAKE_LOCK` alınır.
     - **Ekranı Açma:** `FullScreenIntent` ile `WakeAlertActivity` fırlatılır (`setShowWhenLocked(true)`, `setTurnScreenOn(true)`, `FLAG_KEEP_SCREEN_ON`); kilitli ve kapalı Samsung ekranı anında aydınlanır, görev başlığı/özeti tam ekran gösterilir.
     - **En Az 5 Ardışık Gerçek Bildirim:** `IMPORTANCE_HIGH` + `CATEGORY_ALARM` kanalından, Android'in gruplayıp yutmasını önlemek üzere **5 ayrı benzersiz bildirim ID'siyle** 900 ms aralıklarla (`[1/5]` .. `[5/5]`, ayarlardan `5–10` seçilebilir) sesli ve güçlü titreşimli gerçek sistem bildirimleri arka arkaya oluşturulur ve bilgisayara şifreli `ACK` gönderilir.

---

## 6. Uygulayıcıya Bırakılan Detaylar (Left to the Builder)

- Varsayılan port numaraları (`49871` loopback, `58443` LAN mTLS, `58444` 60sn keşif) ve çakışma durumunda ayarlardan değiştirilebilmesi.
- Gömülü/sentezlenmiş ses dalgaları (`javax.sound.sampled` masaüstü alarm sireni & görev tamamlandı sesi; Android `RingtoneManager` / özel alarm titreşim deseni).
- Swing/FlatLaf ve Jetpack Compose bileşen yerleşimleri ve `com.antigravity.blipper` paket yapısı.
