package com.antigravity.blipper.desktop.crypto;

import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.BasicConstraints;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.springframework.stereotype.Service;

import javax.crypto.Mac;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.security.Security;
import java.security.cert.X509Certificate;
import java.security.spec.ECGenParameterSpec;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.Arrays;
import java.util.Date;
import java.util.HexFormat;
import java.util.LinkedHashMap;
import java.util.Locale;
import java.util.Map;
import java.util.UUID;

@Service
public class EphemeralKeyMaterialService {

    public static final int PBKDF2_ITERATIONS = 210_000;
    public static final long ALLOWED_CLOCK_SKEW_MS = 30_000L;
    private static final int MAX_REPLAY_CACHE_SIZE = 4096;

    static {
        if (Security.getProvider(BouncyCastleProvider.PROVIDER_NAME) == null) {
            Security.addProvider(new BouncyCastleProvider());
        }
    }

    public record EphemeralCertBundle(KeyPair keyPair, X509Certificate certificate, String sha256Hex) {}

    private final SecureRandom secureRandom = new SecureRandom();
    private final Map<String, Long> seenEventIds = new LinkedHashMap<>(256, 0.75f, true) {
        @Override
        protected boolean removeEldestEntry(Map.Entry<String, Long> eldest) {
            return size() > MAX_REPLAY_CACHE_SIZE;
        }
    };

    public EphemeralCertBundle generateEphemeralEcCert(String commonName) {
        try {
            KeyPairGenerator kpg = KeyPairGenerator.getInstance("EC");
            kpg.initialize(new ECGenParameterSpec("secp256r1"), secureRandom);
            KeyPair keyPair = kpg.generateKeyPair();

            Instant now = Instant.now();
            Date notBefore = Date.from(now.minus(5, ChronoUnit.MINUTES));
            Date notAfter = Date.from(now.plus(365, ChronoUnit.DAYS));
            BigInteger serial = new BigInteger(128, secureRandom).abs().add(BigInteger.ONE);
            X500Name subject = new X500Name("CN=" + sanitizeCn(commonName) + ", O=AntigravityBlipper");

            JcaX509v3CertificateBuilder certBuilder = new JcaX509v3CertificateBuilder(
                    subject,
                    serial,
                    notBefore,
                    notAfter,
                    subject,
                    keyPair.getPublic()
            );
            certBuilder.addExtension(Extension.basicConstraints, true, new BasicConstraints(false));

            ContentSigner signer = new JcaContentSignerBuilder("SHA256withECDSA")
                    .build(keyPair.getPrivate());
            X509Certificate cert = new JcaX509CertificateConverter()
                    .getCertificate(certBuilder.build(signer));
            cert.verify(keyPair.getPublic());

            return new EphemeralCertBundle(keyPair, cert, computeCertSha256Hex(cert));
        } catch (Exception e) {
            throw new IllegalStateException("Failed to generate ephemeral ECDSA P-256 certificate", e);
        }
    }

    public String computeCertSha256Hex(X509Certificate cert) {
        try {
            MessageDigest md = MessageDigest.getInstance("SHA-256");
            byte[] digest = md.digest(cert.getEncoded());
            return HexFormat.of().formatHex(digest);
        } catch (Exception e) {
            throw new IllegalStateException("Failed to hash X.509 certificate", e);
        }
    }

    public String computePairingProofHex(
            char[] pin,
            String serverCertSha256Hex,
            String clientCertSha256Hex,
            long timestampMs,
            String nonce
    ) {
        String sHex = serverCertSha256Hex.toLowerCase(Locale.ROOT);
        String cHex = clientCertSha256Hex.toLowerCase(Locale.ROOT);
        byte[] salt = (sHex + ":" + cHex).getBytes(StandardCharsets.UTF_8);
        PBEKeySpec spec = new PBEKeySpec(pin, salt, PBKDF2_ITERATIONS, 256);
        byte[] derivedKey = null;
        try {
            SecretKeyFactory skf = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256");
            derivedKey = skf.generateSecret(spec).getEncoded();
            String msg = "PAIR-V1|" + sHex + "|" + cHex + "|" + timestampMs + "|" + nonce;
            byte[] mac = hmacSha256(derivedKey, msg.getBytes(StandardCharsets.UTF_8));
            return HexFormat.of().formatHex(mac);
        } catch (Exception e) {
            throw new IllegalStateException("Failed to compute pairing proof", e);
        } finally {
            spec.clearPassword();
            if (derivedKey != null) {
                Arrays.fill(derivedKey, (byte) 0);
            }
        }
    }

    public boolean verifyPairingProof(
            char[] pin,
            String serverCertSha256Hex,
            String clientCertSha256Hex,
            long timestampMs,
            String nonce,
            String candidateHex
    ) {
        if (pin == null || pin.length == 0 || nonce == null || nonce.isBlank() || candidateHex == null) {
            return false;
        }
        long skew = Math.abs(System.currentTimeMillis() - timestampMs);
        if (skew > ALLOWED_CLOCK_SKEW_MS) {
            return false;
        }
        byte[] candidateBytes = parseHexSafe(candidateHex);
        if (candidateBytes == null) {
            return false;
        }
        String expectedHex = computePairingProofHex(pin, serverCertSha256Hex, clientCertSha256Hex, timestampMs, nonce);
        byte[] expectedBytes = HexFormat.of().parseHex(expectedHex);
        return MessageDigest.isEqual(expectedBytes, candidateBytes);
    }

    public SignedEnvelope signEnvelope(byte[] hmacKey, String type, String payloadJson) {
        return signEnvelopeAt(hmacKey, type, payloadJson, UUID.randomUUID().toString(), System.currentTimeMillis());
    }

    public SignedEnvelope signEnvelopeAt(byte[] hmacKey, String type, String payloadJson, String eventId, long timestampMs) {
        SignedEnvelope unsigned = new SignedEnvelope(type, eventId, timestampMs, payloadJson, "");
        byte[] mac = hmacSha256(hmacKey, unsigned.canonicalSigningInput().getBytes(StandardCharsets.UTF_8));
        return new SignedEnvelope(type, eventId, timestampMs, payloadJson, HexFormat.of().formatHex(mac));
    }

    public boolean verifyEnvelope(byte[] hmacKey, SignedEnvelope envelope) {
        if (hmacKey == null || hmacKey.length < 32 || envelope == null
                || envelope.eventId() == null || envelope.eventId().isBlank()
                || envelope.hmacHex() == null) {
            return false;
        }
        long now = System.currentTimeMillis();
        if (Math.abs(now - envelope.timestampMs()) > ALLOWED_CLOCK_SKEW_MS) {
            return false;
        }
        byte[] candidateMac = parseHexSafe(envelope.hmacHex());
        if (candidateMac == null) {
            return false;
        }
        byte[] expectedMac = hmacSha256(hmacKey, envelope.canonicalSigningInput().getBytes(StandardCharsets.UTF_8));
        if (!MessageDigest.isEqual(expectedMac, candidateMac)) {
            return false;
        }
        synchronized (seenEventIds) {
            seenEventIds.entrySet().removeIf(entry -> (now - entry.getValue()) > (ALLOWED_CLOCK_SKEW_MS * 2));
            if (seenEventIds.containsKey(envelope.eventId())) {
                return false;
            }
            seenEventIds.put(envelope.eventId(), now);
        }
        return true;
    }

    public void clearReplayCache() {
        synchronized (seenEventIds) {
            seenEventIds.clear();
        }
    }

    public byte[] randomBytes(int length) {
        byte[] out = new byte[length];
        secureRandom.nextBytes(out);
        return out;
    }

    public char[] generateNumericPin(int digits) {
        if (digits < 6) {
            throw new IllegalArgumentException("PIN must be at least 6 digits");
        }
        char[] pin = new char[digits];
        for (int i = 0; i < digits; i++) {
            pin[i] = (char) ('0' + secureRandom.nextInt(10));
        }
        return pin;
    }

    private byte[] hmacSha256(byte[] key, byte[] message) {
        try {
            Mac mac = Mac.getInstance("HmacSHA256");
            mac.init(new SecretKeySpec(key, "HmacSHA256"));
            return mac.doFinal(message);
        } catch (Exception e) {
            throw new IllegalStateException("HMAC-SHA256 computation failed", e);
        }
    }

    private static byte[] parseHexSafe(String hex) {
        try {
            String normalized = hex.trim().toLowerCase(Locale.ROOT);
            if ((normalized.length() & 1) != 0) {
                return null;
            }
            return HexFormat.of().parseHex(normalized);
        } catch (IllegalArgumentException e) {
            return null;
        }
    }

    private static String sanitizeCn(String raw) {
        if (raw == null || raw.isBlank()) {
            return "Blipper";
        }
        return raw.replaceAll("[^a-zA-Z0-9._-]", "_");
    }
}
