package com.antigravity.blipper.android.crypto

import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import java.math.BigInteger
import java.nio.charset.StandardCharsets
import java.security.KeyPairGenerator
import java.security.KeyStore
import java.security.MessageDigest
import java.security.SecureRandom
import java.security.cert.CertificateException
import java.security.cert.X509Certificate
import java.security.spec.ECGenParameterSpec
import java.util.Calendar
import java.util.Locale
import javax.net.ssl.KeyManagerFactory
import javax.net.ssl.SSLContext
import javax.net.ssl.SSLSocketFactory
import javax.net.ssl.TrustManager
import javax.net.ssl.X509TrustManager
import javax.security.auth.x500.X500Principal

class HardwareKeyManager {

    companion object {
        private const val ANDROID_KEYSTORE = "AndroidKeyStore"
        private const val KEY_ALIAS = "blipper_ephemeral_session_key"

        fun sha256HexOfCert(cert: X509Certificate): String {
            val md = MessageDigest.getInstance("SHA-256")
            return md.digest(cert.encoded).toLowerHex()
        }
    }

    data class MtlsSslBundle(
        val sslSocketFactory: SSLSocketFactory,
        val trustManager: X509TrustManager,
        val clientCertSha256Hex: String
    )

    @Synchronized
    fun generateFreshMtlsBundle(pinnedServerCertSha256Hex: String): MtlsSslBundle {
        wipeAllKeys()

        val notBefore = Calendar.getInstance().apply { add(Calendar.MINUTE, -5) }.time
        val notAfter = Calendar.getInstance().apply { add(Calendar.DAY_OF_YEAR, 2) }.time

        val kpg = KeyPairGenerator.getInstance(KeyProperties.KEY_ALGORITHM_EC, ANDROID_KEYSTORE)
        val spec = KeyGenParameterSpec.Builder(
            KEY_ALIAS,
            KeyProperties.PURPOSE_SIGN or KeyProperties.PURPOSE_VERIFY
        )
            .setAlgorithmParameterSpec(ECGenParameterSpec("secp256r1"))
            .setDigests(
                KeyProperties.DIGEST_NONE,
                KeyProperties.DIGEST_SHA256,
                KeyProperties.DIGEST_SHA384,
                KeyProperties.DIGEST_SHA512
            )
            .setCertificateSubject(X500Principal("CN=AntigravityBlipper-Android"))
            .setCertificateSerialNumber(BigInteger.valueOf(System.currentTimeMillis()))
            .setKeyValidityStart(notBefore)
            .setKeyValidityEnd(notAfter)
            .setCertificateNotBefore(notBefore)
            .setCertificateNotAfter(notAfter)
            .build()

        kpg.initialize(spec)
        kpg.generateKeyPair()

        val keyStore = KeyStore.getInstance(ANDROID_KEYSTORE).apply { load(null) }
        val clientCert = keyStore.getCertificate(KEY_ALIAS) as? X509Certificate
            ?: throw IllegalStateException("AndroidKeyStore failed to produce X.509 certificate")
        val clientSha = sha256HexOfCert(clientCert)

        val kmf = KeyManagerFactory.getInstance(KeyManagerFactory.getDefaultAlgorithm())
        kmf.init(keyStore, null)

        val expectedPinBytes = pinnedServerCertSha256Hex.trim().lowercase(Locale.ROOT)
            .toByteArray(StandardCharsets.UTF_8)

        val pinnedTrustManager = object : X509TrustManager {
            override fun checkClientTrusted(chain: Array<out X509Certificate>?, authType: String?) {
                throw CertificateException("Android never acts as TLS server")
            }

            override fun checkServerTrusted(chain: Array<out X509Certificate>?, authType: String?) {
                if (chain.isNullOrEmpty()) {
                    throw CertificateException("Empty server certificate chain")
                }
                val leaf = chain[0]
                leaf.checkValidity()
                val actualHexBytes = sha256HexOfCert(leaf).lowercase(Locale.ROOT)
                    .toByteArray(StandardCharsets.UTF_8)
                if (!MessageDigest.isEqual(expectedPinBytes, actualHexBytes)) {
                    throw CertificateException("Desktop TLS certificate fingerprint mismatch!")
                }
            }

            override fun getAcceptedIssuers(): Array<X509Certificate> = emptyArray()
        }

        val sslContext = SSLContext.getInstance("TLSv1.3")
        sslContext.init(kmf.keyManagers, arrayOf<TrustManager>(pinnedTrustManager), SecureRandom())

        return MtlsSslBundle(
            sslSocketFactory = sslContext.socketFactory,
            trustManager = pinnedTrustManager,
            clientCertSha256Hex = clientSha
        )
    }

    @Synchronized
    fun wipeAllKeys() {
        try {
            val keyStore = KeyStore.getInstance(ANDROID_KEYSTORE).apply { load(null) }
            if (keyStore.containsAlias(KEY_ALIAS)) {
                keyStore.deleteEntry(KEY_ALIAS)
            }
        } catch (_: Exception) {
            // Ignore in JVM unit tests where AndroidKeyStore provider is absent
        }
    }
}
