package expo.modules.mutualtls

import org.bouncycastle.jce.provider.BouncyCastleProvider
import org.bouncycastle.openssl.PEMParser
import org.bouncycastle.openssl.jcajce.JcaPEMKeyConverter
import org.bouncycastle.openssl.PEMKeyPair
import org.bouncycastle.cert.X509CertificateHolder
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter
import org.bouncycastle.openssl.PEMEncryptedKeyPair
import org.bouncycastle.openssl.jcajce.JcePEMDecryptorProviderBuilder
import org.bouncycastle.pkcs.PKCS8EncryptedPrivateKeyInfo
import org.bouncycastle.openssl.jcajce.JceOpenSSLPKCS8DecryptorProviderBuilder
import android.util.Log
import java.io.StringReader
import java.security.PrivateKey
import java.security.Security
import java.security.cert.X509Certificate

class PemCertificateParser {
    companion object {
        private const val TAG = "PemCertificateParser"
        
        init {
            // Add BouncyCastle provider if not already added
            if (Security.getProvider(BouncyCastleProvider.PROVIDER_NAME) == null) {
                Security.addProvider(BouncyCastleProvider())
            }
        }
    }
    
    /**
     * Parse a private key from PEM format string
     * @param pemContent The PEM content as string
     * @param passphrase Optional passphrase for encrypted keys
     * @return PrivateKey object
     * @throws InvalidCertificateException if parsing fails
     */
    fun parsePrivateKey(pemContent: String, passphrase: String? = null): PrivateKey {
        try {
            PEMParser(StringReader(pemContent)).use { parser ->
                var keyObject = parser.readObject()
                
                // Skip any non-key objects (like certificates)
                while (keyObject != null && keyObject !is PEMKeyPair && 
                       keyObject !is PEMEncryptedKeyPair && 
                       keyObject !is PKCS8EncryptedPrivateKeyInfo &&
                       keyObject !is org.bouncycastle.asn1.pkcs.PrivateKeyInfo) {
                    keyObject = parser.readObject()
                }
                
                if (keyObject == null) {
                    throw InvalidCertificateException("No private key found in PEM content")
                }
                
                val converter = JcaPEMKeyConverter()
                
                return when (keyObject) {
                    is PEMKeyPair -> {
                        // Unencrypted key pair
                        converter.getPrivateKey(keyObject.privateKeyInfo)
                    }
                    is PEMEncryptedKeyPair -> {
                        // Encrypted key pair - requires passphrase
                        if (passphrase == null) {
                            throw InvalidCertificateException("Encrypted private key requires passphrase")
                        }
                        val decryptorProvider = JcePEMDecryptorProviderBuilder()
                            .build(passphrase.toCharArray())
                        val decryptedKeyPair = keyObject.decryptKeyPair(decryptorProvider)
                        converter.getPrivateKey(decryptedKeyPair.privateKeyInfo)
                    }
                    is PKCS8EncryptedPrivateKeyInfo -> {
                        // PKCS#8 encrypted private key
                        if (passphrase == null) {
                            throw InvalidCertificateException("Encrypted private key requires passphrase")
                        }
                        val decryptorProvider = JceOpenSSLPKCS8DecryptorProviderBuilder()
                            .build(passphrase.toCharArray())
                        val privateKeyInfo = keyObject.decryptPrivateKeyInfo(decryptorProvider)
                        converter.getPrivateKey(privateKeyInfo)
                    }
                    is org.bouncycastle.asn1.pkcs.PrivateKeyInfo -> {
                        // Unencrypted PKCS#8 private key
                        converter.getPrivateKey(keyObject)
                    }
                    else -> {
                        throw InvalidCertificateException("Unsupported private key format: ${keyObject.javaClass.simpleName}")
                    }
                }
            }
        } catch (e: InvalidCertificateException) {
            throw e
        } catch (e: Exception) {
            Log.e(TAG, "Failed to parse private key", e)
            throw InvalidCertificateException("Private key parsing failed: ${e.message}")
        }
    }
    
    /**
     * Parse certificates from PEM format string
     * @param pemContent The PEM content as string
     * @return List of X509Certificate objects
     * @throws InvalidCertificateException if parsing fails
     */
    fun parseCertificates(pemContent: String): List<X509Certificate> {
        val certificates = mutableListOf<X509Certificate>()
        
        try {
            PEMParser(StringReader(pemContent)).use { parser ->
                val converter = JcaX509CertificateConverter()
                var obj = parser.readObject()
                
                while (obj != null) {
                    when (obj) {
                        is X509CertificateHolder -> {
                            certificates.add(converter.getCertificate(obj))
                        }
                        is java.security.cert.X509Certificate -> {
                            // Already converted certificate
                            certificates.add(obj)
                        }
                    }
                    obj = parser.readObject()
                }
            }
            
            if (certificates.isEmpty()) {
                throw InvalidCertificateException("No certificates found in PEM content")
            }
            
            return certificates
        } catch (e: InvalidCertificateException) {
            throw e
        } catch (e: Exception) {
            Log.e(TAG, "Failed to parse certificates", e)
            throw InvalidCertificateException("Certificate parsing failed: ${e.message}")
        }
    }
    
    /**
     * Parse both certificate and private key from combined PEM content
     * @param pemContent The PEM content containing both certificate and key
     * @param passphrase Optional passphrase for encrypted keys
     * @return Pair of (certificates list, private key)
     * @throws InvalidCertificateException if parsing fails
     */
    fun parseCertificateAndKey(pemContent: String, passphrase: String? = null): Pair<List<X509Certificate>, PrivateKey> {
        try {
            val certificates = parseCertificates(pemContent)
            val privateKey = parsePrivateKey(pemContent, passphrase)
            return Pair(certificates, privateKey)
        } catch (e: Exception) {
            throw InvalidCertificateException("Failed to parse certificate and key: ${e.message}")
        }
    }
    
    /**
     * Validate that a private key matches the public key in the certificate
     * @param privateKey The private key
     * @param certificate The certificate containing the public key
     * @return true if the keys match
     * @throws InvalidCertificateException if validation fails
     */
    fun validateKeyPairMatch(privateKey: PrivateKey, certificate: X509Certificate): Boolean {
        return try {
            // Create a test signature to verify key pair match
            val testData = "key-pair-validation-test".toByteArray()
            
            // Sign with private key
            val signature = java.security.Signature.getInstance("SHA256withRSA").apply {
                initSign(privateKey)
                update(testData)
            }.sign()
            
            // Verify with public key from certificate
            val verification = java.security.Signature.getInstance("SHA256withRSA").apply {
                initVerify(certificate.publicKey)
                update(testData)
            }.verify(signature)
            
            if (!verification) {
                throw InvalidCertificateException("Private key does not match certificate public key")
            }
            
            true
        } catch (e: InvalidCertificateException) {
            throw e
        } catch (e: Exception) {
            Log.e(TAG, "Key pair validation failed", e)
            throw InvalidCertificateException("Key pair validation error: ${e.message}")
        }
    }
}