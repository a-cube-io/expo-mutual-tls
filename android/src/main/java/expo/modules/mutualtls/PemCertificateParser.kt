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

    /**
     * Extract detailed certificate information
     * @param certificate The X509Certificate to extract info from
     * @return Map containing all certificate details
     */
    fun extractCertificateInfo(certificate: X509Certificate): Map<String, Any?> {
        val certInfo = mutableMapOf<String, Any?>()

        // Extract subject information
        certInfo["subject"] = extractSubjectInfo(certificate)

        // Extract issuer information
        certInfo["issuer"] = extractIssuerInfo(certificate)

        // Extract serial number
        certInfo["serialNumber"] = certificate.serialNumber.toString(16)

        // Extract version
        certInfo["version"] = certificate.version

        // Extract validity dates (in milliseconds)
        certInfo["validFrom"] = certificate.notBefore.time
        certInfo["validTo"] = certificate.notAfter.time

        // Extract fingerprints
        certInfo["fingerprints"] = calculateFingerprints(certificate)

        // Extract public key information
        val publicKey = certificate.publicKey
        certInfo["publicKeyAlgorithm"] = publicKey.algorithm

        // Extract key size for RSA/EC keys
        when (publicKey.algorithm) {
            "RSA" -> {
                try {
                    val rsaKey = publicKey as? java.security.interfaces.RSAPublicKey
                    rsaKey?.modulus?.bitLength()?.let { certInfo["publicKeySize"] = it }
                } catch (e: Exception) {
                    Log.w(TAG, "Failed to extract RSA key size", e)
                }
            }
            "EC" -> {
                try {
                    val ecKey = publicKey as? java.security.interfaces.ECPublicKey
                    ecKey?.params?.order?.bitLength()?.let { certInfo["publicKeySize"] = it }
                } catch (e: Exception) {
                    Log.w(TAG, "Failed to extract EC key size", e)
                }
            }
        }

        // Extract signature algorithm
        certInfo["signatureAlgorithm"] = certificate.sigAlgName

        // Extract key usage
        certificate.keyUsage?.let { usage ->
            val keyUsageList = mutableListOf<String>()
            val keyUsageNames = arrayOf(
                "digitalSignature", "nonRepudiation", "keyEncipherment",
                "dataEncipherment", "keyAgreement", "keyCertSign",
                "cRLSign", "encipherOnly", "decipherOnly"
            )
            usage.forEachIndexed { index, bit ->
                if (bit && index < keyUsageNames.size) {
                    keyUsageList.add(keyUsageNames[index])
                }
            }
            if (keyUsageList.isNotEmpty()) {
                certInfo["keyUsage"] = keyUsageList
            }
        }

        // Extract extended key usage
        try {
            certificate.extendedKeyUsage?.let { ekuOids ->
                val ekuList = ekuOids.map { oid ->
                    when (oid) {
                        "1.3.6.1.5.5.7.3.1" -> "serverAuth"
                        "1.3.6.1.5.5.7.3.2" -> "clientAuth"
                        "1.3.6.1.5.5.7.3.3" -> "codeSigning"
                        "1.3.6.1.5.5.7.3.4" -> "emailProtection"
                        "1.3.6.1.5.5.7.3.8" -> "timeStamping"
                        "1.3.6.1.5.5.7.3.9" -> "OCSPSigning"
                        else -> oid
                    }
                }
                certInfo["extendedKeyUsage"] = ekuList
            }
        } catch (e: Exception) {
            Log.w(TAG, "Failed to extract extended key usage", e)
        }

        // Extract subject alternative names
        try {
            certificate.subjectAlternativeNames?.let { sans ->
                val sanList = sans.mapNotNull { san ->
                    // SAN is a list where first element is type, second is value
                    val sanList = san as? List<*>
                    sanList?.get(1)?.toString()
                }
                if (sanList.isNotEmpty()) {
                    certInfo["subjectAlternativeNames"] = sanList
                }
            }
        } catch (e: Exception) {
            Log.w(TAG, "Failed to extract subject alternative names", e)
        }

        return certInfo
    }

    private fun extractSubjectInfo(certificate: X509Certificate): Map<String, String> {
        val subject = mutableMapOf<String, String>()
        val subjectDN = certificate.subjectX500Principal.name

        // Parse DN string
        parseDN(subjectDN).forEach { (key, value) ->
            when (key) {
                "CN" -> subject["commonName"] = value
                "O" -> subject["organization"] = value
                "OU" -> subject["organizationalUnit"] = value
                "C" -> subject["country"] = value
                "ST" -> subject["state"] = value
                "L" -> subject["locality"] = value
                "E", "EMAILADDRESS" -> subject["emailAddress"] = value
            }
        }

        return subject
    }

    private fun extractIssuerInfo(certificate: X509Certificate): Map<String, String> {
        val issuer = mutableMapOf<String, String>()
        val issuerDN = certificate.issuerX500Principal.name

        // Parse DN string
        parseDN(issuerDN).forEach { (key, value) ->
            when (key) {
                "CN" -> issuer["commonName"] = value
                "O" -> issuer["organization"] = value
                "OU" -> issuer["organizationalUnit"] = value
                "C" -> issuer["country"] = value
                "ST" -> issuer["state"] = value
                "L" -> issuer["locality"] = value
            }
        }

        return issuer
    }

    private fun parseDN(dn: String): Map<String, String> {
        val result = mutableMapOf<String, String>()
        // Simple DN parser - handles basic cases
        val parts = dn.split(",").map { it.trim() }
        for (part in parts) {
            val keyValue = part.split("=", limit = 2)
            if (keyValue.size == 2) {
                result[keyValue[0].trim().uppercase()] = keyValue[1].trim()
            }
        }
        return result
    }

    private fun calculateFingerprints(certificate: X509Certificate): Map<String, String> {
        val fingerprints = mutableMapOf<String, String>()

        try {
            val certBytes = certificate.encoded

            // SHA-1 fingerprint
            val sha1 = java.security.MessageDigest.getInstance("SHA-1")
            val sha1Digest = sha1.digest(certBytes)
            fingerprints["sha1"] = sha1Digest.joinToString("") { "%02x".format(it) }

            // SHA-256 fingerprint
            val sha256 = java.security.MessageDigest.getInstance("SHA-256")
            val sha256Digest = sha256.digest(certBytes)
            fingerprints["sha256"] = sha256Digest.joinToString("") { "%02x".format(it) }

        } catch (e: Exception) {
            Log.e(TAG, "Failed to calculate fingerprints", e)
        }

        return fingerprints
    }
}