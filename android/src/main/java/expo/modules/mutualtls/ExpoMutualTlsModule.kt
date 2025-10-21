package expo.modules.mutualtls

import android.content.Context
import android.util.Base64
import android.util.Log
import androidx.core.os.bundleOf
import expo.modules.kotlin.exception.CodedException
import expo.modules.kotlin.exception.toCodedException
import expo.modules.kotlin.functions.Coroutine
import expo.modules.kotlin.modules.Module
import expo.modules.kotlin.modules.ModuleDefinition
import expo.modules.kotlin.records.Field
import expo.modules.kotlin.records.Record
import expo.modules.kotlin.types.Enumerable
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import okhttp3.MediaType.Companion.toMediaType
import okhttp3.RequestBody.Companion.toRequestBody
import java.io.ByteArrayInputStream
import java.security.KeyStore
import java.security.SecureRandom
import java.security.cert.X509Certificate
import javax.net.ssl.KeyManagerFactory
import javax.net.ssl.SSLContext
import javax.net.ssl.SSLSocketFactory
import javax.net.ssl.TrustManagerFactory
import javax.net.ssl.X509TrustManager

// ----------------------------- Config / Types --------------------------------
enum class CertificateFormat(val value: String) : Enumerable {
  P12("p12"),
  PEM("pem")
}

class MutualTlsConfig : Record {
  @Field val certificateFormat: CertificateFormat = CertificateFormat.P12
  @Field val keychainService: String = "expo.mtls.client"
  
  // P12 specific (backward compatibility)
  @Field val keychainServiceForP12: String = "client.p12"
  @Field val keychainServiceForPassword: String = "client.p12.password"
  
  // PEM specific
  @Field val keychainServiceForPrivateKey: String = "expo.mtls.client.key"
  @Field val keychainServiceForCertChain: String = "expo.mtls.client.cert"
  
  @Field val enableLogging: Boolean = false
  // optional: require user authentication (biometric/device credential) to use the wrapping key
  @Field val requireUserAuthentication: Boolean = false
  @Field val userAuthValiditySeconds: Int = 120 // only used if requireUserAuthentication=true
  @Field val expiryWarningDays: Int = 30
}

enum class TlsState(val value: String) : Enumerable {
  NOT_CONFIGURED("notConfigured"),
  CONFIGURED("configured"),
  ERROR("error")
}

class MutualTlsException(message: String, cause: Throwable? = null) : CodedException(message, cause)
class CertificateNotFoundException : CodedException("Client certificate not found in secure storage")
class InvalidCertificateException(message: String) : CodedException("Invalid certificate: $message")


// ----------------------------- Expo Module -----------------------------------
class ExpoMutualTlsModule : Module() {
  companion object {
    private const val MODULE_NAME = "ExpoMutualTls"
    private const val TAG = "ExpoMutualTLS"
    @Volatile private var isConfigured = false
    private var currentConfig: MutualTlsConfig? = null
    @Volatile private var sslSocketFactory: SSLSocketFactory? = null
    @Volatile private var trustManager: X509TrustManager? = null
    private val stateLock = Any()
    @JvmStatic var moduleInstance: ExpoMutualTlsModule? = null
  }

  init { moduleInstance = this }

  private val ctx: Context
    get() = requireNotNull(appContext.reactContext) { "React context not available" }

  private val keychain by lazy { KeychainManager(ctx) }
  private val pemParser by lazy { PemCertificateParser() }

  override fun definition() = ModuleDefinition {
    Name(MODULE_NAME)

    // --- Configure: suspendable async function
    AsyncFunction("configure").Coroutine { config: MutualTlsConfig ->
      currentConfig = config
      try {
        Log.d(TAG, "Configuring mTLS module with format: ${config.certificateFormat}")
        
        // Just store the configuration, don't require existing certificates
        // If certificate already exists, try to initialize SSL context
        val certData = getCertificateFromSecureStorageInternal()
        val keyData = getPasswordFromSecureStorageInternal()
        
        if (certData != null && keyData != null) {
          Log.d(TAG, "Found existing certificate, initializing SSL context")
          initializeSslContext(certData, keyData)
          setConfiguredState(true)
          mapOf("success" to true, "state" to TlsState.CONFIGURED.value, "hasCertificate" to true)
        } else {
          Log.d(TAG, "No existing certificate found, configuration saved")
          setConfiguredState(true) // Configuration is valid even without certificate
          mapOf("success" to true, "state" to TlsState.CONFIGURED.value, "hasCertificate" to false)
        }
      } catch (e: Exception) {
        setConfiguredState(false)
        Log.e(TAG, "configure failed", e)
        throw e.toCodedException()
      }
    }

    // --- storeCertificate (supports both P12 and PEM formats)
    AsyncFunction("storeCertificate").Coroutine { certificateData: Map<String, Any> ->
      try {
        when (currentConfig?.certificateFormat) {
          CertificateFormat.PEM -> {
            storePemCertificate(certificateData)
          }
          else -> {
            // P12 format (default for backward compatibility)
            val p12Base64 = certificateData["p12Data"] as? String
              ?: throw MutualTlsException("P12 data is required for P12 format")
            val password = certificateData["password"] as? String
              ?: throw MutualTlsException("Password is required for P12 format")
            storePkcs12Certificate(p12Base64, password)
          }
        }
        true
      } catch (e: Exception) {
        Log.e(TAG, "storeCertificate failed", e)
        throw e.toCodedException()
      }
    }
    
    // --- Backward compatibility method for P12
    AsyncFunction("storeP12Certificate").Coroutine { p12Base64: String, password: String ->
      try {
        storePkcs12Certificate(p12Base64, password)
        true
      } catch (e: Exception) {
        Log.e(TAG, "storeP12Certificate failed", e)
        throw e.toCodedException()
      }
    }

    // --- removeCertificate
    AsyncFunction("removeCertificate") {
      try {
        when (currentConfig?.certificateFormat) {
          CertificateFormat.PEM -> {
            val certService = currentConfig?.keychainServiceForCertChain ?: "expo.mtls.client.cert"
            val keyService = currentConfig?.keychainServiceForPrivateKey ?: "expo.mtls.client.key"
            val passphraseService = "${keyService}.passphrase"
            keychain.resetInternetCredentials(certService)
            keychain.resetInternetCredentials(keyService)
            keychain.resetInternetCredentials(passphraseService)
          }
          else -> {
            // P12 format (default for backward compatibility)
            val p12Service = currentConfig?.keychainServiceForP12 ?: "client.p12"
            val pwdService = currentConfig?.keychainServiceForPassword ?: "client.p12.password"
            keychain.resetInternetCredentials(p12Service)
            keychain.resetInternetCredentials(pwdService)
          }
        }
        // reset internal SSL state
        setSslState(null, null)
        setConfiguredState(false)
        true
      } catch (e: Exception) {
        Log.e(TAG, "removeCertificate failed", e)
        throw e.toCodedException()
      }
    }

    // --- hasCertificate
    AsyncFunction("hasCertificate") {
      try {
        when (currentConfig?.certificateFormat) {
          CertificateFormat.PEM -> {
            val certService = currentConfig?.keychainServiceForCertChain ?: "expo.mtls.client.cert"
            val keyService = currentConfig?.keychainServiceForPrivateKey ?: "expo.mtls.client.key"
            keychain.hasInternetCredentials(certService) && keychain.hasInternetCredentials(keyService)
          }
          else -> {
            // P12 format (default for backward compatibility)
            val p12Service = currentConfig?.keychainServiceForP12 ?: "client.p12"
            val pwdService = currentConfig?.keychainServiceForPassword ?: "client.p12.password"
            keychain.hasInternetCredentials(p12Service) && keychain.hasInternetCredentials(pwdService)
          }
        }
      } catch (e: Exception) {
        Log.e(TAG, "hasCertificate error", e)
        throw e.toCodedException()
      }
    }

    // --- parseCertificate
    AsyncFunction("parseCertificate").Coroutine { certificateData: Map<String, Any> ->
      try {
        val certificates = parseCertificateInfo(certificateData)
        mapOf("certificates" to certificates)
      } catch (e: Exception) {
        Log.e(TAG, "parseCertificate failed", e)
        throw e.toCodedException()
      }
    }

    // --- getCertificatesInfo
    AsyncFunction("getCertificatesInfo") {
      try {
        val certificates = getStoredCertificatesInfo()
        mapOf("certificates" to certificates)
      } catch (e: Exception) {
        Log.e(TAG, "getCertificatesInfo failed", e)
        throw e.toCodedException()
      }
    }

    // --- testConnection(url)
    AsyncFunction("testConnection").Coroutine { url: String ->
      if (!isConfigured) throw MutualTlsException("Module not configured - call configure() first")
      // perform network IO on IO dispatcher
      withContext(Dispatchers.IO) {
        performMtlsRequest(url)
      }
    }

    // --- makeRequest(options)
    AsyncFunction("makeRequest").Coroutine<Map<String, Any>, Map<String, Any>> { options: Map<String, Any> ->
      if (!isConfigured) throw MutualTlsException("Module not configured - call configure() first")

      val url = options["url"] as? String ?: throw MutualTlsException("URL is required")
      val method = (options["method"] as? String ?: "GET").uppercase()
      @Suppress("UNCHECKED_CAST")
      val headers = options["headers"] as? Map<String, String> ?: emptyMap()
      val body = options["body"] as? String
      val responseType = options["responseType"] as? String

      withContext<Map<String, Any>>(Dispatchers.IO) {
        performMtlsRequestWithOptions(url, method, headers, body, responseType)
      }
    }


    // Properties & events
    Property("isConfigured") { isConfigured }
    Property("currentState") {
      when { isConfigured -> TlsState.CONFIGURED.value; else -> TlsState.NOT_CONFIGURED.value }
    }
    Events("onDebugLog", "onError", "onCertificateExpiry")
  }

  // ---------- Internal helpers ----------

  private fun parseCertificateInfo(certificateData: Map<String, Any>): List<Map<String, Any?>> {
    // Determine format from certificate data
    return if (certificateData.containsKey("p12Data") && certificateData.containsKey("password")) {
      // P12 format
      val p12Base64 = certificateData["p12Data"] as? String
        ?: throw MutualTlsException("P12 data is required")
      val password = certificateData["password"] as? String
        ?: throw MutualTlsException("Password is required")

      val p12Data = Base64.decode(p12Base64, Base64.NO_WRAP)
      val keyStore = KeyStore.getInstance("PKCS12").apply {
        load(ByteArrayInputStream(p12Data), password.toCharArray())
      }

      // Extract all certificates from the P12
      val certificates = mutableListOf<Map<String, Any?>>()
      val aliases = keyStore.aliases()
      while (aliases.hasMoreElements()) {
        val alias = aliases.nextElement()
        val cert = keyStore.getCertificate(alias) as? X509Certificate
        cert?.let {
          certificates.add(pemParser.extractCertificateInfo(it))
        }
      }
      certificates

    } else if (certificateData.containsKey("certificate")) {
      // PEM format
      val certPem = certificateData["certificate"] as? String
        ?: throw MutualTlsException("Certificate PEM is required")

      val certs = pemParser.parseCertificates(certPem)
      certs.map { pemParser.extractCertificateInfo(it) }

    } else {
      throw MutualTlsException("Either p12Data+password or certificate required")
    }
  }

  private fun getStoredCertificatesInfo(): List<Map<String, Any?>> {
    if (currentConfig == null) {
      throw MutualTlsException("Module not configured - call configure() first")
    }

    val certData = getCertificateFromSecureStorageInternal()
      ?: throw CertificateNotFoundException()

    return when (currentConfig?.certificateFormat) {
      CertificateFormat.P12 -> {
        val password = getPasswordFromSecureStorageInternal()
          ?: throw MutualTlsException("P12 password not found in keychain")

        val p12Data = Base64.decode(certData, Base64.NO_WRAP)
        val keyStore = KeyStore.getInstance("PKCS12").apply {
          load(ByteArrayInputStream(p12Data), password.toCharArray())
        }

        val certificates = mutableListOf<Map<String, Any?>>()
        val aliases = keyStore.aliases()
        while (aliases.hasMoreElements()) {
          val alias = aliases.nextElement()
          val cert = keyStore.getCertificate(alias) as? X509Certificate
          cert?.let {
            certificates.add(pemParser.extractCertificateInfo(it))
          }
        }
        certificates
      }
      CertificateFormat.PEM -> {
        val certs = pemParser.parseCertificates(certData)
        certs.map { pemParser.extractCertificateInfo(it) }
      }
      else -> {
        throw MutualTlsException("Unknown certificate format")
      }
    }
  }

  private fun setSslState(factory: SSLSocketFactory?, tm: X509TrustManager?) {
    synchronized(stateLock) {
      sslSocketFactory = factory
      trustManager = tm
      isConfigured = (factory != null && tm != null)
    }
  }

  private fun setConfiguredState(v: Boolean) {
    synchronized(stateLock) { isConfigured = v }
  }

  // direct internal getters (return raw base64 p12 / password string or PEM data)
  private fun getCertificateFromSecureStorageInternal(): String? {
    return when (currentConfig?.certificateFormat) {
      CertificateFormat.PEM -> {
        val certService = currentConfig?.keychainServiceForCertChain ?: "expo.mtls.client.cert"
        keychain.getInternetCredentials(certService)?.password
      }
      else -> {
        // P12 format (default for backward compatibility)
        val p12Service = currentConfig?.keychainServiceForP12 ?: "client.p12"
        keychain.getInternetCredentials(p12Service)?.password
      }
    }
  }

  private fun getPasswordFromSecureStorageInternal(): String? {
    return when (currentConfig?.certificateFormat) {
      CertificateFormat.PEM -> {
        val keyService = currentConfig?.keychainServiceForPrivateKey ?: "expo.mtls.client.key"
        keychain.getInternetCredentials(keyService)?.password
      }
      else -> {
        // P12 format (default for backward compatibility)
        val pwdService = currentConfig?.keychainServiceForPassword ?: "client.p12.password"
        keychain.getInternetCredentials(pwdService)?.password
      }
    }
  }
  
  private fun getPrivateKeyPassphraseFromStorage(): String? {
    return when (currentConfig?.certificateFormat) {
      CertificateFormat.PEM -> {
        val passphraseService = "${currentConfig?.keychainServiceForPrivateKey ?: "expo.mtls.client.key"}.passphrase"
        keychain.getInternetCredentials(passphraseService)?.password
      }
      else -> null
    }
  }
  
  // Helper method to store PKCS12 certificates
  private fun storePkcs12Certificate(p12Base64: String, password: String) {
    validateCertificate(p12Base64, password) // throws on invalid
    
    val keychainOptions = KeychainOptions(
      requireUserAuthentication = currentConfig?.requireUserAuthentication ?: false,
      authValiditySeconds = currentConfig?.userAuthValiditySeconds ?: -1
    )
    
    val p12Service = currentConfig?.keychainServiceForP12 ?: "client.p12"
    val pwdService = currentConfig?.keychainServiceForPassword ?: "client.p12.password"

    // Store certificate and password
    val p12Success = keychain.setInternetCredentials(p12Service, "certificate", p12Base64, keychainOptions)
    val pwdSuccess = keychain.setInternetCredentials(pwdService, "password", password, keychainOptions)
    
    if (!p12Success || !pwdSuccess) {
      throw MutualTlsException("Failed to store P12 certificate in keychain")
    }
    
    // Initialize SSL context with the stored certificate
    try {
      initializeSslContext(p12Base64, password)
      Log.d(TAG, "SSL context initialized after storing P12 certificate")
    } catch (e: Exception) {
      Log.w(TAG, "Failed to initialize SSL context after storing certificate", e)
      // Don't throw here - certificate is stored successfully
    }
  }
  
  // Helper method to store PEM certificates
  private fun storePemCertificate(certificateData: Map<String, Any>) {
    val certPem = certificateData["certificate"] as? String
      ?: throw MutualTlsException("Certificate PEM is required for PEM format")
    val keyPem = certificateData["privateKey"] as? String
      ?: throw MutualTlsException("Private key PEM is required for PEM format")
    val passphrase = certificateData["passphrase"] as? String
    
    // Validate PEM certificate and key
    validatePemCertificate(certPem, keyPem, passphrase)
    
    val keychainOptions = KeychainOptions(
      requireUserAuthentication = currentConfig?.requireUserAuthentication ?: false,
      authValiditySeconds = currentConfig?.userAuthValiditySeconds ?: -1
    )
    
    val certService = currentConfig?.keychainServiceForCertChain ?: "expo.mtls.client.cert"
    val keyService = currentConfig?.keychainServiceForPrivateKey ?: "expo.mtls.client.key"
    val passphraseService = "${keyService}.passphrase"

    // Store certificate and private key
    val certSuccess = keychain.setInternetCredentials(certService, "certificate", certPem, keychainOptions)
    val keySuccess = keychain.setInternetCredentials(keyService, "privateKey", keyPem, keychainOptions)
    
    var passphraseSuccess = true
    if (passphrase != null) {
      passphraseSuccess = keychain.setInternetCredentials(passphraseService, "passphrase", passphrase, keychainOptions)
    }
    
    if (!certSuccess || !keySuccess || !passphraseSuccess) {
      throw MutualTlsException("Failed to store PEM certificate in keychain")
    }
    
    // Initialize SSL context with the stored PEM certificate
    try {
      // For PEM format, certData = certificate PEM, keyData = private key PEM
      initializeSslContext(certPem, keyPem)
      Log.d(TAG, "SSL context initialized after storing PEM certificate")
    } catch (e: Exception) {
      Log.w(TAG, "Failed to initialize SSL context after storing PEM certificate", e)
      // Don't throw here - certificate is stored successfully
    }
  }

  // Validate P12: ensure contains at least one PrivateKeyEntry and that certs have clientAuth EKU.
  private fun validateCertificate(p12Base64: String, password: String) {
    try {
      val p12Bytes = Base64.decode(p12Base64, Base64.NO_WRAP)
      val ks = KeyStore.getInstance("PKCS12").apply {
        load(ByteArrayInputStream(p12Bytes), password.toCharArray())
      }

      if (ks.size() == 0) throw InvalidCertificateException("Empty keystore")

      var hasPrivateKey = false
      val aliases = ks.aliases()
      val now = System.currentTimeMillis()
      val expiryWarningMs = (currentConfig?.expiryWarningDays ?: 30) * 24L * 60L * 60L * 1000L

      while (aliases.hasMoreElements()) {
        val alias = aliases.nextElement()
        if (ks.isKeyEntry(alias)) {
          val key = ks.getKey(alias, password.toCharArray())
          if (key != null) {
            hasPrivateKey = true
          } else {
            throw InvalidCertificateException("Key entry has no private key for alias $alias")
          }
        }

        val cert = ks.getCertificate(alias) as? X509Certificate
        cert?.let {
          // check validity and EKU
          try {
            it.checkValidity()
          } catch (ex: Exception) {
            // expired: inform JS
            sendEvent("onCertificateExpiry", bundleOf(
              "alias" to alias,
              "subject" to it.subjectDN.toString(),
              "expiry" to it.notAfter.time
            ))
            // still allow store but warn - we throw to be strict:
            throw InvalidCertificateException("Certificate for alias $alias is not valid: ${ex.message}")
          }

          val eku = try { it.extendedKeyUsage } catch (_: Exception) { null }
          if (eku != null && !eku.contains("1.3.6.1.5.5.7.3.2")) {
            // EKU present but doesn't include clientAuth OID
            Log.w(TAG, "Certificate alias $alias doesn't include clientAuth EKU")
            // we warn but still allow, or throw to be strict - we choose to warn:
            // sendEvent("onDebugLog", bundleOf("type" to "certificate", "message" to "No clientAuth EKU"))
          }

          // expiry soon
          val msUntilExpiry = it.notAfter.time - now
          if (msUntilExpiry <= expiryWarningMs) {
            sendEvent("onCertificateExpiry", bundleOf(
              "alias" to alias,
              "subject" to it.subjectDN.toString(),
              "expiry" to it.notAfter.time,
              "warning" to true
            ))
          }
        }
      }

      if (!hasPrivateKey) throw InvalidCertificateException("No private key found in PKCS12")
    } catch (e: InvalidCertificateException) {
      throw e
    } catch (e: Exception) {
      throw InvalidCertificateException("Certificate validation failed: ${e.message}")
    }
  }
  
  // Validate PEM certificate and private key
  private fun validatePemCertificate(certPem: String, keyPem: String, passphrase: String?) {
    try {
      // Parse certificates and private key
      val certificates = pemParser.parseCertificates(certPem)
      val privateKey = pemParser.parsePrivateKey(keyPem, passphrase)
      
      if (certificates.isEmpty()) {
        throw InvalidCertificateException("No certificates found in PEM")
      }
      
      val clientCert = certificates.first()
      val now = System.currentTimeMillis()
      val expiryWarningMs = (currentConfig?.expiryWarningDays ?: 30) * 24L * 60L * 60L * 1000L
      
      // Validate certificate expiry
      try {
        clientCert.checkValidity()
      } catch (ex: Exception) {
        sendEvent("onCertificateExpiry", bundleOf(
          "subject" to clientCert.subjectDN.toString(),
          "expiry" to clientCert.notAfter.time
        ))
        throw InvalidCertificateException("Certificate is not valid: ${ex.message}")
      }
      
      // Check EKU for client authentication
      val eku = try { clientCert.extendedKeyUsage } catch (_: Exception) { null }
      if (eku != null && !eku.contains("1.3.6.1.5.5.7.3.2")) {
        Log.w(TAG, "Certificate doesn't include clientAuth EKU")
      }
      
      // Check expiry warning
      val msUntilExpiry = clientCert.notAfter.time - now
      if (msUntilExpiry <= expiryWarningMs) {
        sendEvent("onCertificateExpiry", bundleOf(
          "subject" to clientCert.subjectDN.toString(),
          "expiry" to clientCert.notAfter.time,
          "warning" to true
        ))
      }
      
      // Validate that private key matches the certificate
      pemParser.validateKeyPairMatch(privateKey, clientCert)
      
    } catch (e: InvalidCertificateException) {
      throw e
    } catch (e: Exception) {
      throw InvalidCertificateException("PEM certificate validation failed: ${e.message}")
    }
  }

  // Initialize SSLContext using certificate data (supports both P12 and PEM formats)
  private fun initializeSslContext(certData: String, keyData: String) {
    try {
      val keyStore = when (currentConfig?.certificateFormat) {
        CertificateFormat.PEM -> {
          initializeKeystoreFromPem(certData, keyData)
        }
        else -> {
          // P12 format (backward compatibility)
          initializeKeystoreFromP12(certData, keyData)
        }
      }

      // For PEM, keyData is private key content (keystore password is empty)
      // For P12, keyData is the actual password
      val keystorePassword = when (currentConfig?.certificateFormat) {
        CertificateFormat.PEM -> "" // PEM keystores use empty password
        else -> keyData // P12 uses the actual password
      }
      
      val kmf = KeyManagerFactory.getInstance(KeyManagerFactory.getDefaultAlgorithm()).apply {
        init(keyStore, keystorePassword.toCharArray())
      }

      val tmf = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm()).apply {
        init(null as KeyStore?) // system trust store
      }

      val tm = tmf.trustManagers.filterIsInstance<X509TrustManager>().firstOrNull()
        ?: throw MutualTlsException("No X509TrustManager found")

      val ssl = SSLContext.getInstance("TLS").apply {
        init(kmf.keyManagers, arrayOf(tm), SecureRandom())
      }

      setSslState(ssl.socketFactory, tm)
      Log.d(TAG, "SSLContext initialized with ${currentConfig?.certificateFormat?.value ?: "P12"} format")
    } catch (e: Exception) {
      setSslState(null, null)
      throw MutualTlsException("SSL Context initialization failed", e)
    }
  }
  
  private fun initializeKeystoreFromP12(p12Base64: String, password: String): KeyStore {
    val p12Data = Base64.decode(p12Base64, Base64.NO_WRAP)
    return KeyStore.getInstance("PKCS12").apply {
      load(ByteArrayInputStream(p12Data), password.toCharArray())
    }
  }
  
  private fun initializeKeystoreFromPem(certPem: String, keyPem: String): KeyStore {
    try {
      Log.d(TAG, "Initializing keystore from PEM data...")
      
      val passphrase = getPrivateKeyPassphraseFromStorage()
      Log.d(TAG, "Retrieved passphrase from storage: ${if (passphrase != null) "[PRESENT]" else "[NOT PRESENT]"}")
      
      val certificates = pemParser.parseCertificates(certPem)
      Log.d(TAG, "Parsed ${certificates.size} certificate(s) from PEM")
      
      val privateKey = pemParser.parsePrivateKey(keyPem, passphrase)
      Log.d(TAG, "Parsed private key from PEM: ${privateKey.algorithm} (${privateKey.format})")
      
      // Validate certificate-key pair match
      pemParser.validateKeyPairMatch(privateKey, certificates.first())
      Log.d(TAG, "Certificate-key pair validation successful")
      
      // Create a keystore and add the certificate chain and private key
      val keyStore = KeyStore.getInstance(KeyStore.getDefaultType()).apply {
        load(null, null)
      }
      
      // Add private key and certificate chain
      val certChain = certificates.toTypedArray()
      keyStore.setKeyEntry("client", privateKey, "".toCharArray(), certChain)
      
      Log.d(TAG, "PEM keystore initialized successfully with ${certificates.size} certificates")
      return keyStore
      
    } catch (e: Exception) {
      Log.e(TAG, "Failed to initialize keystore from PEM", e)
      throw MutualTlsException("Failed to initialize keystore from PEM: ${e.message}", e)
    }
  }

  // Build an OkHttp client that uses the configured SSLSocketFactory & TrustManager.
  private fun createMtlsOkHttpClient(): okhttp3.OkHttpClient {
    val factory = sslSocketFactory ?: throw MutualTlsException("SSL not configured")
    val tm = trustManager ?: throw MutualTlsException("Trust manager missing")
    val builder = okhttp3.OkHttpClient.Builder()
      .sslSocketFactory(factory, tm)
      .followRedirects(true)
      .followSslRedirects(true)
      .connectTimeout(30, java.util.concurrent.TimeUnit.SECONDS)
      .readTimeout(30, java.util.concurrent.TimeUnit.SECONDS)
      .writeTimeout(30, java.util.concurrent.TimeUnit.SECONDS)
      .dns(okhttp3.Dns.SYSTEM) // Use system DNS resolver

    if (currentConfig?.enableLogging == true) {
      builder.addInterceptor { chain ->
        val request = chain.request()
        Log.d(TAG, "mTLS Request ${request.method} ${request.url}")
        val start = System.currentTimeMillis()
        val response = chain.proceed(request)
        val duration = System.currentTimeMillis() - start
        Log.d(TAG, "mTLS Response ${response.code} (${duration}ms) for ${request.url}")
        moduleInstance?.sendEvent("onDebugLog", bundleOf(
          "type" to "request",
          "method" to request.method,
          "url" to request.url.toString(),
          "statusCode" to response.code,
          "duration" to duration
        ))
        response
      }
    }

    return builder.build()
  }

  // Perform request and return result map
  private fun performMtlsRequest(url: String): Map<String, Any> {
    try {
      val client = createMtlsOkHttpClient()
      val request = okhttp3.Request.Builder().url(url).build()
      client.newCall(request).execute().use { response ->
        val handshake = response.handshake
        return mapOf(
          "success" to true,
          "statusCode" to response.code,
          "statusMessage" to response.message,
          "headers" to response.headers.toMultimap(),
          "tlsVersion" to (handshake?.tlsVersion?.javaName ?: "unknown"),
          "cipherSuite" to (handshake?.cipherSuite?.javaName ?: "unknown")
        )
      }
    } catch (e: Exception) {
      Log.e(TAG, "mTLS request failed", e)
      throw MutualTlsException("mTLS test failed: ${e.message}", e)
    }
  }


  private fun performMtlsRequestWithOptions(url: String, method: String, headers: Map<String, String>, body: String?, responseType: String?): Map<String, Any> {
    try {
      val client = createMtlsOkHttpClient()
      val requestBuilder = okhttp3.Request.Builder().url(url)

      // Add headers
      headers.forEach { (key, value) ->
        requestBuilder.addHeader(key, value)
      }

      // Add body for POST, PUT, PATCH methods
      val requestBody = when (method) {
        "POST", "PUT", "PATCH" -> {
          val mediaType = (headers["content-type"] ?: "application/json").toMediaType()
          (body ?: "").toRequestBody(mediaType)
        }
        else -> null
      }

      val request = requestBuilder.method(method, requestBody).build()

      client.newCall(request).execute().use { response ->
        val handshake = response.handshake

        // Process response body based on responseType
        val responseBody = response.body?.bytes()?.let { bytes ->
          when (responseType) {
            "json", "text", null -> {
              // Return as string for json and text types
              String(bytes, Charsets.UTF_8)
            }
            "blob", "arraybuffer" -> {
              // Return base64 encoded data for binary response types
              Base64.encodeToString(bytes, Base64.NO_WRAP)
            }
            else -> {
              // Default to string
              String(bytes, Charsets.UTF_8)
            }
          }
        } ?: ""

        return mapOf(
          "success" to true,
          "statusCode" to response.code,
          "statusMessage" to response.message,
          "headers" to response.headers.toMultimap(),
          "body" to responseBody,
          "tlsVersion" to (handshake?.tlsVersion?.javaName ?: "unknown"),
          "cipherSuite" to (handshake?.cipherSuite?.javaName ?: "unknown")
        )
      }
    } catch (e: Exception) {
      Log.e(TAG, "mTLS request with options failed", e)
      throw MutualTlsException("mTLS request failed: ${e.message}", e)
    }
  }
}

