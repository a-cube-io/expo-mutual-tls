package expo.modules.mutualtls

import android.content.Context
import android.content.SharedPreferences
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import android.util.Base64
import android.util.Log
import androidx.core.content.edit
import java.security.KeyStore
import javax.crypto.Cipher
import javax.crypto.KeyGenerator
import javax.crypto.SecretKey
import javax.crypto.spec.GCMParameterSpec
import java.nio.ByteBuffer

/**
 * KeychainManager provides react-native-keychain compatible secure storage
 * using Android Keystore for hardware-backed encryption when available.
 */
class KeychainManager(private val context: Context) {
    
    companion object {
        private const val TAG = "KeychainManager"
        private const val PREFS_NAME = "RNKeychainManager_PREFS"
        private const val ANDROID_KEYSTORE = "AndroidKeyStore"
        private const val AES_MODE = "AES/GCM/NoPadding"
        private const val IV_SIZE = 12
        private const val GCM_TAG_LEN = 128
        private const val KEY_ALIAS_PREFIX = "RNKeychainManager_"
    }
    
    private fun getSharedPreferences(): SharedPreferences {
        return context.getSharedPreferences(PREFS_NAME, Context.MODE_PRIVATE)
    }
    
    /**
     * Store credentials securely using Android Keystore encryption
     * @param service Service identifier (equivalent to server in react-native-keychain)
     * @param username Username to store
     * @param password Password to store
     * @param options Storage options including authentication requirements
     * @return true if successful, false otherwise
     */
    fun setInternetCredentials(
        service: String,
        username: String,
        password: String,
        options: KeychainOptions = KeychainOptions()
    ): Boolean {
        return try {
            val keyAlias = "${KEY_ALIAS_PREFIX}$service"
            val secretKey = getOrCreateSecretKey(keyAlias, options)
            
            // Encrypt both username and password
            val usernameEncrypted = encryptString(username, secretKey)
            val passwordEncrypted = encryptString(password, secretKey)
            
            // Store in SharedPreferences
            getSharedPreferences().edit {
                putString("${service}_u", usernameEncrypted)
                putString("${service}_p", passwordEncrypted)
                putString("${service}_s", service) // service name
            }
            
            Log.d(TAG, "Successfully stored credentials for service: $service")
            true
        } catch (e: Exception) {
            Log.e(TAG, "Failed to store credentials for service: $service", e)
            false
        }
    }
    
    /**
     * Retrieve stored credentials
     * @param service Service identifier
     * @return KeychainCredentials object or null if not found
     */
    fun getInternetCredentials(service: String): KeychainCredentials? {
        return try {
            val prefs = getSharedPreferences()
            val usernameEncrypted = prefs.getString("${service}_u", null) ?: return null
            val passwordEncrypted = prefs.getString("${service}_p", null) ?: return null
            
            val keyAlias = "${KEY_ALIAS_PREFIX}$service"
            val secretKey = getSecretKey(keyAlias) ?: return null
            
            val username = decryptString(usernameEncrypted, secretKey)
            val password = decryptString(passwordEncrypted, secretKey)
            
            KeychainCredentials(
                server = service,
                username = username,
                password = password,
                storage = "AES" // Indicate AES storage type
            )
        } catch (e: Exception) {
            Log.e(TAG, "Failed to retrieve credentials for service: $service", e)
            null
        }
    }
    
    /**
     * Reset/delete stored credentials
     * @param service Service identifier
     * @return true if successful
     */
    fun resetInternetCredentials(service: String): Boolean {
        return try {
            getSharedPreferences().edit {
                remove("${service}_u")
                remove("${service}_p")
                remove("${service}_s")
            }
            
            // Also remove the key from Android Keystore
            val keyAlias = "${KEY_ALIAS_PREFIX}$service"
            removeSecretKey(keyAlias)
            
            Log.d(TAG, "Successfully reset credentials for service: $service")
            true
        } catch (e: Exception) {
            Log.e(TAG, "Failed to reset credentials for service: $service", e)
            false
        }
    }
    
    /**
     * Check if credentials exist for a service
     * @param service Service identifier
     * @return true if credentials exist
     */
    fun hasInternetCredentials(service: String): Boolean {
        val prefs = getSharedPreferences()
        return prefs.contains("${service}_u") && prefs.contains("${service}_p")
    }
    
    /**
     * Get or create a secret key in Android Keystore
     * @param keyAlias Alias for the key
     * @param options Key generation options
     * @return SecretKey for encryption/decryption
     */
    private fun getOrCreateSecretKey(keyAlias: String, options: KeychainOptions): SecretKey {
        val keyStore = KeyStore.getInstance(ANDROID_KEYSTORE).apply { load(null) }
        
        // Return existing key if available
        keyStore.getKey(keyAlias, null)?.let { return it as SecretKey }
        
        // Generate new key
        val keyGenerator = KeyGenerator.getInstance(KeyProperties.KEY_ALGORITHM_AES, ANDROID_KEYSTORE)
        val keyGenParameterSpec = KeyGenParameterSpec.Builder(
            keyAlias,
            KeyProperties.PURPOSE_ENCRYPT or KeyProperties.PURPOSE_DECRYPT
        )
            .setBlockModes(KeyProperties.BLOCK_MODE_GCM)
            .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE)
            .setKeySize(256)
            
        // Apply user authentication requirements if specified
        if (options.requireUserAuthentication) {
            keyGenParameterSpec.setUserAuthenticationRequired(true)
            
            if (options.authValiditySeconds > 0) {
                if (android.os.Build.VERSION.SDK_INT >= android.os.Build.VERSION_CODES.R) {
                    keyGenParameterSpec.setUserAuthenticationParameters(
                        options.authValiditySeconds,
                        KeyProperties.AUTH_DEVICE_CREDENTIAL or KeyProperties.AUTH_BIOMETRIC_STRONG
                    )
                } else {
                    @Suppress("DEPRECATION")
                    keyGenParameterSpec.setUserAuthenticationValidityDurationSeconds(options.authValiditySeconds)
                }
            }
        }
        
        keyGenerator.init(keyGenParameterSpec.build())
        return keyGenerator.generateKey()
    }
    
    /**
     * Get existing secret key from Android Keystore
     */
    private fun getSecretKey(keyAlias: String): SecretKey? {
        return try {
            val keyStore = KeyStore.getInstance(ANDROID_KEYSTORE).apply { load(null) }
            keyStore.getKey(keyAlias, null) as? SecretKey
        } catch (e: Exception) {
            Log.e(TAG, "Failed to get secret key: $keyAlias", e)
            null
        }
    }
    
    /**
     * Remove secret key from Android Keystore
     */
    private fun removeSecretKey(keyAlias: String) {
        try {
            val keyStore = KeyStore.getInstance(ANDROID_KEYSTORE).apply { load(null) }
            keyStore.deleteEntry(keyAlias)
        } catch (e: Exception) {
            Log.e(TAG, "Failed to remove secret key: $keyAlias", e)
        }
    }
    
    /**
     * Encrypt a string using the provided secret key
     */
    private fun encryptString(plaintext: String, secretKey: SecretKey): String {
        val cipher = Cipher.getInstance(AES_MODE)
        cipher.init(Cipher.ENCRYPT_MODE, secretKey)
        val iv = cipher.iv
        val cipherText = cipher.doFinal(plaintext.toByteArray(Charsets.UTF_8))
        
        // Combine IV + ciphertext
        val combined = ByteBuffer.allocate(iv.size + cipherText.size)
            .put(iv)
            .put(cipherText)
            .array()
            
        return Base64.encodeToString(combined, Base64.NO_WRAP)
    }
    
    /**
     * Decrypt a string using the provided secret key
     */
    private fun decryptString(encryptedData: String, secretKey: SecretKey): String {
        val combined = Base64.decode(encryptedData, Base64.NO_WRAP)
        
        if (combined.size < IV_SIZE) {
            throw IllegalArgumentException("Encrypted data too short")
        }
        
        val buffer = ByteBuffer.wrap(combined)
        val iv = ByteArray(IV_SIZE)
        buffer.get(iv)
        val cipherText = ByteArray(buffer.remaining())
        buffer.get(cipherText)
        
        val cipher = Cipher.getInstance(AES_MODE)
        val spec = GCMParameterSpec(GCM_TAG_LEN, iv)
        cipher.init(Cipher.DECRYPT_MODE, secretKey, spec)
        
        val decryptedBytes = cipher.doFinal(cipherText)
        return String(decryptedBytes, Charsets.UTF_8)
    }
}

/**
 * Configuration options for keychain storage
 */
data class KeychainOptions(
    val requireUserAuthentication: Boolean = false,
    val authValiditySeconds: Int = -1
)

/**
 * Credentials retrieved from keychain
 */
data class KeychainCredentials(
    val server: String,
    val username: String,
    val password: String,
    val storage: String
)

/**
 * Result of storing credentials
 */
data class KeychainResult(
    val service: String,
    val storage: String
)