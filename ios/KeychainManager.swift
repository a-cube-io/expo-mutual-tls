// Copyright 2024-present Acube. All rights reserved.

import Foundation
import Security

internal final class KeychainManager {
    static let shared = KeychainManager()
    private init() {}

    private var logger: ((String, String) -> Void)?
    func setLogger(_ logger: @escaping (String, String) -> Void) { self.logger = logger }
    private func log(_ type: String, _ msg: String) { logger?(type, msg) }

    private let prefix = "com.expo.mutualtls."

    // MARK: - Helpers

    private func osStatusString(_ status: OSStatus) -> String {
        (SecCopyErrorMessageString(status, nil) as String?) ?? "OSStatus \(status)"
    }

    private func makeService(_ s: String) -> String { prefix + s }

    // MARK: - Generic blob storage (P12/PEM text)

    func storeInKeychain(service: String, data: String, account: String = "certificate") throws {
        guard let bytes = data.data(using: .utf8) else {
            throw ExpoMutualTlsError.unknownError("UTF8 encoding failed for service \(service)")
        }
        let serviceName = makeService(service)

        log("blob_storage", "Storing blob - service: \(serviceName), account: \(account), size: \(bytes.count)")

        let add: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: serviceName,
            kSecAttrAccount as String: account,
            kSecValueData as String: bytes,
            kSecAttrAccessible as String: kSecAttrAccessibleWhenUnlockedThisDeviceOnly
        ]

        var status = SecItemAdd(add as CFDictionary, nil)
        log("blob_storage", "Initial add status: \(status)")
        
        if status == errSecDuplicateItem {
            log("blob_storage", "Duplicate found, updating existing item")
            let query: [String: Any] = [
                kSecClass as String: kSecClassGenericPassword,
                kSecAttrService as String: serviceName,
                kSecAttrAccount as String: account
            ]
            let update: [String: Any] = [
                kSecValueData as String: bytes
            ]
            status = SecItemUpdate(query as CFDictionary, update as CFDictionary)
            log("blob_storage", "Update status: \(status)")
        }
        
        guard status == errSecSuccess else {
            log("blob_storage", "Storage FAILED: \(osStatusString(status))")
            throw ExpoMutualTlsError.keychainOperationFailed(status)
        }
        
        log("blob_storage", "Blob stored successfully")
    }

    func retrieveFromKeychain(service: String, account: String = "certificate") -> String? {
        let serviceName = makeService(service)
        log("blob_retrieve", "Retrieving blob - service: \(serviceName), account: \(account)")
        
        let q: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: serviceName,
            kSecAttrAccount as String: account,
            kSecReturnData as String: true,
            kSecMatchLimit as String: kSecMatchLimitOne
        ]
        var item: CFTypeRef?
        let status = SecItemCopyMatching(q as CFDictionary, &item)
        log("blob_retrieve", "Retrieve status: \(status)")
        
        guard status == errSecSuccess, let data = item as? Data else { 
            if status != errSecItemNotFound {
                log("blob_retrieve", "Retrieval failed: \(osStatusString(status))")
            }
            return nil 
        }
        
        let result = String(data: data, encoding: .utf8)
        log("blob_retrieve", "Retrieved blob successfully, size: \(result?.count ?? 0)")
        return result
    }

    func removeFromKeychain(service: String, account: String = "certificate") throws {
        let serviceName = makeService(service)
        log("blob_remove", "Removing blob - service: \(serviceName), account: \(account)")
        
        let q: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: serviceName,
            kSecAttrAccount as String: account
        ]
        let status = SecItemDelete(q as CFDictionary)
        log("blob_remove", "Delete status: \(status)")
        
        guard status == errSecSuccess || status == errSecItemNotFound else {
            log("blob_remove", "Delete FAILED: \(osStatusString(status))")
            throw ExpoMutualTlsError.keychainOperationFailed(status)
        }
        
        log("blob_remove", "Blob removed successfully")
    }

    func keychainContainsItem(service: String, account: String = "certificate") -> Bool {
        let result = retrieveFromKeychain(service: service, account: account) != nil
        log("blob_check", "Contains check for service '\(service)': \(result)")
        return result
    }

    // MARK: - PEM certificate + private key storage

    /// Adds/replace certificate by label.
    private func upsertCertificate(label: String, certificate: SecCertificate) throws {
        log("cert_upsert", "Upserting certificate with label: \(label)")
        
        // Try add
        let add: [String: Any] = [
            kSecClass as String: kSecClassCertificate,
            kSecAttrLabel as String: label,
            kSecValueRef as String: certificate
        ]
        var status = SecItemAdd(add as CFDictionary, nil)
        log("cert_upsert", "Certificate add status: \(status)")
        
        if status == errSecDuplicateItem {
            log("cert_upsert", "Certificate exists, replacing")
            // delete then add (certificate attributes generally not updatable)
            let del: [String: Any] = [
                kSecClass as String: kSecClassCertificate,
                kSecAttrLabel as String: label
            ]
            let delStatus = SecItemDelete(del as CFDictionary)
            log("cert_upsert", "Certificate delete status: \(delStatus)")
            
            status = SecItemAdd(add as CFDictionary, nil)
            log("cert_upsert", "Certificate re-add status: \(status)")
        }
        
        guard status == errSecSuccess else { 
            log("cert_upsert", "Certificate upsert FAILED: \(osStatusString(status))")
            throw ExpoMutualTlsError.keychainOperationFailed(status) 
        }
        
        log("cert_upsert", "Certificate upserted successfully")
    }

    /// Adds/replace private key by label + applicationTag, makes it permanent.
    private func upsertPrivateKey(label: String, applicationTag: Data, privateKey: SecKey) throws {
        log("key_upsert", "Upserting private key with label: \(label)")
        
        // Access control is optional but recommended for private keys
        var error: Unmanaged<CFError>?
        let access = SecAccessControlCreateWithFlags(
            nil,
            kSecAttrAccessibleWhenUnlockedThisDeviceOnly,
            [.privateKeyUsage],
            &error
        )
        if let e = error?.takeRetainedValue() {
            log("key_upsert", "Access control creation failed: \(e)")
            throw ExpoMutualTlsError.unknownError("SecAccessControl error: \(e)")
        }

        let add: [String: Any] = [
            kSecClass as String: kSecClassKey,
            kSecAttrLabel as String: label,
            kSecAttrApplicationTag as String: applicationTag,
            kSecAttrIsPermanent as String: true,
            kSecAttrAccessControl as String: access as Any,
            kSecValueRef as String: privateKey
        ]

        var status = SecItemAdd(add as CFDictionary, nil)
        log("key_upsert", "Private key add status: \(status)")
        
        if status == errSecDuplicateItem {
            log("key_upsert", "Private key exists, replacing")
            // delete then add (many key attributes aren't updatable)
            let del: [String: Any] = [
                kSecClass as String: kSecClassKey,
                kSecAttrApplicationTag as String: applicationTag
            ]
            let delStatus = SecItemDelete(del as CFDictionary)
            log("key_upsert", "Private key delete status: \(delStatus)")
            
            status = SecItemAdd(add as CFDictionary, nil)
            log("key_upsert", "Private key re-add status: \(status)")
        }
        
        guard status == errSecSuccess else { 
            log("key_upsert", "Private key upsert FAILED: \(osStatusString(status))")
            throw ExpoMutualTlsError.keychainOperationFailed(status) 
        }
        
        log("key_upsert", "Private key upserted successfully")
    }

    /// Public API: store PEM cert + key; they will be paired by public key hash.
    func storePEMCertificateAndKey(certService: String, keyService: String, certificate: SecCertificate, privateKey: SecKey) throws {
        let certLabel = makeService(certService)
        let keyLabel  = makeService(keyService)
        let keyTag    = Data(keyLabel.utf8)

        log("pem_storage", "Starting PEM storage - cert label: \(certLabel), key label: \(keyLabel)")
        
        try upsertCertificate(label: certLabel, certificate: certificate)
        try upsertPrivateKey(label: keyLabel, applicationTag: keyTag, privateKey: privateKey)
        
        log("pem_storage", "PEM cert+key stored successfully")
    }

    func retrievePEMCertificate(certService: String) throws -> SecCertificate {
        let label = makeService(certService)
        log("pem_retrieve", "Retrieving PEM certificate with label: \(label)")
        
        let q: [String: Any] = [
            kSecClass as String: kSecClassCertificate,
            kSecAttrLabel as String: label,
            kSecReturnRef as String: true,
            kSecMatchLimit as String: kSecMatchLimitOne
        ]
        var item: CFTypeRef?
        let status = SecItemCopyMatching(q as CFDictionary, &item)
        log("pem_retrieve", "Certificate query status: \(status)")
        
        guard status == errSecSuccess else {
            log("pem_retrieve", "Certificate retrieval FAILED: \(osStatusString(status))")
            throw ExpoMutualTlsError.certificateNotFound("Certificate \(label) not found (\(osStatusString(status)))")
        }
        
        let cert = item as! SecCertificate
        
        log("pem_retrieve", "Certificate retrieved successfully")
        return cert
    }

    func retrievePEMPrivateKey(keyService: String) throws -> SecKey {
        let label = makeService(keyService)
        let tag   = Data(label.utf8)
        log("pem_retrieve", "Retrieving PEM private key with label: \(label)")
        
        let q: [String: Any] = [
            kSecClass as String: kSecClassKey,
            kSecAttrApplicationTag as String: tag,
            kSecReturnRef as String: true,
            kSecMatchLimit as String: kSecMatchLimitOne
        ]
        var item: CFTypeRef?
        let status = SecItemCopyMatching(q as CFDictionary, &item)
        log("pem_retrieve", "Private key query status: \(status)")
        
        guard status == errSecSuccess else {
            log("pem_retrieve", "Private key retrieval FAILED: \(osStatusString(status))")
            throw ExpoMutualTlsError.certificateNotFound("Private key \(label) not found (\(osStatusString(status)))")
        }
        
        let key = item as! SecKey
        
        log("pem_retrieve", "Private key retrieved successfully")
        return key
    }

    /// Try to fetch an Identity by label; if not found, reconstruct it from cert+key.
    func retrievePEMIdentity(certService: String, keyService: String) throws -> SecIdentity {
        let label = makeService(certService) // we use cert label to query identity
        log("pem_identity", "Retrieving PEM identity with label: \(label)")
        
        // 1) Try direct identity query
        let q: [String: Any] = [
            kSecClass as String: kSecClassIdentity,
            kSecAttrLabel as String: label,
            kSecReturnRef as String: true,
            kSecMatchLimit as String: kSecMatchLimitOne
        ]
        var item: CFTypeRef?
        let status = SecItemCopyMatching(q as CFDictionary, &item)
        log("pem_identity", "Direct identity query status: \(status)")
        
        if status == errSecSuccess {
            let identity = item as! SecIdentity
            log("pem_identity", "Direct identity retrieval successful")
            return identity
        }

        // 2) Reconstruct identity using cert+key
        log("pem_identity", "Direct identity not found, reconstructing from cert+key")
        let cert = try retrievePEMCertificate(certService: certService)
        let key  = try retrievePEMPrivateKey(keyService: keyService)

        // Verify they actually match (public key == cert key)
        if let certKey = SecCertificateCopyKey(cert),
           let pubFromPriv = SecKeyCopyPublicKey(key) {
            
            let certKeyData = SecKeyCopyExternalRepresentation(certKey, nil)
            let pubKeyData = SecKeyCopyExternalRepresentation(pubFromPriv, nil)
            
            if let certData = certKeyData as? Data,
               let pubData = pubKeyData as? Data,
               certData != pubData {
                log("pem_identity", "Certificate and private key do NOT match")
                throw ExpoMutualTlsError.unknownError("Certificate and private key do not match")
            }
        }

        log("pem_identity", "Certificate and private key match, creating identity")
        
        // Return a mock identity since iOS doesn't support SecIdentityCreateWithCertificate
        // The actual identity should be created at TLS handshake time by matching cert+key
        log("pem_identity", "PEM identity reconstruction not directly supported on iOS")
        log("pem_identity", "Certificate and key are valid and will be matched at TLS time")
        
        // For now, we'll create an identity by storing both cert and key, then retrieving as identity
        // This is a workaround since iOS expects identities to be imported together (via P12)
        throw ExpoMutualTlsError.notImplemented("PEM identity reconstruction requires P12 conversion on iOS")
    }

    func hasPEMCertificate(certService: String, keyService: String) -> Bool {
        log("pem_check", "Checking PEM certificate existence - cert: \(certService), key: \(keyService)")
        do {
            _ = try retrievePEMCertificate(certService: certService)
            _ = try retrievePEMPrivateKey(keyService: keyService)
            log("pem_check", "PEM certificate check: PASSED")
            return true
        } catch {
            log("pem_check", "PEM certificate check FAILED: \(error.localizedDescription)")
            return false
        }
    }

    func removePEMCertificate(certService: String, keyService: String) throws {
        let certLabel = makeService(certService)
        let keyLabel  = makeService(keyService)
        let keyTag    = Data(keyLabel.utf8)

        log("pem_remove", "Removing PEM cert: \(certLabel), key: \(keyLabel)")

        // delete cert
        let delCert: [String: Any] = [
            kSecClass as String: kSecClassCertificate,
            kSecAttrLabel as String: certLabel
        ]
        let cs = SecItemDelete(delCert as CFDictionary)
        log("pem_remove", "Certificate delete status: \(cs)")
        
        guard cs == errSecSuccess || cs == errSecItemNotFound else {
            log("pem_remove", "Certificate delete FAILED: \(osStatusString(cs))")
            throw ExpoMutualTlsError.keychainOperationFailed(cs)
        }

        // delete key by applicationTag
        let delKey: [String: Any] = [
            kSecClass as String: kSecClassKey,
            kSecAttrApplicationTag as String: keyTag
        ]
        let ks = SecItemDelete(delKey as CFDictionary)
        log("pem_remove", "Private key delete status: \(ks)")
        
        guard ks == errSecSuccess || ks == errSecItemNotFound else {
            log("pem_remove", "Private key delete FAILED: \(osStatusString(ks))")
            throw ExpoMutualTlsError.keychainOperationFailed(ks)
        }
        
        log("pem_remove", "PEM cert+key removed successfully")
    }
}