// Copyright 2024-present Acube. All rights reserved.

import Foundation
import Security

internal class KeychainManager {
    
    static let shared = KeychainManager()
    
    private init() {}
    
    func storeInKeychain(service: String, data: String) throws {
        let fullService = "com.expo.mutualtls." + service
        
        var query: [String: Any] = [
            kSecClass as String: kSecClassInternetPassword,
            kSecAttrServer as String: fullService,
            kSecAttrProtocol as String: kSecAttrProtocolHTTPS,
            kSecAttrAccount as String: "certificate",
            kSecValueData as String: data.data(using: .utf8)!,
            kSecAttrAccessible as String: kSecAttrAccessibleWhenUnlockedThisDeviceOnly
        ]
        
        // Delete existing item first
        SecItemDelete(query as CFDictionary)
        
        // Add new item
        let status = SecItemAdd(query as CFDictionary, nil)
        
        guard status == errSecSuccess else {
            throw ExpoMutualTlsError.keychainOperationFailed(status)
        }
    }
    
    func retrieveFromKeychain(service: String) -> String? {
        let fullService = "com.expo.mutualtls." + service
        
        let query: [String: Any] = [
            kSecClass as String: kSecClassInternetPassword,
            kSecAttrServer as String: fullService,
            kSecAttrProtocol as String: kSecAttrProtocolHTTPS,
            kSecReturnData as String: true,
            kSecMatchLimit as String: kSecMatchLimitOne
        ]
        
        var result: AnyObject?
        let status = SecItemCopyMatching(query as CFDictionary, &result)
        
        guard status == errSecSuccess,
              let data = result as? Data,
              let string = String(data: data, encoding: .utf8) else {
            return nil
        }
        
        return string
    }
    
    func removeFromKeychain(service: String) throws {
        let fullService = "com.expo.mutualtls." + service
        
        let query: [String: Any] = [
            kSecClass as String: kSecClassInternetPassword,
            kSecAttrServer as String: fullService,
            kSecAttrProtocol as String: kSecAttrProtocolHTTPS
        ]
        
        let status = SecItemDelete(query as CFDictionary)
        
        // Success if item was deleted or if it didn't exist
        guard status == errSecSuccess || status == errSecItemNotFound else {
            throw ExpoMutualTlsError.keychainOperationFailed(status)
        }
    }
    
    func keychainContainsItem(service: String) -> Bool {
        return retrieveFromKeychain(service: service) != nil
    }
}