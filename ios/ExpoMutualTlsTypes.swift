// Copyright 2024-present Acube. All rights reserved.

import ExpoModulesCore
import Foundation

// MARK: - Enums and Types

public enum CertificateFormat: String, CaseIterable, Enumerable {
    case p12 = "p12"
    case pem = "pem"
}

public enum TlsState: String, CaseIterable, Enumerable {
    case notConfigured = "notConfigured"
    case configured = "configured"
    case error = "error"
}

internal enum KeyType {
    case rsa
    case ec
    case pkcs8
    case encryptedPkcs8
    case unknown
}

// MARK: - Configuration and Result Types

public struct MutualTlsConfig {
    let certificateFormat: CertificateFormat
    let keychainService: String?
    
    // P12 specific (backward compatibility)
    let keychainServiceForP12: String?
    let keychainServiceForPassword: String?
    
    // PEM specific
    let keychainServiceForPrivateKey: String?
    let keychainServiceForCertChain: String?
    
    let enableLogging: Bool
    let requireUserAuthentication: Bool
    let userAuthValiditySeconds: Int
    let expiryWarningDays: Int
    
    public init(from dictionary: [String: Any]) {
        self.certificateFormat = CertificateFormat(rawValue: dictionary["certificateFormat"] as? String ?? "p12") ?? .p12
        self.keychainService = dictionary["keychainService"] as? String
        self.keychainServiceForP12 = dictionary["keychainServiceForP12"] as? String
        self.keychainServiceForPassword = dictionary["keychainServiceForPassword"] as? String
        self.keychainServiceForPrivateKey = dictionary["keychainServiceForPrivateKey"] as? String
        self.keychainServiceForCertChain = dictionary["keychainServiceForCertChain"] as? String
        self.enableLogging = dictionary["enableLogging"] as? Bool ?? false
        self.requireUserAuthentication = dictionary["requireUserAuthentication"] as? Bool ?? false
        self.userAuthValiditySeconds = dictionary["userAuthValiditySeconds"] as? Int ?? 120
        self.expiryWarningDays = dictionary["expiryWarningDays"] as? Int ?? 30
    }
}

public struct ConfigureResult {
    let success: Bool
    let state: TlsState
    let hasCertificate: Bool
    
    func toDictionary() -> [String: Any] {
        return [
            "success": success,
            "state": state.rawValue,
            "hasCertificate": hasCertificate
        ]
    }
    
    static func failure(_ message: String = "Configuration failed") -> ConfigureResult {
        return ConfigureResult(success: false, state: .error, hasCertificate: false)
    }
}

public struct MakeRequestResult {
    let success: Bool
    let statusCode: Int
    let statusMessage: String
    let headers: [String: [String]]
    let body: String
    let tlsVersion: String
    let cipherSuite: String
    
    func toDictionary() -> [String: Any] {
        return [
            "success": success,
            "statusCode": statusCode,
            "statusMessage": statusMessage,
            "headers": headers,
            "body": body,
            "tlsVersion": tlsVersion,
            "cipherSuite": cipherSuite
        ]
    }
    
    static func failure(_ message: String = "Request failed") -> MakeRequestResult {
        return MakeRequestResult(
            success: false,
            statusCode: 0,
            statusMessage: message,
            headers: [:],
            body: "",
            tlsVersion: "unknown",
            cipherSuite: "unknown"
        )
    }
}