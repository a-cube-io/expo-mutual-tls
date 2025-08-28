// Copyright 2024-present Acube. All rights reserved.

import ExpoModulesCore
import Foundation

// MARK: - Error Handling

public enum ExpoMutualTlsError: Error, LocalizedError, CodedError {
    // Configuration Errors
    case notConfigured
    case invalidConfiguration(String)
    case missingRequiredField(String)
    
    // Certificate Errors
    case invalidCertificateFormat(String)
    case certificateImportFailed(String)
    case certificateValidationFailed(String)
    case certificateNotFound(String)
    case keyPairMismatch
    
    // Keychain Errors
    case keychainOperationFailed(OSStatus)
    case keychainAccessDenied
    case biometricAuthenticationFailed
    
    // Network Errors
    case networkRequestFailed(String)
    case sslHandshakeFailed(String)
    case connectionTimeout
    case invalidURL(String)
    
    // Parsing Errors
    case pemParsingFailed(String)
    case p12ParsingFailed(String)
    case invalidKeyFormat(String)
    
    // Implementation Errors
    case notImplemented(String)
    case unknownError(String)
    
    public var errorDescription: String? {
        switch self {
        case .notConfigured:
            return "Module not configured - call configure() first"
        case .invalidConfiguration(let message):
            return "Invalid configuration: \(message)"
        case .missingRequiredField(let field):
            return "Missing required field: \(field)"
        case .invalidCertificateFormat(let message):
            return "Invalid certificate format: \(message)"
        case .certificateImportFailed(let message):
            return "Certificate import failed: \(message)"
        case .certificateValidationFailed(let message):
            return "Certificate validation failed: \(message)"
        case .certificateNotFound(let service):
            return "Certificate not found in keychain: \(service)"
        case .keyPairMismatch:
            return "Private key does not match certificate public key"
        case .keychainOperationFailed(let status):
            return "Keychain operation failed: \(status)"
        case .keychainAccessDenied:
            return "Keychain access denied - check permissions or biometric authentication"
        case .biometricAuthenticationFailed:
            return "Biometric authentication failed"
        case .networkRequestFailed(let message):
            return "Network request failed: \(message)"
        case .sslHandshakeFailed(let message):
            return "SSL handshake failed: \(message)"
        case .connectionTimeout:
            return "Connection timeout"
        case .invalidURL(let url):
            return "Invalid URL: \(url)"
        case .pemParsingFailed(let message):
            return "PEM parsing failed: \(message)"
        case .p12ParsingFailed(let message):
            return "P12 parsing failed: \(message)"
        case .invalidKeyFormat(let message):
            return "Invalid key format: \(message)"
        case .notImplemented(let phase):
            return "Feature not yet implemented: \(phase)"
        case .unknownError(let message):
            return "Unknown error: \(message)"
        }
    }
    
    public var code: String {
        switch self {
        case .notConfigured: return "NOT_CONFIGURED"
        case .invalidConfiguration: return "INVALID_CONFIGURATION"
        case .missingRequiredField: return "MISSING_REQUIRED_FIELD"
        case .invalidCertificateFormat: return "INVALID_CERTIFICATE_FORMAT"
        case .certificateImportFailed: return "CERTIFICATE_IMPORT_FAILED"
        case .certificateValidationFailed: return "CERTIFICATE_VALIDATION_FAILED"
        case .certificateNotFound: return "CERTIFICATE_NOT_FOUND"
        case .keyPairMismatch: return "KEY_PAIR_MISMATCH"
        case .keychainOperationFailed: return "KEYCHAIN_OPERATION_FAILED"
        case .keychainAccessDenied: return "KEYCHAIN_ACCESS_DENIED"
        case .biometricAuthenticationFailed: return "BIOMETRIC_AUTH_FAILED"
        case .networkRequestFailed: return "NETWORK_REQUEST_FAILED"
        case .sslHandshakeFailed: return "SSL_HANDSHAKE_FAILED"
        case .connectionTimeout: return "CONNECTION_TIMEOUT"
        case .invalidURL: return "INVALID_URL"
        case .pemParsingFailed: return "PEM_PARSING_FAILED"
        case .p12ParsingFailed: return "P12_PARSING_FAILED"
        case .invalidKeyFormat: return "INVALID_KEY_FORMAT"
        case .notImplemented: return "NOT_IMPLEMENTED"
        case .unknownError: return "UNKNOWN_ERROR"
        }
    }
    
    public var description: String {
        return errorDescription ?? "Unknown error"
    }
}