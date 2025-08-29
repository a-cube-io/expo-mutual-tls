// Copyright 2024-present Acube. All rights reserved.

import Foundation
import Security

internal class CertificateParser {
    
    static let shared = CertificateParser()
    
    private init() {}
    
    func parseP12Certificate(p12Data: Data, password: String) throws -> (identity: SecIdentity, certificateChain: [SecCertificate]) {
        let importOptions: [String: Any] = [
            kSecImportExportPassphrase as String: password
        ]
        
        var importResults: CFArray?
        let status = SecPKCS12Import(p12Data as CFData, importOptions as CFDictionary, &importResults)
        
        guard status == errSecSuccess else {
            throw ExpoMutualTlsError.p12ParsingFailed("P12 import failed with status: \(status)")
        }
        
        guard let results = importResults as? [[String: Any]],
              let firstResult = results.first else {
            throw ExpoMutualTlsError.p12ParsingFailed("No results from P12 import")
        }
        
        guard let identityRef = firstResult[kSecImportItemIdentity as String] else {
            throw ExpoMutualTlsError.p12ParsingFailed("No identity found in P12 data")
        }
        
        let identity = identityRef as! SecIdentity
        
        let certificateChain = firstResult[kSecImportItemCertChain as String] as? [SecCertificate] ?? []
        
        return (identity: identity, certificateChain: certificateChain)
    }
    
    func extractCommonName(from certificate: SecCertificate) -> String? {
        var commonName: CFString?
        let status = SecCertificateCopyCommonName(certificate, &commonName)
        
        guard status == errSecSuccess, let name = commonName else {
            return nil
        }
        
        return name as String
    }
    
    // MARK: - PEM Certificate Parsing
    
    func parsePEMCertificate(pemString: String) throws -> SecCertificate {
        // Extract certificate content between PEM headers
        let certPattern = "-----BEGIN CERTIFICATE-----([\\s\\S]*?)-----END CERTIFICATE-----"
        guard let regex = try? NSRegularExpression(pattern: certPattern, options: []),
              let match = regex.firstMatch(in: pemString, options: [], range: NSRange(location: 0, length: pemString.count)) else {
            throw ExpoMutualTlsError.pemParsingFailed("Invalid PEM certificate format")
        }
        
        let certBase64 = String(pemString[Range(match.range(at: 1), in: pemString)!])
            .replacingOccurrences(of: "\\s", with: "", options: .regularExpression)
        
        guard let certData = Data(base64Encoded: certBase64) else {
            throw ExpoMutualTlsError.pemParsingFailed("Invalid Base64 certificate data")
        }
        
        guard let certificate = SecCertificateCreateWithData(nil, certData as CFData) else {
            throw ExpoMutualTlsError.pemParsingFailed("Failed to create certificate from data")
        }
        
        return certificate
    }
    
    func parsePEMPrivateKey(pemString: String) throws -> SecKey {
        // Detect key type and extract content
        let keyPatterns = [
            ("PRIVATE KEY", "-----BEGIN PRIVATE KEY-----([\\s\\S]*?)-----END PRIVATE KEY-----"),
            ("RSA PRIVATE KEY", "-----BEGIN RSA PRIVATE KEY-----([\\s\\S]*?)-----END RSA PRIVATE KEY-----"),
            ("EC PRIVATE KEY", "-----BEGIN EC PRIVATE KEY-----([\\s\\S]*?)-----END EC PRIVATE KEY-----")
        ]
        
        var keyData: Data?
        var keyType: String?
        
        for (type, pattern) in keyPatterns {
            if let regex = try? NSRegularExpression(pattern: pattern, options: []),
               let match = regex.firstMatch(in: pemString, options: [], range: NSRange(location: 0, length: pemString.count)) {
                
                let keyBase64 = String(pemString[Range(match.range(at: 1), in: pemString)!])
                    .replacingOccurrences(of: "\\s", with: "", options: .regularExpression)
                
                keyData = Data(base64Encoded: keyBase64)
                keyType = type
                break
            }
        }
        
        guard let data = keyData, let type = keyType else {
            throw ExpoMutualTlsError.pemParsingFailed("Invalid PEM private key format")
        }
        
        // Create key attributes based on detected type
        var attributes: [String: Any] = [
            kSecAttrKeyType as String: kSecAttrKeyTypeRSA,
            kSecAttrKeyClass as String: kSecAttrKeyClassPrivate
        ]
        
        if type.contains("EC") {
            attributes[kSecAttrKeyType as String] = kSecAttrKeyTypeEC
        }
        
        var error: Unmanaged<CFError>?
        guard let privateKey = SecKeyCreateWithData(data as CFData, attributes as CFDictionary, &error) else {
            let errorMsg = error?.takeRetainedValue().localizedDescription ?? "Unknown error"
            throw ExpoMutualTlsError.pemParsingFailed("Failed to create private key: \(errorMsg)")
        }
        
        return privateKey
    }
}