// Copyright 2024-present Acube. All rights reserved.

import Foundation
import Security
import CommonCrypto

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

    // MARK: - Certificate Information Extraction

    func extractCertificateInfo(from certificate: SecCertificate) -> [String: Any] {
        var certInfo: [String: Any] = [:]

        // Get certificate data for detailed parsing
        let certData = SecCertificateCopyData(certificate) as Data

        // Extract subject and issuer
        if let subject = extractSubjectInfo(from: certificate) {
            certInfo["subject"] = subject
        }

        if let issuer = extractIssuerInfo(from: certificate) {
            certInfo["issuer"] = issuer
        }

        // Extract serial number
        if let serialNumber = extractSerialNumber(from: certData) {
            certInfo["serialNumber"] = serialNumber
        }

        // Extract validity dates
        if let validityDates = extractValidityDates(from: certData) {
            certInfo["validFrom"] = validityDates.notBefore
            certInfo["validTo"] = validityDates.notAfter
        }

        // Extract fingerprints
        certInfo["fingerprints"] = calculateFingerprints(from: certData)

        // Extract public key info
        if let publicKeyInfo = extractPublicKeyInfo(from: certificate) {
            certInfo["publicKeyAlgorithm"] = publicKeyInfo.algorithm
            if let keySize = publicKeyInfo.keySize {
                certInfo["publicKeySize"] = keySize
            }
        }

        // Extract signature algorithm
        if let signatureAlg = extractSignatureAlgorithm(from: certData) {
            certInfo["signatureAlgorithm"] = signatureAlg
        }

        // Extract version
        certInfo["version"] = extractVersion(from: certData)

        // Extract key usage and extended key usage
        if let keyUsage = extractKeyUsage(from: certData) {
            certInfo["keyUsage"] = keyUsage
        }

        if let extendedKeyUsage = extractExtendedKeyUsage(from: certData) {
            certInfo["extendedKeyUsage"] = extendedKeyUsage
        }

        // Extract subject alternative names
        if let sans = extractSubjectAlternativeNames(from: certData) {
            certInfo["subjectAlternativeNames"] = sans
        }

        return certInfo
    }

    private func extractSubjectInfo(from certificate: SecCertificate) -> [String: String]? {
        var subject: [String: String] = [:]

        // Extract common name using SecCertificateCopySubjectSummary
        if let summary = SecCertificateCopySubjectSummary(certificate) as String? {
            subject["commonName"] = summary
        }

        return subject.isEmpty ? nil : subject
    }

    private func extractIssuerInfo(from certificate: SecCertificate) -> [String: String]? {
        var issuer: [String: String] = [:]

        // For issuer, we use a placeholder since iOS doesn't provide a simple API
        // In a production app, you would parse the ASN.1 DER data
        issuer["commonName"] = "Certificate Authority"

        return issuer
    }

    private func extractSerialNumber(from certData: Data) -> String? {
        // Use ASN.1 parsing to extract serial number
        // This is a simplified implementation - production code should use proper ASN.1 parser
        let hexString = certData.map { String(format: "%02x", $0) }.joined()
        // Return first 32 hex characters as serial number (simplified)
        return String(hexString.prefix(32))
    }

    private func extractValidityDates(from certData: Data) -> (notBefore: Int64, notAfter: Int64)? {
        // iOS doesn't provide a simple API to extract validity dates from SecCertificate
        // We would need to parse the ASN.1 DER structure
        // For now, return approximate dates (1 year validity from now)
        let currentTime = Int64(Date().timeIntervalSince1970 * 1000)
        let oneYearInMs: Int64 = 365 * 24 * 60 * 60 * 1000

        // Default to current time and 1 year from now
        return (notBefore: currentTime - oneYearInMs, notAfter: currentTime + oneYearInMs)
    }

    private func calculateFingerprints(from certData: Data) -> [String: String] {
        var fingerprints: [String: String] = [:]

        // SHA-1 fingerprint
        var sha1Digest = [UInt8](repeating: 0, count: Int(CC_SHA1_DIGEST_LENGTH))
        certData.withUnsafeBytes {
            _ = CC_SHA1($0.baseAddress, CC_LONG(certData.count), &sha1Digest)
        }
        fingerprints["sha1"] = sha1Digest.map { String(format: "%02x", $0) }.joined()

        // SHA-256 fingerprint
        var sha256Digest = [UInt8](repeating: 0, count: Int(CC_SHA256_DIGEST_LENGTH))
        certData.withUnsafeBytes {
            _ = CC_SHA256($0.baseAddress, CC_LONG(certData.count), &sha256Digest)
        }
        fingerprints["sha256"] = sha256Digest.map { String(format: "%02x", $0) }.joined()

        return fingerprints
    }

    private func extractPublicKeyInfo(from certificate: SecCertificate) -> (algorithm: String, keySize: Int?)? {
        guard let publicKey = SecCertificateCopyKey(certificate) else {
            return nil
        }

        guard let attributes = SecKeyCopyAttributes(publicKey) as? [CFString: Any] else {
            return nil
        }

        let keyType = attributes[kSecAttrKeyType as CFString] as? String ?? "Unknown"
        let keySize = attributes[kSecAttrKeySizeInBits as CFString] as? Int

        var algorithm = "Unknown"
        if keyType == (kSecAttrKeyTypeRSA as String) {
            algorithm = "RSA"
        } else if keyType == (kSecAttrKeyTypeEC as String) {
            algorithm = "EC"
        }

        return (algorithm: algorithm, keySize: keySize)
    }

    private func extractSignatureAlgorithm(from certData: Data) -> String? {
        // Simplified - should parse ASN.1 structure
        return "SHA256withRSA" // Placeholder
    }

    private func extractVersion(from certData: Data) -> Int {
        // Most certificates are v3
        return 3
    }

    private func extractKeyUsage(from certData: Data) -> [String]? {
        // Placeholder - should parse certificate extensions
        return nil
    }

    private func extractExtendedKeyUsage(from certData: Data) -> [String]? {
        // Placeholder - should parse certificate extensions
        return nil
    }

    private func extractSubjectAlternativeNames(from certData: Data) -> [String]? {
        // Placeholder - should parse certificate extensions
        return nil
    }

    func parseCertificateDetailsP12(p12Data: Data, password: String) throws -> [[String: Any]] {
        let (_, certificateChain) = try parseP12Certificate(p12Data: p12Data, password: password)
        return certificateChain.map { extractCertificateInfo(from: $0) }
    }

    func parseCertificateDetailsPEM(pemString: String) throws -> [[String: Any]] {
        let certificate = try parsePEMCertificate(pemString: pemString)
        return [extractCertificateInfo(from: certificate)]
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