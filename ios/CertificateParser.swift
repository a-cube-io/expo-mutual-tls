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
}