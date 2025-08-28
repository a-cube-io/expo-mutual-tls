# Expo Mutual TLS Module - iOS Implementation Specifications

## Table of Contents
1. [Architecture Overview](#architecture-overview)
2. [Module Structure](#module-structure)
3. [Core Components](#core-components)
4. [Certificate Management](#certificate-management)
5. [SSL/TLS Configuration](#ssltls-configuration)
6. [Network Layer](#network-layer)
7. [Security Implementation](#security-implementation)
8. [Type System](#type-system)
9. [Error Handling](#error-handling)
10. [Event System](#event-system)
11. [Platform-Specific Considerations](#platform-specific-considerations)
12. [Dependencies](#dependencies)
13. [Implementation Checklist](#implementation-checklist)

## Architecture Overview

### Design Principles
- **Dual Certificate Format Support**: Both P12 (PKCS#12) and PEM certificates
- **Hardware-Backed Security**: iOS Keychain Services with Secure Enclave when available
- **Memory Safety**: Proper memory management for cryptographic operations
- **Thread Safety**: Concurrent operations with proper synchronization
- **Error Resilience**: Comprehensive error handling and recovery
- **Performance Optimization**: Efficient SSL context reuse and connection pooling

### System Architecture
```
┌─────────────────────────────────────────────────────────────┐
│                    React Native Layer                       │
├─────────────────────────────────────────────────────────────┤
│                  Expo Modules Core                          │
├─────────────────────────────────────────────────────────────┤
│                ExpoMutualTlsModule                          │
├─────────────────┬─────────────────┬─────────────────────────┤
│  Certificate    │   SSL Context   │    Network Layer        │
│   Management    │   Management    │                         │
├─────────────────┼─────────────────┼─────────────────────────┤
│  KeychainManager│ PEMCertParser   │   NSURLSession          │
│                 │                 │   (Custom Config)       │
├─────────────────┴─────────────────┴─────────────────────────┤
│              iOS Security Framework                         │
│           (Keychain Services, SecureTransport)              │
└─────────────────────────────────────────────────────────────┘
```

## Module Structure

### File Organization
```
ios/
├── ExpoMutualTlsModule.swift           # Main module implementation
├── ExpoMutualTlsModule.h               # Objective-C bridge (if needed)
├── KeychainManager.swift               # Keychain operations
├── PEMCertificateParser.swift          # PEM parsing utilities
├── SSLContextManager.swift             # SSL/TLS context management
├── NetworkManager.swift                # HTTP/HTTPS requests
├── Types/
│   ├── ExpoMutualTlsTypes.swift       # Type definitions
│   └── ExpoMutualTlsErrors.swift      # Error definitions
└── Extensions/
    ├── Data+Extensions.swift           # Data utilities
    └── URLSession+Extensions.swift     # Network extensions
```

### Module Declaration
```swift
import ExpoModulesCore
import Foundation
import Security
import Network

@objc(ExpoMutualTlsModule)
public class ExpoMutualTlsModule: Module {
    private static let moduleName = "ExpoMutualTls"
    private static let logTag = "ExpoMutualTLS"
    
    // Thread-safe state management
    private let stateQueue = DispatchQueue(label: "com.expo.mutualtls.state", attributes: .concurrent)
    private var _isConfigured: Bool = false
    private var _currentConfig: MutualTlsConfig?
    private var _sslContext: SSLContextRef?
    private var _urlSessionConfiguration: URLSessionConfiguration?
    
    // Lazy-initialized components
    private lazy var keychainManager = KeychainManager()
    private lazy var pemParser = PEMCertificateParser()
    private lazy var sslContextManager = SSLContextManager()
    private lazy var networkManager = NetworkManager()
}
```

## Core Components

### 1. ExpoMutualTlsModule (Main Module)

**Purpose**: Primary module interface, coordinates all operations

**Key Responsibilities**:
- Module lifecycle management
- Configuration handling
- State synchronization
- Event emission
- Error propagation

**Critical Implementation Points**:
```swift
public func definition() -> ModuleDefinition {
    Name(Self.moduleName)
    
    // Configuration
    AsyncFunction("configure") { [weak self] (config: MutualTlsConfig) -> ConfigureResult in
        try await self?.configure(config: config) ?? ConfigureResult(success: false, state: .error, hasCertificate: false)
    }
    
    // Certificate Management
    AsyncFunction("storeCertificate") { [weak self] (certificateData: [String: Any]) -> Bool in
        try await self?.storeCertificate(certificateData: certificateData) ?? false
    }
    
    AsyncFunction("removeCertificate") { [weak self] -> Void in
        try await self?.removeCertificate()
    }
    
    AsyncFunction("hasCertificate") { [weak self] -> Bool in
        await self?.hasCertificate() ?? false
    }
    
    // Network Operations
    AsyncFunction("makeRequest") { [weak self] (options: [String: Any]) -> MakeRequestResult in
        try await self?.makeRequest(options: options) ?? MakeRequestResult.failure()
    }
    
    AsyncFunction("testConnection") { [weak self] (url: String) -> MakeRequestResult in
        try await self?.testConnection(url: url) ?? MakeRequestResult.failure()
    }
    
    AsyncFunction("testSimpleRequest") { [weak self] (options: [String: Any]) -> MakeRequestResult in
        try await self?.testSimpleRequest(options: options) ?? MakeRequestResult.failure()
    }
    
    // Properties
    Property("isConfigured") { [weak self] in
        self?.isConfigured ?? false
    }
    
    Property("currentState") { [weak self] in
        self?.currentState.rawValue ?? TlsState.notConfigured.rawValue
    }
    
    // Events
    Events("onDebugLog", "onError", "onCertificateExpiry")
}
```

### 2. KeychainManager

**Purpose**: Secure certificate and key storage using iOS Keychain Services

**Key Features**:
- Hardware-backed encryption with Secure Enclave
- Biometric authentication support
- Backward compatibility with react-native-keychain API
- Memory-safe operations

**Implementation Structure**:
```swift
class KeychainManager {
    private static let keychainServicePrefix = "com.expo.mutualtls"
    private static let accessGroup: String? = nil // Configure per app requirements
    
    // Keychain Operations
    func setInternetCredentials(
        service: String,
        username: String,
        password: String,
        options: KeychainOptions = KeychainOptions()
    ) throws -> Bool
    
    func getInternetCredentials(service: String) throws -> KeychainCredentials?
    
    func resetInternetCredentials(service: String) throws -> Bool
    
    func hasInternetCredentials(service: String) -> Bool
    
    // Security Attributes
    private func buildKeychainQuery(
        service: String,
        options: KeychainOptions
    ) -> [String: Any]
    
    // Biometric Authentication
    private func configureBiometricAccess(
        query: inout [String: Any],
        options: KeychainOptions
    )
}
```

**Keychain Security Configuration**:
```swift
struct KeychainOptions {
    let requireUserAuthentication: Bool
    let authValiditySeconds: Int
    let accessControl: SecAccessControl?
    
    static let `default` = KeychainOptions(
        requireUserAuthentication: false,
        authValiditySeconds: -1,
        accessControl: nil
    )
}

// Security attributes mapping
private func securityAttributes(for options: KeychainOptions) -> [String: Any] {
    var attributes: [String: Any] = [
        kSecClass as String: kSecClassInternetPassword,
        kSecAttrAccessible as String: kSecAttrAccessibleWhenUnlockedThisDeviceOnly
    ]
    
    if options.requireUserAuthentication {
        if #available(iOS 11.3, *) {
            attributes[kSecAttrAccessControl as String] = createAccessControl(options: options)
        } else {
            attributes[kSecAttrAccessible as String] = kSecAttrAccessibleWhenPasscodeSetThisDeviceOnly
        }
    }
    
    return attributes
}
```

### 3. PEMCertificateParser

**Purpose**: Parse PEM format certificates and private keys

**Core Capabilities**:
- X.509 certificate parsing
- RSA/ECDSA private key parsing
- Encrypted private key support
- Certificate chain validation
- Key-certificate pair validation

**Implementation Structure**:
```swift
class PEMCertificateParser {
    private static let pemCertificateHeader = "-----BEGIN CERTIFICATE-----"
    private static let pemCertificateFooter = "-----END CERTIFICATE-----"
    private static let pemPrivateKeyHeaders = [
        "-----BEGIN PRIVATE KEY-----",
        "-----BEGIN RSA PRIVATE KEY-----", 
        "-----BEGIN EC PRIVATE KEY-----",
        "-----BEGIN ENCRYPTED PRIVATE KEY-----"
    ]
    
    // Certificate parsing
    func parseCertificates(from pemData: String) throws -> [SecCertificate]
    
    // Private key parsing  
    func parsePrivateKey(from pemData: String, passphrase: String?) throws -> SecKey
    
    // Combined parsing
    func parseCertificateAndKey(
        from pemData: String, 
        passphrase: String?
    ) throws -> (certificates: [SecCertificate], privateKey: SecKey)
    
    // Validation
    func validateKeyPairMatch(privateKey: SecKey, certificate: SecCertificate) throws -> Bool
    
    // Utility methods
    private func extractPEMBlocks(from content: String, type: PEMBlockType) -> [String]
    private func base64Decode(pemBlock: String) throws -> Data
    private func createSecCertificate(from data: Data) throws -> SecCertificate
    private func createSecKey(from data: Data, type: KeyType) throws -> SecKey
}

enum PEMBlockType {
    case certificate
    case privateKey
    case encryptedPrivateKey
}

enum KeyType {
    case rsa
    case ec
    case pkcs8
}
```

### 4. SSLContextManager

**Purpose**: Manage SSL/TLS context configuration for mutual TLS

**Key Responsibilities**:
- SSL context creation and configuration
- Certificate identity management
- Trust policy configuration
- Protocol version selection

**Implementation Structure**:
```swift
class SSLContextManager {
    private var currentIdentity: SecIdentity?
    private var certificateChain: [SecCertificate]?
    private var sslContext: SSLContextRef?
    
    // SSL Context Management
    func createSSLContext(
        identity: SecIdentity,
        certificateChain: [SecCertificate]
    ) throws -> URLSessionConfiguration
    
    func updateSSLContext(
        identity: SecIdentity,
        certificateChain: [SecCertificate]
    ) throws
    
    func clearSSLContext()
    
    // Identity Management
    func createIdentity(
        privateKey: SecKey,
        certificate: SecCertificate
    ) throws -> SecIdentity
    
    func createIdentityFromP12(
        p12Data: Data,
        password: String
    ) throws -> (identity: SecIdentity, certificateChain: [SecCertificate])
    
    func createIdentityFromPEM(
        certificates: [SecCertificate],
        privateKey: SecKey
    ) throws -> (identity: SecIdentity, certificateChain: [SecCertificate])
    
    // URLSession Configuration
    func configureURLSession() -> URLSessionConfiguration
    
    // Trust Policy
    private func configureTrustPolicy() -> SecTrust?
}
```

### 5. NetworkManager

**Purpose**: Execute HTTP/HTTPS requests with mTLS authentication

**Key Features**:
- URLSession-based implementation
- Automatic SSL context application
- Request/response logging
- Connection pooling
- Error handling and retry logic

**Implementation Structure**:
```swift
class NetworkManager: NSObject {
    private var urlSession: URLSession?
    private let operationQueue = OperationQueue()
    
    // Request Execution
    func executeRequest(
        url: String,
        method: String,
        headers: [String: String],
        body: Data?
    ) async throws -> MakeRequestResult
    
    func executeSimpleRequest(
        url: String,
        method: String, 
        headers: [String: String],
        body: Data?
    ) async throws -> MakeRequestResult
    
    // Session Management
    func configureSession(with configuration: URLSessionConfiguration)
    func invalidateSession()
    
    // Utility Methods
    private func buildURLRequest(
        url: String,
        method: String,
        headers: [String: String],
        body: Data?
    ) throws -> URLRequest
    
    private func processResponse(
        data: Data?,
        response: URLResponse?,
        error: Error?
    ) -> MakeRequestResult
}

// URLSessionDelegate for SSL handling
extension NetworkManager: URLSessionDelegate {
    func urlSession(
        _ session: URLSession,
        didReceive challenge: URLAuthenticationChallenge,
        completionHandler: @escaping (URLSession.AuthChallengeDisposition, URLCredential?) -> Void
    ) {
        // Handle server trust and client certificate challenges
    }
    
    func urlSession(
        _ session: URLSession,
        task: URLSessionTask,
        didReceive challenge: URLAuthenticationChallenge,
        completionHandler: @escaping (URLSession.AuthChallengeDisposition, URLCredential?) -> Void
    ) {
        // Handle per-task authentication challenges
    }
}
```

## Certificate Management

### P12 Certificate Support

**Data Flow**:
```
P12 Base64 String → Data → SecPKCS12Import → SecIdentity + Certificate Chain → Keychain Storage
```

**Implementation**:
```swift
private func storeP12Certificate(p12Base64: String, password: String) async throws {
    // 1. Decode base64 to Data
    guard let p12Data = Data(base64Encoded: p12Base64) else {
        throw ExpoMutualTlsError.invalidCertificateFormat("Invalid P12 base64 data")
    }
    
    // 2. Import P12 using Security framework
    let importOptions: [String: Any] = [
        kSecImportExportPassphrase as String: password
    ]
    
    var importResults: CFArray?
    let status = SecPKCS12Import(p12Data as CFData, importOptions as CFDictionary, &importResults)
    
    guard status == errSecSuccess,
          let results = importResults as? [[String: Any]],
          let firstResult = results.first else {
        throw ExpoMutualTlsError.certificateImportFailed("P12 import failed: \(status)")
    }
    
    // 3. Extract identity and certificate chain
    guard let identity = firstResult[kSecImportItemIdentity as String] as? SecIdentity else {
        throw ExpoMutualTlsError.certificateImportFailed("No identity found in P12")
    }
    
    let certificateChain = firstResult[kSecImportItemCertChain as String] as? [SecCertificate] ?? []
    
    // 4. Validate certificate
    try validateP12Certificate(identity: identity, certificateChain: certificateChain)
    
    // 5. Store in keychain
    let service = currentConfig?.keychainServiceForP12 ?? "client.p12"
    let passwordService = currentConfig?.keychainServiceForPassword ?? "client.p12.password"
    
    let keychainOptions = KeychainOptions(
        requireUserAuthentication: currentConfig?.requireUserAuthentication ?? false,
        authValiditySeconds: currentConfig?.userAuthValiditySeconds ?? -1
    )
    
    try keychainManager.setInternetCredentials(
        service: service,
        username: "p12",
        password: p12Base64,
        options: keychainOptions
    )
    
    try keychainManager.setInternetCredentials(
        service: passwordService,
        username: "password",
        password: password,
        options: keychainOptions
    )
    
    // 6. Initialize SSL context
    try await initializeSSLContext(identity: identity, certificateChain: certificateChain)
}
```

### PEM Certificate Support

**Data Flow**:
```
PEM Certificate String → [SecCertificate]
PEM Private Key String → SecKey  
→ SecIdentity → Keychain Storage
```

**Implementation**:
```swift
private func storePEMCertificate(certificateData: [String: Any]) async throws {
    guard let certPem = certificateData["certificate"] as? String,
          let keyPem = certificateData["privateKey"] as? String else {
        throw ExpoMutualTlsError.missingRequiredField("Certificate and private key required for PEM format")
    }
    
    let passphrase = certificateData["passphrase"] as? String
    
    // 1. Parse PEM data
    let certificates = try pemParser.parseCertificates(from: certPem)
    let privateKey = try pemParser.parsePrivateKey(from: keyPem, passphrase: passphrase)
    
    guard let clientCertificate = certificates.first else {
        throw ExpoMutualTlsError.invalidCertificateFormat("No certificates found in PEM")
    }
    
    // 2. Validate certificate and key match
    try pemParser.validateKeyPairMatch(privateKey: privateKey, certificate: clientCertificate)
    
    // 3. Create identity
    let identity = try sslContextManager.createIdentity(
        privateKey: privateKey,
        certificate: clientCertificate
    )
    
    // 4. Validate certificate chain
    try validatePEMCertificate(identity: identity, certificateChain: certificates)
    
    // 5. Store in keychain
    let certService = currentConfig?.keychainServiceForCertChain ?? "expo.mtls.client.cert"
    let keyService = currentConfig?.keychainServiceForPrivateKey ?? "expo.mtls.client.key"
    let passphraseService = "\(keyService).passphrase"
    
    let keychainOptions = KeychainOptions(
        requireUserAuthentication: currentConfig?.requireUserAuthentication ?? false,
        authValiditySeconds: currentConfig?.userAuthValiditySeconds ?? -1
    )
    
    try keychainManager.setInternetCredentials(
        service: certService,
        username: "certificate",
        password: certPem,
        options: keychainOptions
    )
    
    try keychainManager.setInternetCredentials(
        service: keyService,
        username: "privateKey", 
        password: keyPem,
        options: keychainOptions
    )
    
    if let passphrase = passphrase {
        try keychainManager.setInternetCredentials(
            service: passphraseService,
            username: "passphrase",
            password: passphrase,
            options: keychainOptions
        )
    }
    
    // 6. Initialize SSL context
    try await initializeSSLContext(identity: identity, certificateChain: certificates)
}
```

## SSL/TLS Configuration

### SSL Context Initialization

**Purpose**: Create properly configured URLSessionConfiguration for mTLS

**Key Implementation Points**:
```swift
private func initializeSSLContext(
    identity: SecIdentity,
    certificateChain: [SecCertificate]
) async throws {
    // 1. Create URLSessionConfiguration
    let configuration = URLSessionConfiguration.default
    
    // 2. Configure client certificate
    let credential = URLCredential(
        identity: identity,
        certificates: certificateChain,
        persistence: .forSession
    )
    
    // 3. Set up custom URL protocol if needed
    configuration.protocolClasses = [CustomHTTPSProtocol.self]
    
    // 4. Configure timeouts
    configuration.timeoutIntervalForRequest = 30.0
    configuration.timeoutIntervalForResource = 60.0
    
    // 5. Store configuration
    await stateQueue.async(flags: .barrier) { [weak self] in
        self?._urlSessionConfiguration = configuration
        self?._isConfigured = true
    }
    
    // 6. Update network manager
    networkManager.configureSession(with: configuration)
    
    // 7. Log success
    emitDebugLog(type: "ssl_context", message: "SSL context initialized successfully")
}
```

### Custom URLProtocol for mTLS (Alternative Approach)

```swift
class CustomHTTPSProtocol: URLProtocol {
    private var session: URLSession?
    private var sessionTask: URLSessionDataTask?
    
    override class func canInit(with request: URLRequest) -> Bool {
        return request.url?.scheme?.lowercased() == "https"
    }
    
    override class func canonicalRequest(for request: URLRequest) -> URLRequest {
        return request
    }
    
    override func startLoading() {
        guard let configuration = ExpoMutualTlsModule.shared?.urlSessionConfiguration else {
            client?.urlProtocol(self, didFailWithError: ExpoMutualTlsError.notConfigured)
            return
        }
        
        session = URLSession(
            configuration: configuration,
            delegate: self,
            delegateQueue: nil
        )
        
        sessionTask = session?.dataTask(with: request) { [weak self] data, response, error in
            // Handle response
        }
        
        sessionTask?.resume()
    }
    
    override func stopLoading() {
        sessionTask?.cancel()
        session?.invalidateAndCancel()
    }
}

// URLSessionDelegate implementation for certificate handling
extension CustomHTTPSProtocol: URLSessionDelegate, URLSessionTaskDelegate {
    func urlSession(
        _ session: URLSession,
        task: URLSessionTask,
        didReceive challenge: URLAuthenticationChallenge,
        completionHandler: @escaping (URLSession.AuthChallengeDisposition, URLCredential?) -> Void
    ) {
        // Handle client certificate challenge
        if challenge.protectionSpace.authenticationMethod == NSURLAuthenticationMethodClientCertificate {
            if let identity = ExpoMutualTlsModule.shared?.currentIdentity {
                let credential = URLCredential(
                    identity: identity,
                    certificates: ExpoMutualTlsModule.shared?.certificateChain,
                    persistence: .forSession
                )
                completionHandler(.useCredential, credential)
                return
            }
        }
        
        // Handle server trust challenge
        if challenge.protectionSpace.authenticationMethod == NSURLAuthenticationMethodServerTrust {
            completionHandler(.performDefaultHandling, nil)
            return
        }
        
        completionHandler(.performDefaultHandling, nil)
    }
}
```

## Network Layer

### HTTP Request Implementation

**Key Features**:
- Support for all HTTP methods (GET, POST, PUT, PATCH, DELETE, etc.)
- Custom headers handling
- Request body support
- Response processing with detailed metadata
- TLS information extraction

```swift
func makeRequest(options: [String: Any]) async throws -> MakeRequestResult {
    guard isConfigured else {
        throw ExpoMutualTlsError.notConfigured
    }
    
    guard let url = options["url"] as? String else {
        throw ExpoMutualTlsError.missingRequiredField("URL is required")
    }
    
    let method = options["method"] as? String ?? "GET"
    let headers = options["headers"] as? [String: String] ?? [:]
    let bodyString = options["body"] as? String
    let bodyData = bodyString?.data(using: .utf8)
    
    // Execute request with mTLS configuration
    return try await networkManager.executeRequest(
        url: url,
        method: method,
        headers: headers,
        body: bodyData
    )
}

func testSimpleRequest(options: [String: Any]) async throws -> MakeRequestResult {
    // Execute request without mTLS (for testing network connectivity)
    guard let url = options["url"] as? String else {
        throw ExpoMutualTlsError.missingRequiredField("URL is required")
    }
    
    let method = options["method"] as? String ?? "GET"
    let headers = options["headers"] as? [String: String] ?? [:]
    let bodyString = options["body"] as? String
    let bodyData = bodyString?.data(using: .utf8)
    
    return try await networkManager.executeSimpleRequest(
        url: url,
        method: method,
        headers: headers,
        body: bodyData
    )
}
```

### Response Processing

```swift
private func processResponse(
    data: Data?,
    response: URLResponse?,
    error: Error?
) -> MakeRequestResult {
    if let error = error {
        emitDebugLog(type: "request_error", message: error.localizedDescription)
        return MakeRequestResult(
            success: false,
            statusCode: 0,
            statusMessage: error.localizedDescription,
            headers: [:],
            body: "",
            tlsVersion: "unknown",
            cipherSuite: "unknown"
        )
    }
    
    guard let httpResponse = response as? HTTPURLResponse else {
        return MakeRequestResult.failure()
    }
    
    let responseBody = data.map { String(data: $0, encoding: .utf8) ?? "" } ?? ""
    
    // Extract TLS information if available
    var tlsVersion = "unknown"
    var cipherSuite = "unknown"
    
    if let connectionInfo = response?.value(forHTTPHeaderField: "Connection-Info") {
        // Parse TLS information from connection info or other sources
        // iOS doesn't provide direct access to TLS info like Android
        tlsVersion = extractTLSVersion(from: connectionInfo)
        cipherSuite = extractCipherSuite(from: connectionInfo)
    }
    
    emitDebugLog(
        type: "request_success",
        message: "Request completed",
        statusCode: httpResponse.statusCode,
        duration: nil
    )
    
    return MakeRequestResult(
        success: true,
        statusCode: httpResponse.statusCode,
        statusMessage: HTTPURLResponse.localizedString(forStatusCode: httpResponse.statusCode),
        headers: httpResponse.allHeaderFields as? [String: [String]] ?? [:],
        body: responseBody,
        tlsVersion: tlsVersion,
        cipherSuite: cipherSuite
    )
}
```

## Security Implementation

### Keychain Security Best Practices

1. **Access Control**:
```swift
private func createAccessControl(options: KeychainOptions) -> SecAccessControl? {
    var error: Unmanaged<CFError>?
    
    var flags: SecAccessControlCreateFlags = []
    
    if options.requireUserAuthentication {
        flags.insert(.userPresence)
        
        if #available(iOS 11.3, *), options.authValiditySeconds > 0 {
            flags.insert(.applicationPassword)
        }
    }
    
    let accessControl = SecAccessControlCreateWithFlags(
        kCFAllocatorDefault,
        kSecAttrAccessibleWhenUnlockedThisDeviceOnly,
        flags,
        &error
    )
    
    if let error = error?.takeRetainedValue() {
        print("Failed to create access control: \(error)")
        return nil
    }
    
    return accessControl
}
```

2. **Secure Memory Handling**:
```swift
extension Data {
    /// Zero out data content securely
    mutating func secureZero() {
        withUnsafeMutableBytes { bytes in
            memset_s(bytes.baseAddress, bytes.count, 0, bytes.count)
        }
    }
}

extension String {
    /// Create string from data and zero out source data
    init(securingDataUTF8 data: inout Data) {
        self.init(data: data, encoding: .utf8) ?? ""
        data.secureZero()
    }
}
```

3. **Certificate Validation**:
```swift
private func validateCertificate(
    identity: SecIdentity,
    certificateChain: [SecCertificate]
) throws {
    // Extract certificate from identity
    var certificate: SecCertificate?
    let status = SecIdentityCopyCertificate(identity, &certificate)
    
    guard status == errSecSuccess, let cert = certificate else {
        throw ExpoMutualTlsError.certificateValidationFailed("Failed to extract certificate from identity")
    }
    
    // Check certificate validity period
    guard let notBefore = SecCertificateNotValidBefore(cert),
          let notAfter = SecCertificateNotValidAfter(cert) else {
        throw ExpoMutualTlsError.certificateValidationFailed("Cannot read certificate validity period")
    }
    
    let now = CFAbsoluteTimeGetCurrent()
    guard now >= notBefore && now <= notAfter else {
        throw ExpoMutualTlsError.certificateValidationFailed("Certificate is not valid at current time")
    }
    
    // Check for client authentication extended key usage
    let clientAuthOID = "1.3.6.1.5.5.7.3.2"
    guard certificateHasExtendedKeyUsage(cert, oid: clientAuthOID) else {
        throw ExpoMutualTlsError.certificateValidationFailed("Certificate lacks client authentication usage")
    }
    
    // Emit certificate expiry warning if needed
    let warningThreshold = TimeInterval((currentConfig?.expiryWarningDays ?? 30) * 24 * 60 * 60)
    if notAfter - now <= warningThreshold {
        emitCertificateExpiryWarning(certificate: cert, expiry: notAfter)
    }
}
```

## Type System

### Core Types Mapping

**Swift Type Definitions**:
```swift
// Enums
enum CertificateFormat: String, CaseIterable {
    case p12 = "p12"
    case pem = "pem"
}

enum TlsState: String, CaseIterable {
    case notConfigured = "notConfigured"
    case configured = "configured"
    case error = "error"
}

// Configuration Types
struct MutualTlsConfig {
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
    
    init(from dictionary: [String: Any]) {
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

// Result Types
struct ConfigureResult {
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
}

struct MakeRequestResult {
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
    
    static func failure(message: String = "Request failed") -> MakeRequestResult {
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

// Event Types
struct DebugLogEvent {
    let type: String
    let message: String?
    let method: String?
    let url: String?
    let statusCode: Int?
    let duration: TimeInterval?
    
    func toDictionary() -> [String: Any] {
        var dict: [String: Any] = ["type": type]
        if let message = message { dict["message"] = message }
        if let method = method { dict["method"] = method }
        if let url = url { dict["url"] = url }
        if let statusCode = statusCode { dict["statusCode"] = statusCode }
        if let duration = duration { dict["duration"] = Int(duration * 1000) } // ms
        return dict
    }
}

struct ErrorEvent {
    let message: String
    let code: String?
    
    func toDictionary() -> [String: Any] {
        var dict: [String: Any] = ["message": message]
        if let code = code { dict["code"] = code }
        return dict
    }
}

struct CertificateExpiryEvent {
    let alias: String?
    let subject: String
    let expiry: TimeInterval
    let warning: Bool
    
    func toDictionary() -> [String: Any] {
        var dict: [String: Any] = [
            "subject": subject,
            "expiry": Int(expiry * 1000), // Convert to milliseconds
            "warning": warning
        ]
        if let alias = alias { dict["alias"] = alias }
        return dict
    }
}
```

### Type Bridge Extensions

```swift
// Expo Modules Core bridge extensions
extension CertificateFormat: Enumerable {}
extension TlsState: Enumerable {}

extension MutualTlsConfig: Record {
    static func definition() -> RecordDefinition {
        return RecordDefinition {
            Field("certificateFormat") { CertificateFormat.p12 }
            Field("keychainService") { "expo.mtls.client" }
            Field("keychainServiceForP12") { "client.p12" }
            Field("keychainServiceForPassword") { "client.p12.password" }
            Field("keychainServiceForPrivateKey") { "expo.mtls.client.key" }
            Field("keychainServiceForCertChain") { "expo.mtls.client.cert" }
            Field("enableLogging") { false }
            Field("requireUserAuthentication") { false }
            Field("userAuthValiditySeconds") { 120 }
            Field("expiryWarningDays") { 30 }
        }
    }
}
```

## Error Handling

### Error Hierarchy

```swift
enum ExpoMutualTlsError: Error, LocalizedError {
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
    
    var errorDescription: String? {
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
            return "Keychain access denied - check permissions"
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
        }
    }
    
    var errorCode: String {
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
        }
    }
}

// Expo Modules Core error bridge
extension ExpoMutualTlsError: ExceptionType {
    var code: String { return errorCode }
    var debugDescription: String { return errorDescription ?? "Unknown error" }
}
```

### Error Handling Patterns

```swift
// Centralized error handling
private func handleError(_ error: Error, context: String) {
    let expoError = error as? ExpoMutualTlsError ?? ExpoMutualTlsError.networkRequestFailed(error.localizedDescription)
    
    // Log error
    print("[\(Self.logTag)] Error in \(context): \(expoError.errorDescription ?? "Unknown")")
    
    // Emit error event
    emitErrorEvent(message: expoError.errorDescription ?? "Unknown error", code: expoError.errorCode)
    
    // Update state if needed
    if case .sslHandshakeFailed = expoError {
        stateQueue.async(flags: .barrier) { [weak self] in
            self?._isConfigured = false
        }
    }
}

// Async error handling wrapper
private func asyncErrorHandler<T>(_ operation: () async throws -> T) async -> T? {
    do {
        return try await operation()
    } catch {
        handleError(error, context: "async operation")
        return nil
    }
}
```

## Event System

### Event Emission

```swift
// Debug logging events
private func emitDebugLog(
    type: String,
    message: String? = nil,
    method: String? = nil,
    url: String? = nil,
    statusCode: Int? = nil,
    duration: TimeInterval? = nil
) {
    guard currentConfig?.enableLogging == true else { return }
    
    let event = DebugLogEvent(
        type: type,
        message: message,
        method: method,
        url: url,
        statusCode: statusCode,
        duration: duration
    )
    
    sendEvent("onDebugLog", event.toDictionary())
}

// Error events
private func emitErrorEvent(message: String, code: String? = nil) {
    let event = ErrorEvent(message: message, code: code)
    sendEvent("onError", event.toDictionary())
}

// Certificate expiry warnings
private func emitCertificateExpiryWarning(certificate: SecCertificate, expiry: CFAbsoluteTime) {
    let subject = extractCertificateSubject(certificate) ?? "Unknown"
    let event = CertificateExpiryEvent(
        alias: nil,
        subject: subject,
        expiry: expiry,
        warning: true
    )
    sendEvent("onCertificateExpiry", event.toDictionary())
}

// Certificate information extraction
private func extractCertificateSubject(_ certificate: SecCertificate) -> String? {
    var commonName: CFString?
    let status = SecCertificateCopyCommonName(certificate, &commonName)
    
    guard status == errSecSuccess, let name = commonName else {
        return nil
    }
    
    return name as String
}
```

## Platform-Specific Considerations

### iOS Security Framework Integration

1. **Keychain Services**:
   - Use `kSecAttrAccessibleWhenUnlockedThisDeviceOnly` for enhanced security
   - Support Secure Enclave when available (iPhone 5s+)
   - Handle keychain access control flags properly

2. **Certificate Handling**:
   - iOS uses `SecCertificate` and `SecIdentity` types
   - P12 import via `SecPKCS12Import`
   - Certificate validation via `SecTrust` APIs

3. **Network Security**:
   - App Transport Security (ATS) considerations
   - Custom certificate validation
   - Network.framework integration for advanced networking

4. **Memory Management**:
   - Proper cleanup of Security framework objects
   - Zero out sensitive data
   - Handle Core Foundation memory management

### iOS Version Compatibility

```swift
// Version-specific implementations
@available(iOS 13.0, *)
private func modernNetworkConfiguration() {
    // Use Network.framework for advanced features
}

@available(iOS 11.3, *)
private func biometricAccessControl() -> SecAccessControl? {
    // Use advanced biometric controls
    return SecAccessControlCreateWithFlags(
        kCFAllocatorDefault,
        kSecAttrAccessibleWhenUnlockedThisDeviceOnly,
        [.userPresence, .applicationPassword],
        nil
    )
}

// Fallback implementations
private func legacyAccessControl() -> [String: Any] {
    return [
        kSecAttrAccessible as String: kSecAttrAccessibleWhenPasscodeSetThisDeviceOnly
    ]
}
```

## Dependencies

### Required iOS Frameworks

```swift
import ExpoModulesCore      // Expo Modules framework
import Foundation           // Core Foundation types
import Security             // Keychain Services, certificates
import Network              // Advanced networking (iOS 12+)
import CryptoKit           // Modern cryptography (iOS 13+)
import CommonCrypto        // Legacy crypto support
import SystemConfiguration // Network reachability
```

### Package Dependencies

```json
// package.json dependencies for iOS
{
  "dependencies": {
    "expo": "^50.0.0",
    "expo-modules-core": "^1.11.0"
  },
  "peerDependencies": {
    "react": "*",
    "react-native": "*"
  }
}
```

### iOS Project Configuration

```xml
<!-- ios/ExpoMutualTls/Info.plist -->
<key>NSAppTransportSecurity</key>
<dict>
    <key>NSAllowsArbitraryLoads</key>
    <false/>
    <key>NSAllowsArbitraryLoadsInWebContent</key>
    <false/>
    <key>NSExceptionDomains</key>
    <dict>
        <!-- Add specific domains if needed -->
    </dict>
</dict>

<!-- Keychain access -->
<key>keychain-access-groups</key>
<array>
    <string>$(AppIdentifierPrefix)com.yourapp.keychain</string>
</array>
```

## Implementation Checklist

### Phase 1: Core Infrastructure ✓
- [ ] Create Expo module structure
- [ ] Implement basic module definition
- [ ] Set up error handling system
- [ ] Create type definitions
- [ ] Implement thread-safe state management

### Phase 2: Keychain Integration ✓
- [ ] Implement KeychainManager class
- [ ] Add secure storage operations
- [ ] Support biometric authentication
- [ ] Handle keychain access control
- [ ] Test keychain operations

### Phase 3: Certificate Management ✓
- [ ] Implement P12 certificate support
- [ ] Create PEM parser for certificates
- [ ] Add certificate validation
- [ ] Implement identity creation
- [ ] Test certificate operations

### Phase 4: SSL Context Management ✓  
- [ ] Create SSL context manager
- [ ] Implement URLSessionConfiguration
- [ ] Add client certificate handling
- [ ] Support certificate chain validation
- [ ] Test SSL context creation

### Phase 5: Network Layer ✓
- [ ] Implement NetworkManager class
- [ ] Add HTTP request support
- [ ] Handle authentication challenges
- [ ] Process responses with TLS info
- [ ] Test network operations

### Phase 6: Event System ✓
- [ ] Implement debug logging
- [ ] Add error event emission
- [ ] Create certificate expiry warnings
- [ ] Test event communication
- [ ] Verify React Native bridge

### Phase 7: Integration Testing ✓
- [ ] Test P12 certificate workflow
- [ ] Test PEM certificate workflow  
- [ ] Verify mTLS connections
- [ ] Test error scenarios
- [ ] Performance testing

### Phase 8: Documentation & Polish ✓
- [ ] Complete API documentation
- [ ] Add usage examples
- [ ] Create troubleshooting guide
- [ ] Code review and optimization
- [ ] Release preparation

## Notes for iOS Implementation

### Key Differences from Android

1. **Certificate Storage**: iOS Keychain vs Android Keystore
2. **SSL Context**: URLSessionConfiguration vs OkHttpClient
3. **Certificate Parsing**: Security framework vs BouncyCastle
4. **Threading**: DispatchQueue vs Kotlin Coroutines
5. **Memory Management**: ARC vs GC

### Critical Implementation Points

1. **Memory Safety**: Always zero out sensitive data
2. **Thread Safety**: Use concurrent queues with barriers
3. **Error Handling**: Provide detailed, actionable error messages
4. **Performance**: Reuse SSL contexts and connection pools
5. **Security**: Follow Apple's security guidelines

### Testing Strategy

1. **Unit Tests**: Individual component functionality
2. **Integration Tests**: End-to-end certificate workflows
3. **Security Tests**: Certificate validation and keychain security
4. **Performance Tests**: Network request performance
5. **Compatibility Tests**: iOS version compatibility

This comprehensive specification provides all the technical details needed to implement the iOS version of the Expo Mutual TLS module, ensuring feature parity with the Android implementation while following iOS-specific best practices and security guidelines.