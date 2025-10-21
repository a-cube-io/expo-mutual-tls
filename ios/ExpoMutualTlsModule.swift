// Copyright 2024-present Acube. All rights reserved.

import ExpoModulesCore
import Foundation
import Security
import Network
import CryptoKit

// MARK: - Main Module

public class ExpoMutualTlsModule: Module, @unchecked Sendable {
    private static let moduleName = "ExpoMutualTls"
    private static let logTag = "ExpoMutualTLS"
    
    // Thread-safe state management
    private let stateQueue = DispatchQueue(label: "com.expo.mutualtls.state", attributes: .concurrent)
    private var _isConfigured: Bool = false
    private var _currentConfig: MutualTlsConfig?
    private var _currentState: TlsState = .notConfigured
    
    // Core components
    private let keychainManager = KeychainManager.shared
    private let certificateParser = CertificateParser.shared
    internal let networkManager = NetworkManager()
    private lazy var sessionDelegate = ExpoMutualTlsURLSessionDelegate(module: self)
    
    // MARK: - Public Properties (Thread-Safe)
    
    public var isConfigured: Bool {
        return stateQueue.sync { _isConfigured }
    }
    
    public var currentState: TlsState {
        return stateQueue.sync { _currentState }
    }
    
    public var currentConfig: MutualTlsConfig? {
        return stateQueue.sync { _currentConfig }
    }
    
    // MARK: - Module Definition
    
    public func definition() -> ModuleDefinition {
        Name(Self.moduleName)
        
        // Module initialization
        OnCreate {
            // Set up logging for KeychainManager
            self.keychainManager.setLogger { [weak self] type, message in
                self?.emitDebugLog(type: type, message: message)
            }
        }
        
        // Configuration Management
        AsyncFunction("configure") { [weak self] (config: [String: Any]) in
            guard let self = self else { 
                return ConfigureResult.failure("Module deallocated").toDictionary()
            }
            
            do {
                let mutualTlsConfig = MutualTlsConfig(from: config)
                let result = try await self.configure(config: mutualTlsConfig)
                return result.toDictionary()
            } catch {
                self.handleError(error, context: "configure")
                return ConfigureResult.failure(error.localizedDescription).toDictionary()
            }
        }
        
        // Certificate Storage Management
        AsyncFunction("storeCertificate") { [weak self] (certificateData: [String: Any]) in
            guard let self = self else { return false }
            
            do {
                return try await self.storeCertificate(certificateData: certificateData)
            } catch {
                self.handleError(error, context: "storeCertificate")
                return false
            }
        }
        
        AsyncFunction("storeP12Certificate") { [weak self] (p12Base64: String, password: String) in
            guard let self = self else { return false }
            
            do {
                return try await self.storeP12Certificate(p12Base64: p12Base64, password: password)
            } catch {
                self.handleError(error, context: "storeP12Certificate")
                return false
            }
        }
        
        AsyncFunction("removeCertificate") { [weak self] in
            guard let self = self else { return }
            
            do {
                try await self.removeCertificate()
            } catch {
                self.handleError(error, context: "removeCertificate")
            }
        }
        
        AsyncFunction("hasCertificate") { [weak self] in
            return await self?.hasCertificate() ?? false
        }

        // Certificate Parsing
        AsyncFunction("parseCertificate") { [weak self] (certificateData: [String: Any]) in
            guard let self = self else {
                throw ExpoMutualTlsError.unknownError("Module deallocated")
            }

            do {
                let certificates = try self.parseCertificateInfo(certificateData: certificateData)
                return ["certificates": certificates]
            } catch {
                self.handleError(error, context: "parseCertificate")
                throw error
            }
        }

        // Network Operations
        AsyncFunction("makeRequest") { [weak self] (options: [String: Any]) in
            guard let self = self else {
                return MakeRequestResult.failure("Module deallocated").toDictionary()
            }
            
            do {
                let result = try await self.makeRequest(options: options)
                return result.toDictionary()
            } catch {
                self.handleError(error, context: "makeRequest")
                return MakeRequestResult.failure(error.localizedDescription).toDictionary()
            }
        }
        
        AsyncFunction("testConnection") { [weak self] (url: String) in
            guard let self = self else {
                return MakeRequestResult.failure("Module deallocated").toDictionary()
            }
            
            do {
                let result = try await self.testConnection(url: url)
                return result.toDictionary()
            } catch {
                self.handleError(error, context: "testConnection")
                return MakeRequestResult.failure(error.localizedDescription).toDictionary()
            }
        }
        
        
        // Properties exposed to JavaScript
        Property("isConfigured") { [weak self] in
            return self?.isConfigured ?? false
        }
        
        Property("currentState") { [weak self] in
            return self?.currentState.rawValue ?? TlsState.notConfigured.rawValue
        }
        
        // Events for debugging, error handling, and certificate expiry warnings
        Events("onDebugLog", "onError", "onCertificateExpiry")
    }
    
    // MARK: - Core Implementation Methods
    
    private func configure(config: MutualTlsConfig) async throws -> ConfigureResult {
        emitDebugLog(type: "configuration", message: "Starting configuration with format: \(config.certificateFormat.rawValue)")
        
        stateQueue.async(flags: .barrier) { [weak self] in
            self?._currentConfig = config
            self?._currentState = .notConfigured
        }
        
        // Check if certificate already exists in keychain
        let hasCert = await hasCertificate()
        
        if hasCert {
            do {
                try await initializeSSLContextFromKeychain()
                
                stateQueue.async(flags: .barrier) { [weak self] in
                    self?._isConfigured = true
                    self?._currentState = .configured
                }
                
                emitDebugLog(type: "configuration", message: "Configuration successful with existing certificate")
                return ConfigureResult(success: true, state: .configured, hasCertificate: true)
            } catch {
                emitDebugLog(type: "configuration", message: "Failed to initialize with existing certificate: \(error.localizedDescription)")
            }
        }
        
        // Configuration successful but no certificate yet
        stateQueue.async(flags: .barrier) { [weak self] in
            self?._currentState = .configured
        }
        
        emitDebugLog(type: "configuration", message: "Configuration completed - ready for certificate storage")
        return ConfigureResult(success: true, state: .configured, hasCertificate: hasCert)
    }
    
    private func storeCertificate(certificateData: [String: Any]) async throws -> Bool {
        guard let config = currentConfig else {
            throw ExpoMutualTlsError.notConfigured
        }
        
        switch config.certificateFormat {
        case .p12:
            guard let p12Data = certificateData["p12Data"] as? String,
                  let password = certificateData["password"] as? String else {
                throw ExpoMutualTlsError.missingRequiredField("P12 data and password required")
            }
            return try await storeP12Certificate(p12Base64: p12Data, password: password)
            
        case .pem:
            emitDebugLog(type: "store_certificate", message: "initializing PEM certificate storage")
            guard let certPem = certificateData["certificate"] as? String,
                  let keyPem = certificateData["privateKey"] as? String else {
                throw ExpoMutualTlsError.missingRequiredField("Certificate and private key required for PEM")
            }
            let passphrase = certificateData["passphrase"] as? String
            emitDebugLog(type: "store_certificate", message: "certificate: \(certPem) key: \(keyPem)")
            return try await storePEMCertificate(certificate: certPem, privateKey: keyPem, passphrase: passphrase)
        }
    }
    
    private func storeP12Certificate(p12Base64: String, password: String) async throws -> Bool {
        emitDebugLog(type: "certificate_storage", message: "Storing P12 certificate")
        
        guard let config = currentConfig else {
            throw ExpoMutualTlsError.notConfigured
        }
        
        // Decode base64 P12 data
        guard let p12Data = Data(base64Encoded: p12Base64) else {
            throw ExpoMutualTlsError.invalidCertificateFormat("Invalid P12 base64 data")
        }
        
        do {
            // Parse P12 certificate
            let (identity, certificateChain) = try certificateParser.parseP12Certificate(p12Data: p12Data, password: password)
            
            emitDebugLog(type: "certificate_storage", message: "P12 certificate parsed successfully")
            
            // Store P12 data in keychain
            let p12Service = config.keychainServiceForP12 ?? "client.p12"
            let passwordService = config.keychainServiceForPassword ?? "client.p12.password"
            
            try keychainManager.storeInKeychain(service: p12Service, data: p12Base64)
            try keychainManager.storeInKeychain(service: passwordService, data: password)
            
            emitDebugLog(type: "certificate_storage", message: "P12 certificate stored in keychain")
            
            // Initialize SSL context with the parsed identity
            try await initializeSSLContext(identity: identity, certificateChain: certificateChain)
            
            // Update configuration state
            stateQueue.async(flags: .barrier) { [weak self] in
                self?._isConfigured = true
                self?._currentState = .configured
            }
            
            emitDebugLog(type: "certificate_storage", message: "P12 certificate configuration completed")
            return true
            
        } catch {
            emitDebugLog(type: "certificate_storage", message: "P12 certificate storage failed: \(error.localizedDescription)")
            throw error
        }
    }
    
    private func storePEMCertificate(certificate: String, privateKey: String, passphrase: String?) async throws -> Bool {
        emitDebugLog(type: "certificate_storage", message: "Storing PEM certificate")

        guard let config = currentConfig else {
            emitErrorEvent(message: "Not configured")
            throw ExpoMutualTlsError.notConfigured
        }

        do {
            // Parse PEM certificate and private key
            let secCertificate = try certificateParser.parsePEMCertificate(pemString: certificate)
            let secPrivateKey = try certificateParser.parsePEMPrivateKey(pemString: privateKey)
            
            emitDebugLog(type: "certificate_storage", message: "PEM certificate and key parsed successfully")
            
            // Get keychain services from config
            let certService = config.keychainServiceForCertChain ?? "expo.mtls.client.cert"
            let keyService = config.keychainServiceForPrivateKey ?? "expo.mtls.client.key"
            
            emitDebugLog(type: "certificate_storage", message: "Storing PEM certificate with cert service: \(certService), key service: \(keyService)")
            
            // Store certificate and private key in keychain
            try keychainManager.storePEMCertificateAndKey(
                certService: certService,
                keyService: keyService,
                certificate: secCertificate,
                privateKey: secPrivateKey
            )
            
            emitDebugLog(type: "certificate_storage", message: "PEM certificate and key stored in keychain")
            
            // Initialize SSL context with the parsed certificate and key
            let identity = try keychainManager.retrievePEMIdentity(certService: certService, keyService: keyService)
            try await initializeSSLContext(identity: identity, certificateChain: [secCertificate])
            
            // Update configuration state
            stateQueue.async(flags: .barrier) { [weak self] in
                self?._isConfigured = true
                self?._currentState = .configured
            }
            
            emitDebugLog(type: "certificate_storage", message: "PEM certificate configuration completed")
            return true
            
        } catch {
            emitDebugLog(type: "certificate_storage", message: "PEM certificate storage failed: \(error.localizedDescription)")
            throw error
        }
    }
    
    private func removeCertificate() async throws {
        guard let config = currentConfig else {
            throw ExpoMutualTlsError.notConfigured
        }
        
        emitDebugLog(type: "certificate_removal", message: "Removing certificates from keychain")
        
        var servicesToRemove: [String] = []
        
        switch config.certificateFormat {
        case .p12:
            if let p12Service = config.keychainServiceForP12 {
                servicesToRemove.append(p12Service)
            }
            if let passwordService = config.keychainServiceForPassword {
                servicesToRemove.append(passwordService)
            }
            
            // Remove P12 certificate data from keychain
            for service in servicesToRemove {
                try keychainManager.removeFromKeychain(service: service)
            }
            
        case .pem:
            let certService = config.keychainServiceForCertChain ?? "expo.mtls.client.cert"
            let keyService = config.keychainServiceForPrivateKey ?? "expo.mtls.client.key"
            
            // Remove PEM certificate and key from keychain
            try keychainManager.removePEMCertificate(certService: certService, keyService: keyService)
        }
        
        // Clear SSL context and reset state
        networkManager.getSSLContextManager().invalidateSession()
        
        stateQueue.async(flags: .barrier) { [weak self] in
            self?._isConfigured = false
            self?._currentState = .configured
        }
        
        emitDebugLog(type: "certificate_removal", message: "Successfully removed certificates from keychain")
    }
    
    private func hasCertificate() async -> Bool {
        guard let config = currentConfig else {
            return false
        }

        switch config.certificateFormat {
        case .p12:
            let p12Service = config.keychainServiceForP12 ?? "client.p12"
            return keychainManager.keychainContainsItem(service: p12Service)

        case .pem:
            let certService = config.keychainServiceForCertChain ?? "expo.mtls.client.cert"
            let keyService = config.keychainServiceForPrivateKey ?? "expo.mtls.client.key"

            return keychainManager.hasPEMCertificate(certService: certService, keyService: keyService)
        }
    }

    private func parseCertificateInfo(certificateData: [String: Any]) throws -> [[String: Any]] {
        // Determine format from certificate data
        if let p12Data = certificateData["p12Data"] as? String,
           let password = certificateData["password"] as? String {
            // P12 format
            guard let p12Bytes = Data(base64Encoded: p12Data) else {
                throw ExpoMutualTlsError.invalidCertificateFormat("Invalid P12 base64 data")
            }
            return try certificateParser.parseCertificateDetailsP12(p12Data: p12Bytes, password: password)
        } else if let certPem = certificateData["certificate"] as? String {
            // PEM format
            return try certificateParser.parseCertificateDetailsPEM(pemString: certPem)
        } else {
            throw ExpoMutualTlsError.missingRequiredField("Either p12Data+password or certificate required")
        }
    }
    
    private func makeRequest(options: [String: Any]) async throws -> MakeRequestResult {
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
        let responseType = options["responseType"] as? String

        emitDebugLog(type: "request", message: "Starting mTLS request", method: method, url: url)

        do {
            let result = try await networkManager.executeRequest(url: url, method: method, headers: headers, body: bodyData, withMTLS: true, responseType: responseType)

            emitDebugLog(
                type: "request_completed",
                message: result.success ? "Request successful" : "Request failed",
                method: method,
                url: url,
                statusCode: result.statusCode
            )

            return result

        } catch {
            emitDebugLog(type: "request_error", message: "Request failed: \(error.localizedDescription)", method: method, url: url)
            throw error
        }
    }
    
    private func testConnection(url: String) async throws -> MakeRequestResult {
        emitDebugLog(type: "test_connection", message: "Testing connection with mTLS", url: url)
        
        guard isConfigured else {
            throw ExpoMutualTlsError.notConfigured
        }
        
        do {
            let result = try await networkManager.executeRequest(url: url, method: "HEAD", headers: [:], body: nil, withMTLS: true)
            
            emitDebugLog(
                type: "test_connection_completed",
                message: result.success ? "Connection test successful" : "Connection test failed",
                url: url,
                statusCode: result.statusCode
            )
            
            return result
            
        } catch {
            emitDebugLog(type: "test_connection_error", message: "Connection test failed: \(error.localizedDescription)", url: url)
            throw error
        }
    }
    
    
    // MARK: - Helper Methods
    
    private func initializeSSLContextFromKeychain() async throws {
        guard let config = currentConfig else {
            throw ExpoMutualTlsError.notConfigured
        }
        
        emitDebugLog(type: "ssl_initialization", message: "Initializing SSL context from keychain")
        
        do {
            let (identity, certificateChain) = try restoreIdentityFromKeychain(config: config)
            emitDebugLog(type: "ssl_initialization", message: "Identity restored from keychain successfully")
            try await initializeSSLContext(identity: identity, certificateChain: certificateChain)
        } catch {
            emitDebugLog(type: "ssl_initialization", message: "Failed to initialize SSL context from keychain: \(error.localizedDescription)")
            throw error
        }
    }
    
    private func restoreIdentityFromKeychain(config: MutualTlsConfig) throws -> (SecIdentity, [SecCertificate]) {
        switch config.certificateFormat {
        case .p12:
            let p12Service = config.keychainServiceForP12 ?? "client.p12"
            let passwordService = config.keychainServiceForPassword ?? "client.p12.password"
            
            guard let p12Base64 = keychainManager.retrieveFromKeychain(service: p12Service),
                  let password = keychainManager.retrieveFromKeychain(service: passwordService) else {
                throw ExpoMutualTlsError.certificateNotFound("P12 certificate or password not found in keychain")
            }
            
            guard let p12Data = Data(base64Encoded: p12Base64) else {
                throw ExpoMutualTlsError.invalidCertificateFormat("Invalid P12 data in keychain")
            }
            
            return try certificateParser.parseP12Certificate(p12Data: p12Data, password: password)
            
        case .pem:
            let certService = config.keychainServiceForCertChain ?? "expo.mtls.client.cert"
            let keyService = config.keychainServiceForPrivateKey ?? "expo.mtls.client.key"
            
            let identity = try keychainManager.retrievePEMIdentity(certService: certService, keyService: keyService)
            let certificate = try keychainManager.retrievePEMCertificate(certService: certService)
            
            return (identity, [certificate])
        }
    }
    
    private func initializeSSLContext(identity: SecIdentity, certificateChain: [SecCertificate]) async throws {
        emitDebugLog(type: "ssl_context", message: "Configuring SSL context for mTLS")
        
        do {
            // Initialize SSL context using the SSLContextManager
            try networkManager.getSSLContextManager().initializeSSLContext(identity: identity, certificateChain: certificateChain, delegate: sessionDelegate)
            
            emitDebugLog(type: "ssl_context", message: "SSL context configured successfully")
            
            // Extract certificate information for logging
            if let certificate = certificateChain.first {
                if let commonName = certificateParser.extractCommonName(from: certificate) {
                    emitDebugLog(type: "ssl_context", message: "Certificate common name: \(commonName)")
                }
            }
            
        } catch {
            emitDebugLog(type: "ssl_context", message: "Failed to configure SSL context: \(error.localizedDescription)")
            throw error
        }
    }
    
    // MARK: - Event Emission & Error Handling
    
    private func emitDebugLog(
        type: String,
        message: String? = nil,
        method: String? = nil,
        url: String? = nil,
        statusCode: Int? = nil,
        duration: TimeInterval? = nil
    ) {
        guard currentConfig?.enableLogging == true else { return }
        
        var eventData: [String: Any] = ["type": type]
        if let message = message { eventData["message"] = message }
        if let method = method { eventData["method"] = method }
        if let url = url { eventData["url"] = url }
        if let statusCode = statusCode { eventData["statusCode"] = statusCode }
        if let duration = duration { eventData["duration"] = Int(duration * 1000) }
        
        sendEvent("onDebugLog", eventData)
    }
    
    private func emitErrorEvent(message: String, code: String? = nil) {
        var eventData: [String: Any] = ["message": message]
        if let code = code { eventData["code"] = code }
        
        sendEvent("onError", eventData)
    }
    
    private func emitCertificateExpiryWarning(daysUntilExpiry: Int, certificateInfo: String) {
        let eventData: [String: Any] = [
            "daysUntilExpiry": daysUntilExpiry,
            "certificateInfo": certificateInfo,
            "timestamp": Date().timeIntervalSince1970
        ]
        
        sendEvent("onCertificateExpiry", eventData)
    }
    
    private func handleError(_ error: Error, context: String) {
        let expoError = error as? ExpoMutualTlsError ?? ExpoMutualTlsError.unknownError(error.localizedDescription)
        
        print("[\(Self.logTag)] Error in \(context): \(expoError.errorDescription ?? "Unknown")")
        emitErrorEvent(message: expoError.errorDescription ?? "Unknown error", code: expoError.code)
        
        // Update state on critical errors
        if case .sslHandshakeFailed = expoError {
            stateQueue.async(flags: .barrier) { [weak self] in
                self?._isConfigured = false
                self?._currentState = .error
            }
        }
    }
}

// MARK: - URLSessionDelegate Implementation

class ExpoMutualTlsURLSessionDelegate: NSObject, URLSessionDelegate, URLSessionTaskDelegate {
    weak var module: ExpoMutualTlsModule?
    
    init(module: ExpoMutualTlsModule) {
        self.module = module
        super.init()
    }
    
    public func urlSession(
        _ session: URLSession,
        didReceive challenge: URLAuthenticationChallenge,
        completionHandler: @escaping (URLSession.AuthChallengeDisposition, URLCredential?) -> Void
    ) {
        handleAuthenticationChallenge(challenge: challenge, completionHandler: completionHandler)
    }
    
    public func urlSession(
        _ session: URLSession,
        task: URLSessionTask,
        didReceive challenge: URLAuthenticationChallenge,
        completionHandler: @escaping (URLSession.AuthChallengeDisposition, URLCredential?) -> Void
    ) {
        handleAuthenticationChallenge(challenge: challenge, completionHandler: completionHandler)
    }
    
    private func handleAuthenticationChallenge(
        challenge: URLAuthenticationChallenge,
        completionHandler: @escaping (URLSession.AuthChallengeDisposition, URLCredential?) -> Void
    ) {
        
        // Handle client certificate challenge
        if challenge.protectionSpace.authenticationMethod == NSURLAuthenticationMethodClientCertificate {
            if let credential = module?.networkManager.getSSLContextManager().getSSLCredential() {
                completionHandler(.useCredential, credential)
                return
            }
        }
        
        // Handle server trust challenge
        if challenge.protectionSpace.authenticationMethod == NSURLAuthenticationMethodServerTrust {
            // For now, perform default handling
            completionHandler(.performDefaultHandling, nil)
            return
        }
        
        // Default handling for other authentication methods
        completionHandler(.performDefaultHandling, nil)
    }
    
    public func urlSession(_ session: URLSession, task: URLSessionTask, didCompleteWithError error: Error?) {
        if let error = error {
            print("[ExpoMutualTLS] Task completed with error: \(error.localizedDescription)")
        }
    }
}
