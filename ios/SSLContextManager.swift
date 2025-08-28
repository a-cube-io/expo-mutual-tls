// Copyright 2024-present Acube. All rights reserved.

import Foundation
import Security

internal class SSLContextManager {
    
    private var urlSession: URLSession?
    private var sslCredential: URLCredential?
    
    func initializeSSLContext(identity: SecIdentity, certificateChain: [SecCertificate], delegate: URLSessionDelegate?) throws {
        // Create URL session configuration
        let configuration = URLSessionConfiguration.default
        configuration.timeoutIntervalForRequest = 30.0
        configuration.timeoutIntervalForResource = 60.0
        configuration.requestCachePolicy = .reloadIgnoringLocalCacheData
        
        // Create URL credential with client certificate
        let credential = URLCredential(
            identity: identity,
            certificates: certificateChain,
            persistence: .forSession
        )
        
        // Store credential and create session
        self.sslCredential = credential
        self.urlSession = URLSession(configuration: configuration, delegate: delegate, delegateQueue: nil)
    }
    
    func getURLSession() -> URLSession? {
        return urlSession
    }
    
    func getSSLCredential() -> URLCredential? {
        return sslCredential
    }
    
    func invalidateSession() {
        urlSession?.invalidateAndCancel()
        urlSession = nil
        sslCredential = nil
    }
}