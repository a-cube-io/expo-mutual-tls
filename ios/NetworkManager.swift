// Copyright 2024-present Acube. All rights reserved.

import Foundation

internal class NetworkManager {
    
    private let sslContextManager = SSLContextManager()
    
    func executeRequest(url: String, method: String, headers: [String: String], body: Data?, withMTLS: Bool) async throws -> MakeRequestResult {
        guard let requestURL = URL(string: url) else {
            throw ExpoMutualTlsError.invalidURL(url)
        }
        
        var request = URLRequest(url: requestURL)
        request.httpMethod = method
        request.httpBody = body
        
        // Add headers
        for (key, value) in headers {
            request.setValue(value, forHTTPHeaderField: key)
        }
        
        // Add default headers if not provided
        if request.value(forHTTPHeaderField: "User-Agent") == nil {
            request.setValue("ExpoMutualTLS/1.0", forHTTPHeaderField: "User-Agent")
        }
        
        let session: URLSession
        if withMTLS {
            guard let mTLSSession = sslContextManager.getURLSession() else {
                throw ExpoMutualTlsError.sslHandshakeFailed("SSL context not initialized")
            }
            session = mTLSSession
        } else {
            // Create simple session without mTLS
            let simpleConfig = URLSessionConfiguration.default
            simpleConfig.timeoutIntervalForRequest = 30.0
            session = URLSession(configuration: simpleConfig)
        }
        
        let startTime = CFAbsoluteTimeGetCurrent()
        
        do {
            let (data, response) = try await session.data(for: request)
            let duration = CFAbsoluteTimeGetCurrent() - startTime
            
            return processResponse(data: data, response: response, duration: duration, error: nil)
            
        } catch {
            let duration = CFAbsoluteTimeGetCurrent() - startTime
            throw ExpoMutualTlsError.networkRequestFailed("\(error.localizedDescription) (duration: \(Int(duration * 1000))ms)")
        }
    }
    
    private func processResponse(data: Data?, response: URLResponse?, duration: TimeInterval, error: Error?) -> MakeRequestResult {
        if let error = error {
            return MakeRequestResult.failure(error.localizedDescription)
        }
        
        guard let httpResponse = response as? HTTPURLResponse else {
            return MakeRequestResult.failure("Invalid response type")
        }
        
        let responseBody = data.map { String(data: $0, encoding: .utf8) ?? "" } ?? ""
        
        // Convert headers to expected format
        let headers = httpResponse.allHeaderFields.reduce(into: [String: [String]]()) { result, element in
            if let key = element.key as? String, let value = element.value as? String {
                result[key] = [value]
            }
        }
        
        let success = (200...299).contains(httpResponse.statusCode)
        
        return MakeRequestResult(
            success: success,
            statusCode: httpResponse.statusCode,
            statusMessage: HTTPURLResponse.localizedString(forStatusCode: httpResponse.statusCode),
            headers: headers,
            body: responseBody,
            tlsVersion: "TLS 1.2+",
            cipherSuite: "iOS Secure Transport"
        )
    }
    
    func getSSLContextManager() -> SSLContextManager {
        return sslContextManager
    }
}