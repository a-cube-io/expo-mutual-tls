# expo-mutual-tls

🔒 **Production-ready Mutual TLS (mTLS) client certificate authentication for Expo/React Native applications**

[![Platform - iOS](https://img.shields.io/badge/Platform-iOS-blue?logo=apple&logoColor=white)](https://developer.apple.com/ios/)
[![Platform - Android](https://img.shields.io/badge/Platform-Android-green?logo=android&logoColor=white)](https://developer.android.com/)
[![React Native](https://img.shields.io/badge/React_Native-blue?logo=react&logoColor=white)](https://reactnative.dev/)
[![Expo](https://img.shields.io/badge/Expo-black?logo=expo&logoColor=white)](https://expo.dev/)

## Overview

This Expo module provides secure, hardware-backed mTLS client certificate authentication for mobile applications. It supports both **P12 (PKCS#12)** and **PEM** certificate formats with enterprise-grade security features.

### Key Features

- 🔐 **Hardware-backed Security**: iOS Keychain & Android Keystore integration
- 📱 **Cross-platform**: Native iOS (Swift) and Android (Kotlin) implementations
- 🎯 **Simple API**: Easy-to-use utility functions for common operations
- 📋 **Multiple Formats**: Support for P12/PKCS#12 and PEM certificate formats
- 🔒 **Biometric Auth**: Optional biometric/device credential requirements
- 📊 **Rich Events**: Debug logging, error handling, and certificate expiry warnings
- ⚡ **Performance**: Optimized for production workloads
- 🛡️ **Enterprise Ready**: Comprehensive certificate validation and security

## Quick Start

### Installation

```bash
npx expo install expo-mutual-tls
```

### Basic Usage

```typescript
import ExpoMutualTls from 'expo-mutual-tls';

// Configure for P12 certificates
await ExpoMutualTls.configureP12('my-keychain-service', true);

// Store P12 certificate
await ExpoMutualTls.storeP12(p12Base64Data, 'certificate-password');

// Make authenticated mTLS request
const response = await ExpoMutualTls.request('https://api.example.com/secure', {
  method: 'POST',
  headers: { 'Content-Type': 'application/json' },
  body: JSON.stringify({ data: 'example' })
});
```

## API Reference

### Configuration Methods

#### `configureP12(keychainService?, enableLogging?)`

Configure the module for P12/PKCS#12 certificate format.

```typescript
const result = await ExpoMutualTls.configureP12(
  'my-p12-service',  // Optional: keychain service name (default: 'client.p12')
  true               // Optional: enable debug logging (default: false)
);
```

#### `configurePEM(certService?, keyService?, enableLogging?)`

Configure the module for PEM certificate format.

```typescript
const result = await ExpoMutualTls.configurePEM(
  'cert-service',    // Optional: certificate service name
  'key-service',     // Optional: private key service name  
  true               // Optional: enable debug logging
);
```

### Certificate Management

#### `storeP12(p12Base64, password)`

Store a P12/PKCS#12 certificate in secure storage.

```typescript
await ExpoMutualTls.storeP12(
  'MIIKXgIBAzCCCh...',  // Base64-encoded P12 data
  'my-certificate-password'
);
```

#### `storePEM(certificate, privateKey, passphrase?)`

Store PEM certificate and private key in secure storage.

```typescript
await ExpoMutualTls.storePEM(
  '-----BEGIN CERTIFICATE-----\n...',  // PEM certificate
  '-----BEGIN PRIVATE KEY-----\n...',   // PEM private key
  'optional-passphrase'                 // Optional: passphrase for encrypted key
);
```

#### `hasCertificate()`

Check if certificates are stored.

```typescript
const hasStoredCert = await ExpoMutualTls.hasCertificate();
```

#### `removeCertificate()`

Remove stored certificates from secure storage.

```typescript
await ExpoMutualTls.removeCertificate();
```

### Network Operations

#### `request(url, options?)`

Make an authenticated mTLS request.

```typescript
const result = await ExpoMutualTls.request('https://api.example.com', {
  method: 'POST',
  headers: { 'Authorization': 'Bearer token' },
  body: JSON.stringify({ key: 'value' })
});

console.log('Status:', result.statusCode);
console.log('TLS Version:', result.tlsVersion);
console.log('Response:', result.body);
```

#### `testConnection(url)`

Test mTLS connection to a URL (HEAD request).

```typescript
const result = await ExpoMutualTls.testConnection('https://secure-api.example.com');
```

### State Management

#### `isConfigured` (getter)

Check if the module is configured.

```typescript
if (ExpoMutualTls.isConfigured) {
  // Module is ready for certificate operations
}
```

#### `currentState` (getter)

Get the current module state.

```typescript
console.log('Current state:', ExpoMutualTls.currentState);
// Possible values: 'notConfigured', 'configured', 'error'
```

### Event Handling

The module provides comprehensive event utilities for monitoring mTLS operations, debugging, and certificate lifecycle management.

#### `onDebugLog(callback)`

Listen for debug log events including network requests, certificate operations, and system information.

```typescript
const debugSubscription = ExpoMutualTls.onDebugLog(event => {
  console.log(`[${event.type}] ${event.message}`);
  
  // Access additional event data
  if (event.method) console.log('HTTP Method:', event.method);
  if (event.url) console.log('Request URL:', event.url);
  if (event.statusCode) console.log('Status Code:', event.statusCode);
  if (event.duration) console.log('Duration:', event.duration + 'ms');
});

// Remember to remove the listener when done
debugSubscription.remove();
```

**Event Types:**
- `certificate_storage` - Certificate store/retrieve operations
- `network_request` - HTTP/HTTPS requests
- `keychain_operation` - Keychain access operations
- `tls_handshake` - TLS/SSL handshake information

#### `onError(callback)`

Listen for error events from all module operations.

```typescript
const errorSubscription = ExpoMutualTls.onError(event => {
  console.error('mTLS Error:', event.message);
  
  // Handle specific error codes
  if (event.code) {
    switch (event.code) {
      case 'CERTIFICATE_NOT_FOUND':
        console.log('Action: Store a certificate first');
        break;
      case 'SSL_HANDSHAKE_FAILED':
        console.log('Action: Check certificate validity');
        break;
      case 'KEYCHAIN_ACCESS_DENIED':
        console.log('Action: Check app permissions');
        break;
      default:
        console.error('Error Code:', event.code);
    }
  }
});

// Remove listener when done
errorSubscription.remove();
```

#### `onCertificateExpiry(callback)`

Listen for certificate expiry warnings and notifications.

```typescript
const expirySubscription = ExpoMutualTls.onCertificateExpiry(event => {
  const expiryDate = new Date(event.expiry);
  
  console.warn('Certificate Expiry Warning:');
  console.warn('Subject:', event.subject);
  console.warn('Expires:', expiryDate.toLocaleDateString());
  
  if (event.alias) {
    console.warn('Alias:', event.alias);
  }
  
  if (event.warning) {
    console.warn('⚠️ Certificate expires soon!');
  }
  
  // Calculate days until expiry
  const daysUntilExpiry = Math.ceil((event.expiry - Date.now()) / (1000 * 60 * 60 * 24));
  console.warn(`Days until expiry: ${daysUntilExpiry}`);
});

// Remove listener when done  
expirySubscription.remove();
```

#### `removeAllListeners()`

Remove all active event listeners at once.

```typescript
// Remove all event listeners
ExpoMutualTls.removeAllListeners();
```

### Complete Event Handling Example

```typescript
import { useEffect } from 'react';
import ExpoMutualTls from 'expo-mutual-tls';

export default function MyComponent() {
  useEffect(() => {
    // Set up all event listeners
    const debugSubscription = ExpoMutualTls.onDebugLog((event) => {
      const message = event.message || '';
      const method = event.method ? ` [${event.method}]` : '';
      const url = event.url ? ` ${event.url}` : '';
      const statusCode = event.statusCode ? ` (${event.statusCode})` : '';
      const duration = event.duration ? ` ${event.duration}ms` : '';
      
      console.log(`🔍 Debug [${event.type}]: ${message}${method}${url}${statusCode}${duration}`);
    });

    const errorSubscription = ExpoMutualTls.onError((event) => {
      const code = event.code ? ` [${event.code}]` : '';
      console.error(`❌ Error: ${event.message}${code}`);
      
      // Show user-friendly error messages
      if (event.code === 'CERTIFICATE_NOT_FOUND') {
        alert('Please store a certificate first');
      }
    });

    const expirySubscription = ExpoMutualTls.onCertificateExpiry((event) => {
      const expiryDate = new Date(event.expiry).toLocaleDateString();
      const alias = event.alias ? ` (${event.alias})` : '';
      const warning = event.warning ? ' ⚠️' : '';
      
      console.warn(`📅 Certificate Expiry${warning}: ${event.subject}${alias} - expires ${expiryDate}`);
      
      if (event.warning) {
        alert(`Certificate expiring soon: ${event.subject}`);
      }
    });

    // Cleanup all listeners on unmount
    return () => {
      debugSubscription.remove();
      errorSubscription.remove();
      expirySubscription.remove();
    };
  }, []);

  // Component JSX...
}
```

## Advanced Configuration

### Complete Configuration Options

For advanced use cases, you can use the raw module interface:

```typescript
import { ExpoMutualTlsModuleRaw, MutualTlsConfig } from 'expo-mutual-tls';

const config: MutualTlsConfig = {
  certificateFormat: 'p12',
  keychainServiceForP12: 'custom.p12.service',
  keychainServiceForPassword: 'custom.password.service',
  enableLogging: true,
  requireUserAuthentication: true,      // Require biometric/device auth
  userAuthValiditySeconds: 300,         // Auth validity duration
  expiryWarningDays: 30                 // Days before expiry to warn
};

const result = await ExpoMutualTlsModuleRaw.configure(config);
```

### Security Features

#### Biometric Authentication

Enable biometric or device credential authentication:

```typescript
const config: MutualTlsConfig = {
  certificateFormat: 'p12',
  requireUserAuthentication: true,
  userAuthValiditySeconds: 300,  // 5 minutes
  // ... other options
};
```

#### Certificate Validation

The module performs comprehensive certificate validation:

- ✅ Certificate expiry checking
- ✅ Extended Key Usage (EKU) validation for client authentication
- ✅ Private key/certificate pairing verification
- ✅ Certificate chain validation
- ✅ Hardware-backed key storage

## Platform Implementation

### iOS Implementation

- **Security Framework**: Uses iOS Security Framework APIs
- **Keychain Integration**: Secure keychain storage with hardware backing
- **Certificate Parsing**: Native PEM and P12 parsing
- **TLS Integration**: URLSession with custom SSL context

### Android Implementation  

- **Android Keystore**: Hardware-backed key storage when available
- **BouncyCastle**: PEM certificate parsing and cryptographic operations
- **OkHttp Integration**: mTLS-enabled HTTP client
- **Biometric Support**: Android Biometric API integration

## Error Handling

The module provides detailed error information:

```typescript
try {
  await ExpoMutualTls.request('https://api.example.com');
} catch (error) {
  console.error('Request failed:', error.message);
  // Handle specific error types
  if (error.code === 'CERTIFICATE_NOT_FOUND') {
    // Certificate is not stored
  } else if (error.code === 'SSL_HANDSHAKE_FAILED') {
    // mTLS handshake failed
  }
}
```

### Common Error Codes

| Code | Description | Solution |
|------|-------------|----------|
| `NOT_CONFIGURED` | Module not configured | Call configure method first |
| `CERTIFICATE_NOT_FOUND` | No certificate stored | Store certificate before making requests |
| `INVALID_CERTIFICATE_FORMAT` | Certificate format invalid | Verify certificate data and format |
| `SSL_HANDSHAKE_FAILED` | mTLS handshake failed | Check certificate validity and server configuration |
| `KEYCHAIN_ACCESS_DENIED` | Keychain access denied | Check app permissions or retry with authentication |

## Example Apps

### Complete P12 Example with Event Handling

```typescript
import React, { useEffect, useState } from 'react';
import ExpoMutualTls from 'expo-mutual-tls';
import { Asset } from 'expo-asset';
import * as FileSystem from 'expo-file-system';

export default function App() {
  const [logs, setLogs] = useState<string[]>([]);
  const [status, setStatus] = useState('Ready');

  const addLog = (message: string) => {
    const timestamp = new Date().toLocaleTimeString();
    setLogs(prev => [`[${timestamp}] ${message}`, ...prev.slice(0, 19)]);
  };

  // Comprehensive event listeners setup
  useEffect(() => {
    // Debug logging with detailed information
    const debugSubscription = ExpoMutualTls.onDebugLog((event) => {
      const message = event.message || '';
      const method = event.method ? ` [${event.method}]` : '';
      const url = event.url ? ` ${event.url}` : '';
      const statusCode = event.statusCode ? ` (${event.statusCode})` : '';
      const duration = event.duration ? ` ${event.duration}ms` : '';
      
      addLog(`🔍 Debug [${event.type}]: ${message}${method}${url}${statusCode}${duration}`);
      console.log(`Debug [${event.type}]:`, message, { 
        method: event.method, 
        url: event.url, 
        statusCode: event.statusCode, 
        duration: event.duration 
      });
    });

    // Error handling with user-friendly messages
    const errorSubscription = ExpoMutualTls.onError((event) => {
      const code = event.code ? ` [${event.code}]` : '';
      addLog(`❌ Error: ${event.message}${code}`);
      console.error('mTLS Error:', event.message, event.code ? `Code: ${event.code}` : '');
      
      // Provide user guidance based on error codes
      if (event.code === 'CERTIFICATE_NOT_FOUND') {
        setStatus('Please store a certificate first');
      } else if (event.code === 'SSL_HANDSHAKE_FAILED') {
        setStatus('Certificate validation failed');
      }
    });

    // Certificate expiry monitoring
    const expirySubscription = ExpoMutualTls.onCertificateExpiry((event) => {
      const expiryDate = new Date(event.expiry).toLocaleDateString();
      const alias = event.alias ? ` (${event.alias})` : '';
      const warning = event.warning ? ' ⚠️' : '';
      
      addLog(`📅 Certificate Expiry${warning}: ${event.subject}${alias} - expires ${expiryDate}`);
      console.warn('Certificate expiry warning:', {
        subject: event.subject,
        alias: event.alias,
        expiry: expiryDate,
        warning: event.warning
      });
      
      if (event.warning) {
        setStatus(`Certificate expires soon: ${event.subject}`);
      }
    });

    // Cleanup listeners on unmount
    return () => {
      debugSubscription.remove();
      errorSubscription.remove();
      expirySubscription.remove();
    };
  }, []);

  const setupP12Certificate = async () => {
    try {
      setStatus('Setting up P12 certificate...');
      
      // Configure for P12 with logging enabled
      await ExpoMutualTls.configureP12('demo-service', true);
      addLog('✅ P12 configuration completed');
      
      // Load P12 certificate from assets
      const [asset] = await Asset.loadAsync(require('./assets/client.p12'));
      const p12Data = await FileSystem.readAsStringAsync(asset.localUri!, {
        encoding: FileSystem.EncodingType.Base64,
      });
      
      // Store certificate
      await ExpoMutualTls.storeP12(p12Data, 'certificate-password');
      addLog('✅ P12 certificate stored successfully');
      
      // Test connection
      const result = await ExpoMutualTls.request('https://secure-api.example.com', {
        method: 'GET',
        headers: { 'Accept': 'application/json' }
      });
      
      if (result.success) {
        addLog(`✅ Connection successful! Status: ${result.statusCode}, TLS: ${result.tlsVersion}`);
        setStatus(`Connected successfully (${result.statusCode})`);
      } else {
        addLog('❌ Connection failed');
        setStatus('Connection failed');
      }
      
    } catch (error) {
      addLog(`❌ Setup failed: ${error}`);
      setStatus('Setup failed');
      console.error('Setup failed:', error);
    }
  };

  return (
    <div>
      <h1>mTLS P12 Demo</h1>
      <p>Status: {status}</p>
      <button onClick={setupP12Certificate}>Setup P12 Certificate</button>
      
      <h2>Activity Logs</h2>
      <div style={{ height: '200px', overflow: 'auto', border: '1px solid #ccc' }}>
        {logs.map((log, index) => (
          <div key={index} style={{ fontSize: '12px', fontFamily: 'monospace' }}>
            {log}
          </div>
        ))}
      </div>
      
      <button onClick={() => ExpoMutualTls.removeAllListeners()}>
        Clear All Event Listeners
      </button>
    </div>
  );
}
```

### Complete PEM Example with Event Handling

```typescript
import React, { useEffect } from 'react';
import ExpoMutualTls from 'expo-mutual-tls';
import { Asset } from 'expo-asset';
import * as FileSystem from 'expo-file-system';

const PEMCertificateDemo = () => {
  useEffect(() => {
    // Set up comprehensive event monitoring
    const debugSubscription = ExpoMutualTls.onDebugLog((event) => {
      console.log(`🔍 [${event.type}] ${event.message}`);
      if (event.url) console.log(`   URL: ${event.url}`);
      if (event.duration) console.log(`   Duration: ${event.duration}ms`);
    });

    const errorSubscription = ExpoMutualTls.onError((event) => {
      console.error(`❌ mTLS Error: ${event.message}`);
      if (event.code) console.error(`   Code: ${event.code}`);
    });

    const expirySubscription = ExpoMutualTls.onCertificateExpiry((event) => {
      console.warn(`📅 Certificate "${event.subject}" expires on ${new Date(event.expiry).toLocaleDateString()}`);
    });

    return () => {
      debugSubscription.remove();
      errorSubscription.remove();
      expirySubscription.remove();
    };
  }, []);

  const setupPEMCertificates = async () => {
    try {
      // Configure for PEM with debug logging
      console.log('Configuring PEM certificate format...');
      await ExpoMutualTls.configurePEM('cert-service', 'key-service', true);
      
      // Load PEM files from assets
      console.log('Loading PEM certificate files...');
      const [certAsset, keyAsset] = await Asset.loadAsync([
        require('./assets/client.pem'),
        require('./assets/client.key')
      ]);
      
      const certificate = await FileSystem.readAsStringAsync(certAsset.localUri!);
      const privateKey = await FileSystem.readAsStringAsync(keyAsset.localUri!);
      
      // Store certificates
      console.log('Storing PEM certificates...');
      await ExpoMutualTls.storePEM(certificate, privateKey);
      
      // Verify certificates are stored
      const hasCerts = await ExpoMutualTls.hasCertificate();
      console.log('Certificate verification:', hasCerts ? '✅ Present' : '❌ Missing');
      
      if (hasCerts) {
        // Make authenticated request
        console.log('Making authenticated mTLS request...');
        const response = await ExpoMutualTls.request('https://api.example.com/data', {
          method: 'POST',
          headers: { 
            'Accept': 'application/json',
            'Content-Type': 'application/json'
          },
          body: JSON.stringify({ action: 'getData', timestamp: Date.now() })
        });
        
        if (response.success) {
          console.log('✅ API Request successful!');
          console.log(`   Status: ${response.statusCode} ${response.statusMessage}`);
          console.log(`   TLS Version: ${response.tlsVersion}`);
          console.log(`   Cipher Suite: ${response.cipherSuite}`);
          console.log('   Response:', JSON.parse(response.body));
        } else {
          console.log('❌ API Request failed');
        }
      }
      
    } catch (error) {
      console.error('❌ PEM setup failed:', error);
      
      // Handle specific error scenarios
      if (error.code === 'INVALID_CERTIFICATE_FORMAT') {
        console.error('   Solution: Check PEM file format and encoding');
      } else if (error.code === 'KEYCHAIN_ACCESS_DENIED') {
        console.error('   Solution: Check app keychain permissions');
      }
    }
  };

  return (
    <div>
      <h1>mTLS PEM Demo</h1>
      <button onClick={setupPEMCertificates}>
        Setup PEM Certificates & Test
      </button>
    </div>
  );
};

export default PEMCertificateDemo;
```

## Troubleshooting

### Common Issues

**iOS Build Errors:**
- Ensure iOS deployment target is 11.0 or higher
- Add required iOS frameworks in your app configuration

**Android Build Errors:**
- Verify Android API level 24 (Android 7.0) or higher
- Ensure BouncyCastle dependencies are properly resolved

**Certificate Issues:**
- Verify certificate format and encoding
- Check certificate expiry dates
- Ensure a private key matches a certificate public key

**Network Issues:**
- Verify server supports mTLS client certificate authentication
- Check server certificate authority trust chain
- Ensure proper network connectivity

### Debug Logging

Enable comprehensive logging:

```typescript
// Enable debug logging during configuration
await ExpoMutualTls.configureP12('service', true);

// Listen for debug events
ExpoMutualTls.onDebugLog(event => {
  console.log(`[${event.type}] ${event.message}`);
  if (event.url) console.log(`URL: ${event.url}`);
  if (event.statusCode) console.log(`Status: ${event.statusCode}`);
  if (event.duration) console.log(`Duration: ${event.duration}ms`);
});
```

## Security Considerations

### Certificate Storage
- Certificates are stored in hardware-backed secure storage when available
- iOS: Uses iOS Keychain with hardware encryption
- Android: Uses Android Keystore with hardware security module (HSM)

### Best Practices
- Enable biometric authentication for sensitive applications
- Use short authentication validity periods
- Implement certificate rotation procedures
- Monitor certificate expiry dates
- Validate server certificates properly

### Compliance
- Supports enterprise security requirements
- Hardware-backed cryptographic operations
- Audit-friendly debug logging
- Secure credential lifecycle management

## Migration Guide

### From v0.0.x to v0.1.x

The v0.1.x release introduces simplified utility functions:

**Before (v0.0.x):**
```typescript
import ExpoMutualTlsModule, { MutualTlsConfig } from 'expo-mutual-tls';

const config: MutualTlsConfig = {
  certificateFormat: 'p12',
  keychainServiceForP12: 'service',
  enableLogging: true
};
await ExpoMutualTlsModule.configure(config);
```

**After (v0.1.x):**
```typescript
import ExpoMutualTls from 'expo-mutual-tls';

await ExpoMutualTls.configureP12('service', true);
```

The raw module interface is still available for advanced use cases via `ExpoMutualTlsModuleRaw`.

## Contributing

Contributions are very welcome!
Please refer to guidelines described in the [contributing guide]( https://github.com/a-cube-io/expo-mutual-tls#contributing).

### Development Setup

1. Clone the repository
2. Install dependencies: `npm install`
3. Build the module: `npm run build`
4. Run example app: `cd example && npx expo run:ios`

## License

MIT License - see [LICENSE](LICENSE) file for details.

## Support

- 📋 [GitHub Issues](https://github.com/a-cube-io/expo-mutual-tls/issues)
- 📖 [Documentation](https://github.com/a-cube-io/expo-mutual-tls)
---

**Made with ❤️ for secure mobile applications**
