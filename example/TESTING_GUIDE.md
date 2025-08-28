# Mutual TLS Demo App - Testing Guide

This example app demonstrates both P12 and PEM certificate functionality of the expo-mutual-tls module.

## 📋 Setup Instructions

### 1. Install Dependencies
```bash
cd example
npm install
```

### 2. Install Main Module Dependencies
```bash
cd ..
npm install
```

### 3. Build the Module
```bash
npm run build
```

## 🚀 Running the App

### Android
```bash
cd example
npm run android
```

### iOS
```bash
cd example
npm run ios
```

## 📱 Testing Features

### 🔧 Configuration Testing

1. **Configure P12 Mode**
   - Tap "Configure P12 Mode"
   - Status should show "Configured (P12)"
   - Format indicator shows "P12"

2. **Configure PEM Mode**
   - Tap "Configure PEM Mode" 
   - Status should show "Configured (PEM)"
   - Format indicator shows "PEM"

### 🔐 Certificate Management Testing

#### P12 Certificate Testing
1. Configure P12 mode first
2. Tap "Store P12 Certificate"
   - App loads `merchant.p12` from assets
   - Uses default password `test123`
   - Should show success alert
3. Tap "Check Certificates" → Should show "Present"

#### PEM Certificate Testing
1. Configure PEM mode first
2. Tap "Store PEM Certificates"
   - App loads `certificate.pem` and `private.pem` from assets
   - Should show success alert
3. Tap "Check Certificates" → Should show "Present"

### 🌐 Connection Testing

1. After storing certificates (P12 or PEM)
2. Tap "Test mTLS Connection"
   - Tests connection to `https://client.badssl.com/`
   - Should show connection results (TLS version, cipher suite)
   - **Note**: This may fail if server doesn't accept your test certificates

### 🧹 Cleanup Testing

1. Tap "Remove Certificates"
2. Should show success alert
3. Tap "Check Certificates" → Should show "Not Found"

## 📊 Monitoring & Debugging

### Event Logging
The app automatically logs all events in the "Logs" section:
- Debug messages from the module
- Certificate operations
- Connection attempts
- Error messages

### Event Types
- **onDebugLog**: Module debug information
- **onError**: Error messages
- **onCertificateExpiry**: Certificate expiry warnings

### Log Management
- Logs auto-scroll and show timestamps
- Maximum 20 recent entries
- Tap "Clear" to reset logs

## 🎯 Test Scenarios

### Scenario 1: P12 Certificate Flow
1. Configure P12 mode
2. Store P12 certificate
3. Check certificate presence
4. Test connection
5. Remove certificate
6. Verify removal

### Scenario 2: PEM Certificate Flow
1. Configure PEM mode
2. Store PEM certificates
3. Check certificate presence
4. Test connection
5. Remove certificates
6. Verify removal

### Scenario 3: Format Switching
1. Configure P12 mode and store certificate
2. Switch to PEM mode (reconfigure)
3. Store PEM certificates
4. Verify both formats work independently

### Scenario 4: Error Handling
1. Try operations without configuration
2. Try storing certificates in wrong format
3. Verify proper error messages and logging

## 🔍 Expected Behavior

### ✅ Success Cases
- Configuration changes format indicator
- Certificate storage shows success alerts
- Check certificates returns correct status
- Event logs show detailed operation info
- UI buttons enable/disable appropriately

### ⚠️ Expected Failures
- Connection test may fail (server doesn't recognize test certs)
- Operations fail gracefully with clear error messages
- Invalid operations show appropriate alerts

## 📁 Test Assets

The app includes test certificate files:
- `assets/merchant.p12` - P12 certificate bundle
- `assets/certificate.pem` - PEM certificate chain
- `assets/private.pem` - PEM private key

## 🐛 Troubleshooting

### Common Issues

1. **Build Errors**
   - Ensure all dependencies installed
   - Run `npm run build` from module root

2. **Asset Loading Errors**
   - Verify certificate files exist in assets folder
   - Check file permissions

3. **Connection Failures**
   - Normal for test certificates
   - Check logs for detailed error info
   - Verify mTLS server requirements

4. **Android Build Issues**
   - Ensure Android SDK is configured
   - Check Gradle sync
   - Verify BouncyCastle dependencies

### Debug Tips

1. **Check Logs Section**
   - All operations are logged with timestamps
   - Error messages provide detailed information

2. **Monitor Status Bar**
   - Shows current operation status
   - Indicates active certificate format

3. **Use Development Build**
   - Enable debug logging in configuration
   - Check native logs via `adb logcat` (Android)

## 🎉 Success Criteria

The test is successful when:
- ✅ Both P12 and PEM modes configure properly
- ✅ Certificates store and retrieve correctly
- ✅ Format switching works seamlessly
- ✅ Error handling is robust
- ✅ Event logging provides detailed feedback
- ✅ UI updates reflect current state accurately

This comprehensive testing validates the dual certificate format support and cross-platform secure storage integration of your mutual TLS module!