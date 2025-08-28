# Quick Test Script for Mutual TLS Module

## Prerequisites
1. Android device connected via ADB
2. Module built successfully
3. Example app dependencies installed

## Quick Testing Commands

### 1. Build and Install
```bash
# From module root
npm run build

# Install example dependencies
cd example
npm install

# Run on Android
npm run android
```

### 2. Manual Testing Sequence

#### Test P12 Format
1. Tap "Configure P12 Mode"
2. Tap "Store P12 Certificate" 
3. Tap "Check Certificates" (should show "Present")
4. Tap "Test mTLS Connection"
5. Check logs for detailed results

#### Test PEM Format
1. Tap "Configure PEM Mode"
2. Tap "Store PEM Certificates"
3. Tap "Check Certificates" (should show "Present") 
4. Tap "Test mTLS Connection"
5. Check logs for detailed results

#### Verify Cleanup
1. Tap "Remove Certificates"
2. Tap "Check Certificates" (should show "Not Found")

### 3. Expected Log Messages

#### P12 Success Flow:
```
[timestamp] Configuring module for P12 format
[timestamp] P12 configuration: Success  
[timestamp] Loading and storing P12 certificate
[timestamp] P12 certificate stored successfully
[timestamp] Certificates check: Found
```

#### PEM Success Flow:
```
[timestamp] Configuring module for PEM format
[timestamp] PEM configuration: Success
[timestamp] Loading and storing PEM certificates  
[timestamp] PEM certificates stored successfully
[timestamp] Certificates check: Found
```

### 4. Validation Checklist

- [ ] P12 mode configures successfully
- [ ] PEM mode configures successfully
- [ ] P12 certificates store without errors
- [ ] PEM certificates store without errors
- [ ] Certificate check returns correct status
- [ ] mTLS connection attempt executes (result may vary)
- [ ] Certificate removal works properly
- [ ] Event logging shows detailed information
- [ ] UI updates reflect current state
- [ ] Error handling works gracefully

## Android Logcat Monitoring

```bash
# Monitor native logs
adb logcat | grep -E "(ExpoMutualTLS|PemCertificateParser|KeychainManager)"
```

## Debugging Commands

```bash
# Check if module is properly linked
adb shell pm list packages | grep mutual

# Check app logs
adb logcat -s ReactNativeJS:*

# Clear app data (reset certificates)
adb shell pm clear com.expomutualtsexample
```

## Expected Results

✅ **All operations should complete without crashes**
✅ **Logs should show detailed operation information**  
✅ **Both P12 and PEM formats should work**
✅ **Certificate storage should persist between app restarts**
✅ **Error messages should be informative**

This testing script validates that your mutual TLS module implementation supports both certificate formats and provides reliable secure storage functionality.