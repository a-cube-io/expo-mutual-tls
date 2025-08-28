import { useEvent } from 'expo';
import ExpoMutualTls, { MutualTlsConfig, CertificateFormat } from 'expo-mutual-tls';
import { Asset } from 'expo-asset';
import * as FileSystem from 'expo-file-system';
import { Alert, Button, SafeAreaView, ScrollView, Text, View, StyleSheet } from 'react-native';
import { useState, useEffect } from 'react';

export default function App() {
  const [status, setStatus] = useState<string>('Ready');
  const [isConfigured, setIsConfigured] = useState<boolean>(false);
  const [currentFormat, setCurrentFormat] = useState<CertificateFormat>('p12');
  const [logs, setLogs] = useState<string[]>([]);
  const [isLoading, setIsLoading] = useState<boolean>(false);

  // Event listeners
  const onDebugLog = useEvent(ExpoMutualTls, 'onDebugLog');
  const onError = useEvent(ExpoMutualTls, 'onError');
  const onCertificateExpiry = useEvent(ExpoMutualTls, 'onCertificateExpiry');

  useEffect(() => {
    if (onDebugLog) {
      addLog(`Debug: ${onDebugLog.type} - ${onDebugLog.message || ''}`);
    }
  }, [onDebugLog]);

  useEffect(() => {
    if (onError) {
      addLog(`Error: ${onError.message}`);
    }
  }, [onError]);

  useEffect(() => {
    if (onCertificateExpiry) {
      addLog(`Certificate Expiry: ${onCertificateExpiry.subject} - ${new Date(onCertificateExpiry.expiry).toLocaleDateString()}`);
    }
  }, [onCertificateExpiry]);

  const addLog = (message: string) => {
    const timestamp = new Date().toLocaleTimeString();
    setLogs(prev => [`[${timestamp}] ${message}`, ...prev.slice(0, 19)]);
  };

  const clearLogs = () => {
    setLogs([]);
  };

  // Load and encode P12 file
  const loadP12Certificate = async (): Promise<{ p12Data: string; password: string }> => {
    try {
      // Load the asset using require() now that Metro recognizes .p12 files
      const [asset] = await Asset.loadAsync(require('./assets/merchant.p12'));
      
      console.log('P12 asset loaded:', {
        name: asset.name,
        type: asset.type,
        localUri: asset.localUri,
        downloaded: asset.downloaded
      });
      
      if (!asset.localUri) {
        throw new Error('Failed to load P12 asset - no local URI available');
      }

      // Check if a file exists before reading
      const fileInfo = await FileSystem.getInfoAsync(asset.localUri);
      if (!fileInfo.exists) {
        throw new Error('P12 file does not exist at local URI');
      }

      console.log('P12 file info:', fileInfo);

      const base64Data = await FileSystem.readAsStringAsync(asset.localUri, {
        encoding: FileSystem.EncodingType.Base64,
      });

      console.log('P12 base64 data loaded, length:', base64Data.length);

      return {
        p12Data: base64Data,
        password: 'ciao', // Default password for merchant.p12
      };
    } catch (error) {
      console.error('Error loading P12 certificate:', error);
      throw new Error(`Failed to load P12 certificate: ${error}`);
    }
  };

  // Load PEM files
  const loadPemCertificates = async (): Promise<{ certificate: string; privateKey: string }> => {
    try {
      // Load both PEM assets using require() now that Metro recognizes .pem files
      const [certAsset, keyAsset] = await Asset.loadAsync([
        require('./assets/certificate.pem'),
        require('./assets/private.pem'),
      ]);

      console.log('PEM assets loaded:', {
        certificate: {
          name: certAsset.name,
          type: certAsset.type,
          localUri: certAsset.localUri,
          downloaded: certAsset.downloaded
        },
        privateKey: {
          name: keyAsset.name,
          type: keyAsset.type,
          localUri: keyAsset.localUri,
          downloaded: keyAsset.downloaded
        }
      });

      if (!certAsset.localUri || !keyAsset.localUri) {
        throw new Error('Failed to load PEM assets - no local URIs available');
      }

      // Check if files exist before reading
      const [certFileInfo, keyFileInfo] = await Promise.all([
        FileSystem.getInfoAsync(certAsset.localUri),
        FileSystem.getInfoAsync(keyAsset.localUri),
      ]);

      if (!certFileInfo.exists || !keyFileInfo.exists) {
        throw new Error('PEM files do not exist at local URIs');
      }

      console.log('PEM file info:', { certFileInfo, keyFileInfo });

      const [certificate, privateKey] = await Promise.all([
        FileSystem.readAsStringAsync(certAsset.localUri, { encoding: FileSystem.EncodingType.UTF8 }),
        FileSystem.readAsStringAsync(keyAsset.localUri, { encoding: FileSystem.EncodingType.UTF8 }),
      ]);

      console.log('PEM certificate loaded, length:', certificate.length);
      console.log('PEM private key loaded, length:', privateKey.length);

      return { certificate, privateKey };
    } catch (error) {
      console.error('Error loading PEM certificates:', error);
      throw new Error(`Failed to load PEM certificates: ${error}`);
    }
  };

  // Configure module for P12 format
  const configureP12 = async () => {
    try {
      setStatus('Configuring P12...');
      addLog('Configuring module for P12 format');

      const config: MutualTlsConfig = {
        certificateFormat: 'p12',
        keychainServiceForP12: 'demo.client.p12',
        keychainServiceForPassword: 'demo.client.p12.password',
        enableLogging: true,
        expiryWarningDays: 30,
      };

      const result = await ExpoMutualTls.configure(config);
      setCurrentFormat('p12');
      setIsConfigured(result.success);
      const hasCert = result.hasCertificate ? ' (Has Certificate)' : ' (No Certificate - Store One)';
      setStatus(result.success ? `Configured P12${hasCert}` : 'Configuration Failed');
      addLog(`P12 configuration: ${result.success ? 'Success' : 'Failed'}${result.hasCertificate ? ' - Certificate found' : ' - No certificate, store one first'}`);
    } catch (error) {
      setStatus('P12 Config Error');
      addLog(`P12 configuration error: ${error}`);
      Alert.alert('Configuration Error', `Failed to configure P12: ${error}`);
    }
  };

  // Configure module for PEM format
  const configurePEM = async () => {
    try {
      setStatus('Configuring PEM...');
      addLog('Configuring module for PEM format');

      const config: MutualTlsConfig = {
        certificateFormat: 'pem',
        keychainServiceForCertChain: 'demo.client.cert',
        keychainServiceForPrivateKey: 'demo.client.key',
        enableLogging: true,
        expiryWarningDays: 30,
      };

      const result = await ExpoMutualTls.configure(config);
      setCurrentFormat('pem');
      setIsConfigured(result.success);
      const hasCert = result.hasCertificate ? ' (Has Certificate)' : ' (No Certificate - Store One)';
      setStatus(result.success ? `Configured PEM${hasCert}` : 'Configuration Failed');
      addLog(`PEM configuration: ${result.success ? 'Success' : 'Failed'}${result.hasCertificate ? ' - Certificate found' : ' - No certificate, store one first'}`);
    } catch (error) {
      setStatus('PEM Config Error');
      addLog(`PEM configuration error: ${error}`);
      Alert.alert('Configuration Error', `Failed to configure PEM: ${error}`);
    }
  };

  // Store P12 certificate
  const storeP12Certificate = async () => {
    if (isLoading) return;
    
    try {
      setIsLoading(true);
      setStatus('Storing P12 Certificate...');
      addLog('Loading and storing P12 certificate');

      const { p12Data, password } = await loadP12Certificate();
      
      await ExpoMutualTls.storeCertificate({
        p12Data,
        password,
      });

      setStatus('P12 Certificate Stored');
      addLog('P12 certificate stored successfully');
      Alert.alert('Success', 'P12 certificate stored successfully');
    } catch (error) {
      setStatus('P12 Store Error');
      addLog(`P12 storage error: ${error}`);
      Alert.alert('Storage Error', `Failed to store P12 certificate: ${error}`);
    } finally {
      setIsLoading(false);
    }
  };

  // Store PEM certificates
  const storePemCertificates = async () => {
    if (isLoading) return;
    
    try {
      setIsLoading(true);
      setStatus('Storing PEM Certificates...');
      addLog('Loading and storing PEM certificates');

      const { certificate, privateKey } = await loadPemCertificates();
      
      await ExpoMutualTls.storeCertificate({
        certificate,
        privateKey,
        // passphrase: 'optional-passphrase-if-key-is-encrypted'
      });

      setStatus('PEM Certificates Stored');
      addLog('PEM certificates stored successfully');
      Alert.alert('Success', 'PEM certificates stored successfully');
    } catch (error) {
      setStatus('PEM Store Error');
      addLog(`PEM storage error: ${error}`);
      Alert.alert('Storage Error', `Failed to store PEM certificates: ${error}`);
    } finally {
      setIsLoading(false);
    }
  };

  // Check if certificates are stored
  const checkCertificates = async () => {
    try {
      setStatus('Checking Certificates...');
      const hasCerts = await ExpoMutualTls.hasCertificate();
      setStatus(`Certificates: ${hasCerts ? 'Present' : 'Not Found'}`);
      addLog(`Certificates check: ${hasCerts ? 'Found' : 'Not found'}`);
      Alert.alert('Certificate Check', `Certificates are ${hasCerts ? 'present' : 'not found'}`);
    } catch (error) {
      setStatus('Check Error');
      addLog(`Certificate check error: ${error}`);
      Alert.alert('Check Error', `Failed to check certificates: ${error}`);
    }
  };

  // Test mTLS connection
  const testConnection = async () => {
    try {
      setStatus('Testing Connection...');
      addLog('Testing mTLS connection to test server');

      // Use a test mTLS endpoint - replace it with your actual mTLS test server
      const testUrl = 'https://ereceipts-it.dev.acubeapi.com:444/mf1/receipts';

      const result = await ExpoMutualTls.makeRequest({
        url: testUrl,
        method: 'POST',
        headers: {
          'content-type': 'application/json',
          'Authorization': `Bearer eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiJ9.eyJpYXQiOjE3NTYzMTA0NDMsImV4cCI6MTc1NjM5Njg0Mywicm9sZXMiOnsiZXJlY2VpcHRzLWl0LmFjdWJlYXBpLmNvbSI6WyJST0xFX01FUkNIQU5UIl19LCJ1c2VybmFtZSI6Im1lcmNhbnRlaW5maWVyYTE5QGdtYWlsLmNvbSIsInVpZCI6MTUxNCwiZmlkIjpudWxsLCJwaWQiOm51bGx9.b9n5QCTrkxyJN73lSj9VRX4KMqlIuXYWGF-EOorwLjC07AF1k5csotu5hUkBBdjtTO692OXtcPWbCw3D2OHuoBw-WPdMwhRWQYK2tZuVMu0XNsVOHDZdyxt8zIcMc8WnaV45-BQOABhQFp8Z60j7ghrOCLUjBxGb8TSB0FxgvBGJXUUEmayu55bCtkKJVHHQbZdz3m1Iyf271F-Cr9obDAkO3AFBnkk-XwYtUYY1Qao7RMgV-cAEeDigAUM12EKv3jdGdL-Lfp03fQxwPP3HNpkb3mvVU-1nZOFKMMah2plFQ_Ne7NF_UwmRF3qgJ2pIBCE3GhrRNp3I6qHHf1UEmqF4tJtfYtlSCBAkoXws1FqZxKHb0lIsAPKMDbYVGjPgxSosgD8xLVPeT9GsgSrpkU3tiE_LP4CVHuFhAWOoI0QXDkRGSKBCFRK7iaxjh53L1T-qDDTE6SCEUKGnmqAn_NXnHQXsG8Kp9Vtfe2PP6NIzMQcJa_QTLf5pBzg1RP69_TRz5TuzWtBdbdDwSXV30hysGzKHv59GVW8J_BOQCThX4_T8ftNTnx36y9ZVcnXtzciDEefTPjiwySOe6EeeLimqIfylM5GcYp3j29s71Pzn682P5gKL52-mQPTLACqZz-uI8NGtEd5wjZ1phV6IMfFeyn0jQzpi2t4vLW1Fy_4`
        },
        body: JSON.stringify({
          "items": [
            {
              "description": "Latte Macchiato",
              "quantity": "2.00",
              "unit_price": "2.99",
              "discount": "5"
            },
              {
              "description": "Espresso Macchiato",
              "quantity": "3.00",
              "unit_price": "1.99",
              "discount": "0"
              }
          ],
          "customer_tax_code": "QWERT12345",
          "customer_lottery_code": "QWER123",
          "invoice_issuing": true,
          "uncollected_dcr_to_ssn": false,
          "cash_payment_amount": "4.0",
          "electronic_payment_amount": "0.0",
          "ticket_restaurant_payment_amount": "0.0",
          "ticket_restaurant_quantity": 0
        })
      });

      console.log('mTLS Request Result:', result);


      setStatus(`Connection: ${result.success ? 'Success' : 'Failed'}`);

      if (result.success) {
        addLog(`Connection successful! Status: ${result.statusCode}, TLS: ${result.tlsVersion}, Cipher: ${result.cipherSuite}`);
        Alert.alert('Connection Success', `Status: ${result.statusCode}\nTLS Version: ${result.tlsVersion}\nCipher Suite: ${result.cipherSuite}`);
      } else {
        addLog(`Connection failed`);
        Alert.alert('Connection Failed', 'mTLS connection failed');
      }
    } catch (error) {
      setStatus('Connection Error');
      addLog(`Connection error: ${error}`);
      Alert.alert('Connection Error', `Failed to test connection: ${error}`);
    }
  };

  // Remove certificates
  const removeCertificates = async () => {
    try {
      setStatus('Removing Certificates...');
      await ExpoMutualTls.removeCertificate();
      setStatus('Certificates Removed');
      setIsConfigured(false);
      addLog('Certificates removed successfully');
      Alert.alert('Success', 'Certificates removed successfully');
    } catch (error) {
      setStatus('Remove Error');
      addLog(`Remove error: ${error}`);
      Alert.alert('Remove Error', `Failed to remove certificates: ${error}`);
    }
  };

  return (
    <SafeAreaView style={styles.container}>
      <ScrollView style={styles.container}>
        <Text style={styles.header}>Mutual TLS Demo</Text>
        
        <View style={styles.statusContainer}>
          <Text style={styles.statusLabel}>Status: </Text>
          <Text style={styles.statusText}>{status}</Text>
          <Text style={styles.formatText}>Format: {currentFormat.toUpperCase()}</Text>
        </View>

        <Group name="Configuration">
          <Button title="Configure P12 Mode" onPress={configureP12} />
          <View style={styles.buttonSpacer} />
          <Button title="Configure PEM Mode" onPress={configurePEM} />
        </Group>

        <Group name="Certificate Management">
          <Button 
            title={isLoading ? "Loading P12..." : "Store P12 Certificate"} 
            onPress={storeP12Certificate}
            disabled={isLoading || (!isConfigured || currentFormat !== 'p12')}
          />
          <View style={styles.buttonSpacer} />
          <Button 
            title={isLoading ? "Loading PEM..." : "Store PEM Certificates"} 
            onPress={storePemCertificates}
            disabled={isLoading || (!isConfigured || currentFormat !== 'pem')}
          />
          <View style={styles.buttonSpacer} />
          <Button title="Check Certificates" onPress={checkCertificates} disabled={isLoading || !isConfigured} />
          <View style={styles.buttonSpacer} />
          <Button title="Remove Certificates" onPress={removeCertificates} disabled={isLoading || !isConfigured} />
        </Group>

        <Group name="Testing">
          <Button title="Test mTLS Connection" onPress={testConnection} disabled={!isConfigured} />
        </Group>

        <Group name="Logs">
          <View style={styles.logHeader}>
            <Text style={styles.logTitle}>Recent Activity</Text>
            <Button title="Clear" onPress={clearLogs} />
          </View>
          <ScrollView style={styles.logContainer} nestedScrollEnabled>
            {logs.map((log, index) => (
              <Text key={index} style={styles.logText}>{log}</Text>
            ))}
            {logs.length === 0 && (
              <Text style={styles.emptyLogText}>No activity logged yet</Text>
            )}
          </ScrollView>
        </Group>
      </ScrollView>
    </SafeAreaView>
  );
}

function Group(props: { name: string; children: React.ReactNode }) {
  return (
    <View style={styles.group}>
      <Text style={styles.groupHeader}>{props.name}</Text>
      {props.children}
    </View>
  );
}

const styles = StyleSheet.create({
  container: {
    flex: 1,
    backgroundColor: '#f5f5f5',
  },
  header: {
    fontSize: 28,
    fontWeight: 'bold',
    textAlign: 'center',
    margin: 20,
    color: '#333',
  },
  statusContainer: {
    flexDirection: 'row',
    justifyContent: 'space-between',
    alignItems: 'center',
    margin: 20,
    padding: 15,
    backgroundColor: '#fff',
    borderRadius: 10,
    shadowColor: '#000',
    shadowOffset: { width: 0, height: 2 },
    shadowOpacity: 0.1,
    shadowRadius: 4,
    elevation: 3,
  },
  statusLabel: {
    fontSize: 16,
    fontWeight: '600',
    color: '#666',
  },
  statusText: {
    fontSize: 16,
    fontWeight: 'bold',
    color: '#007AFF',
    flex: 1,
    textAlign: 'center',
  },
  formatText: {
    fontSize: 14,
    fontWeight: '600',
    color: '#FF6B6B',
    backgroundColor: '#FFE6E6',
    paddingHorizontal: 8,
    paddingVertical: 4,
    borderRadius: 4,
  },
  group: {
    margin: 20,
    backgroundColor: '#fff',
    borderRadius: 12,
    padding: 20,
    shadowColor: '#000',
    shadowOffset: { width: 0, height: 2 },
    shadowOpacity: 0.1,
    shadowRadius: 4,
    elevation: 3,
  },
  groupHeader: {
    fontSize: 20,
    fontWeight: 'bold',
    marginBottom: 15,
    color: '#333',
    textAlign: 'center',
  },
  buttonSpacer: {
    height: 10,
  },
  logHeader: {
    flexDirection: 'row',
    justifyContent: 'space-between',
    alignItems: 'center',
    marginBottom: 10,
  },
  logTitle: {
    fontSize: 16,
    fontWeight: '600',
    color: '#333',
  },
  logContainer: {
    maxHeight: 200,
    backgroundColor: '#f8f8f8',
    borderRadius: 8,
    padding: 10,
    borderWidth: 1,
    borderColor: '#e0e0e0',
  },
  logText: {
    fontSize: 12,
    color: '#555',
    fontFamily: 'monospace',
    marginBottom: 2,
    lineHeight: 16,
  },
  emptyLogText: {
    fontSize: 14,
    color: '#999',
    textAlign: 'center',
    fontStyle: 'italic',
    paddingVertical: 20,
  },
});
