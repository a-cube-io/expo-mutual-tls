import ExpoMutualTlsModule from './ExpoMutualTlsModule';
import { 
  MutualTlsConfig, 
  P12CertificateData, 
  PemCertificateData,
  MakeRequestOptions,
  MakeRequestResult,
  ConfigureResult,
  DebugLogEventPayload,
  ErrorEventPayload,
  CertificateExpiryEventPayload
} from './ExpoMutualTls.types';

// Re-export types for convenience
export * from './ExpoMutualTls.types';

// Simple utility functions for common operations
export class ExpoMutualTls {
  /**
   * Configure the mTLS module with P12 certificate
   * @param keychainService - Keychain service identifier
   * @param enableLogging - Enable debug logging
   */
  static async configureP12(keychainService: string = 'client.p12', enableLogging: boolean = false): Promise<ConfigureResult> {
    const config: MutualTlsConfig = {
      certificateFormat: 'p12',
      keychainServiceForP12: keychainService,
      keychainServiceForPassword: `${keychainService}.password`,
      enableLogging
    };
    return ExpoMutualTlsModule.configure(config);
  }

  /**
   * Configure the mTLS module with PEM certificate
   * @param certService - Certificate service identifier
   * @param keyService - Private key service identifier
   * @param enableLogging - Enable debug logging
   */
  static async configurePEM(
    certService: string = 'expo.mtls.client.cert', 
    keyService: string = 'expo.mtls.client.key',
    enableLogging: boolean = false
  ): Promise<ConfigureResult> {
    const config: MutualTlsConfig = {
      certificateFormat: 'pem',
      keychainServiceForCertChain: certService,
      keychainServiceForPrivateKey: keyService,
      enableLogging
    };
    return ExpoMutualTlsModule.configure(config);
  }

  /**
   * Store P12 certificate with simple interface
   * @param p12Base64 - Base64 encoded P12 certificate
   * @param password - P12 password
   */
  static async storeP12(p12Base64: string, password: string): Promise<boolean> {
    const certData: P12CertificateData = { p12Data: p12Base64, password };
    return ExpoMutualTlsModule.storeCertificate(certData);
  }

  /**
   * Store PEM certificate with simple interface
   * @param certificate - PEM certificate content
   * @param privateKey - PEM private key content
   * @param passphrase - Optional passphrase for encrypted private key
   */
  static async storePEM(certificate: string, privateKey: string, passphrase?: string): Promise<boolean> {
    const certData: PemCertificateData = { certificate, privateKey, passphrase };
    return ExpoMutualTlsModule.storeCertificate(certData);
  }

  /**
   * Make authenticated mTLS request with simple interface
   * @param url - Target URL
   * @param options - Optional request configuration
   */
  static async request(url: string, options: Partial<MakeRequestOptions> = {}): Promise<MakeRequestResult> {
    const requestOptions: MakeRequestOptions = { url, ...options };
    return ExpoMutualTlsModule.makeRequest(requestOptions);
  }

  /**
   * Test mTLS connection to a URL
   * @param url - Target URL to test
   */
  static async testConnection(url: string): Promise<MakeRequestResult> {
    return ExpoMutualTlsModule.testConnection(url);
  }

  /**
   * Get current module state
   */
  static get isConfigured(): boolean {
    return ExpoMutualTlsModule.isConfigured;
  }

  /**
   * Get current TLS state
   */
  static get currentState(): string {
    return ExpoMutualTlsModule.currentState;
  }

  /**
   * Check if certificate is stored
   */
  static async hasCertificate(): Promise<boolean> {
    return ExpoMutualTlsModule.hasCertificate();
  }

  /**
   * Remove stored certificate
   */
  static async removeCertificate(): Promise<void> {
    return ExpoMutualTlsModule.removeCertificate();
  }

  // Event handling utilities
  static onDebugLog(listener: (event: DebugLogEventPayload) => void) {
    return ExpoMutualTlsModule.addListener('onDebugLog', listener);
  }

  static onError(listener: (event: ErrorEventPayload) => void) {
    return ExpoMutualTlsModule.addListener('onError', listener);
  }

  static onCertificateExpiry(listener: (event: CertificateExpiryEventPayload) => void) {
    return ExpoMutualTlsModule.addListener('onCertificateExpiry', listener);
  }

  /**
   * Remove all event listeners
   */
  static removeAllListeners() {
    ExpoMutualTlsModule.removeAllListeners('onDebugLog');
    ExpoMutualTlsModule.removeAllListeners('onError');
    ExpoMutualTlsModule.removeAllListeners('onCertificateExpiry');
  }
}

// Export both the utility class and the raw module for advanced usage
export default ExpoMutualTls;
export { ExpoMutualTlsModule as ExpoMutualTlsModuleRaw };
