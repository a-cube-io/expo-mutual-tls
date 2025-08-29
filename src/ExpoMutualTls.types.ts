export type ExpoMutualTlsModuleEvents = {
  onChange: (params: ChangeEventPayload) => void;
  onDebugLog: (params: DebugLogEventPayload) => void;
  onError: (params: ErrorEventPayload) => void;
  onCertificateExpiry: (params: CertificateExpiryEventPayload) => void;
};

export type ChangeEventPayload = {
  value: string;
};

export type DebugLogEventPayload = {
  type: string;
  message?: string;
  method?: string;
  url?: string;
  statusCode?: number;
  duration?: number;
};

export type ErrorEventPayload = {
  message: string;
  code?: string;
};

export type CertificateExpiryEventPayload = {
  alias?: string;
  subject: string;
  expiry: number;
  warning?: boolean;
};

export type CertificateFormat = "p12" | "pem";

export type TlsState = "notConfigured" | "configured" | "error";

export type MutualTlsConfig = {
  certificateFormat?: CertificateFormat;
  keychainService?: string;

  // P12 specific (backward compatibility)
  keychainServiceForP12?: string;
  keychainServiceForPassword?: string;

  // PEM specific
  keychainServiceForPrivateKey?: string;
  keychainServiceForCertChain?: string;

  enableLogging?: boolean;
  requireUserAuthentication?: boolean;
  userAuthValiditySeconds?: number;
  expiryWarningDays?: number;
};

export type P12CertificateData = {
  p12Data: string; // Base64 encoded P12 file
  password: string;
};

export type PemCertificateData = {
  certificate: string; // PEM certificate(s) content
  privateKey: string; // PEM private key content
  passphrase?: string; // Optional passphrase for an encrypted private key
};

export type CertificateData = P12CertificateData | PemCertificateData;

export type ConfigureResult = {
  success: boolean;
  state: TlsState;
  hasCertificate: boolean;
};

export type StoreCertificateOptions = P12CertificateData | PemCertificateData;

export type MakeRequestOptions = {
  url: string;
  method?: string;
  headers?: Record<string, string>;
  body?: string;
};

export type MakeRequestResult = {
  success: boolean;
  statusCode: number;
  statusMessage: string;
  headers: Record<string, string[]>;
  body: string;
  tlsVersion: string;
  cipherSuite: string;
};
