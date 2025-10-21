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

export type ResponseType = "json" | "blob" | "arraybuffer" | "text";

export type MakeRequestOptions = {
  url: string;
  method?: string;
  headers?: Record<string, string>;
  body?: string;
  responseType?: ResponseType;
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

export type CertificateSubject = {
  commonName?: string;
  organization?: string;
  organizationalUnit?: string;
  country?: string;
  state?: string;
  locality?: string;
  emailAddress?: string;
};

export type CertificateFingerprints = {
  sha1: string;
  sha256: string;
};

export type CertificateInfo = {
  subject: CertificateSubject;
  issuer: CertificateSubject;
  serialNumber: string;
  version: number;
  validFrom: number; // Unix timestamp in milliseconds
  validTo: number; // Unix timestamp in milliseconds
  fingerprints: CertificateFingerprints;
  publicKeyAlgorithm: string;
  publicKeySize?: number;
  signatureAlgorithm: string;
  keyUsage?: string[];
  extendedKeyUsage?: string[];
  subjectAlternativeNames?: string[];
};

export type ParseCertificateResult = {
  certificates: CertificateInfo[];
};
