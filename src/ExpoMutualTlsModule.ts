import { NativeModule, requireNativeModule } from "expo";

import {
  ExpoMutualTlsModuleEvents,
  MutualTlsConfig,
  StoreCertificateOptions,
  MakeRequestOptions,
  MakeRequestResult,
  ConfigureResult,
} from "./ExpoMutualTls.types";

declare class ExpoMutualTlsModule extends NativeModule<ExpoMutualTlsModuleEvents> {
  configure(config: MutualTlsConfig): Promise<ConfigureResult>;
  storeCertificate(options: StoreCertificateOptions): Promise<boolean>;
  storeP12Certificate(p12Base64: string, password: string): Promise<boolean>;
  removeCertificate(): Promise<void>;
  hasCertificate(): Promise<boolean>;
  testConnection(url: string): Promise<MakeRequestResult>;
  makeRequest(options: MakeRequestOptions): Promise<MakeRequestResult>;
  isConfigured: boolean;
  currentState: string;
}

// This call loads the native module object from the JSI.
export default requireNativeModule<ExpoMutualTlsModule>("ExpoMutualTls");
