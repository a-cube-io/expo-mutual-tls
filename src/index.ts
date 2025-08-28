// Reexport the native module. On web, it will be resolved to ExpoMutualTlsModule.web.ts
// and on native platforms to ExpoMutualTlsModule.ts
export { default } from './ExpoMutualTlsModule';
export * from  './ExpoMutualTls.types';
