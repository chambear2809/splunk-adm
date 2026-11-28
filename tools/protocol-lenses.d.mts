export interface ProtocolLensBundleSpec {
  id: string;
  pageExport: string;
  summarizeExport: string;
}

export declare const PROTOCOLS_HOST_MODULES: Record<string, string>;
export declare const PROTOCOLS_CORE_SDK_MODULES: Record<string, string>;
export declare const IMPLEMENTED_PROTOCOL_LENSES: readonly ProtocolLensBundleSpec[];
export declare function protocolLensAssetVersion(lensId: string): string;
export declare function protocolLensVersions(): Record<string, string>;
export declare function protocolsCoreHostModule(id: string): string | undefined;
export declare function protocolLensExternalGlobal(
  id: string,
): string | undefined;
