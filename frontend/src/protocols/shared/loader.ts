import type { ComponentType } from "react";
import type {
  LensProfileValidator,
  ProtocolLensComponentProps,
  ProtocolLensId,
  ProtocolLensSummaryRunner,
} from "./contract";

export type LensBundleSummaryFn = (
  ...args: [
    ...Parameters<ProtocolLensSummaryRunner>,
    options?: {
      profileValidators?: Partial<Record<ProtocolLensId, LensProfileValidator>>;
    },
  ]
) => ReturnType<ProtocolLensSummaryRunner>;

export type LensBundleExports = {
  assetVersion: string;
  LensPage: ComponentType<ProtocolLensComponentProps>;
  summarize?: LensBundleSummaryFn;
};

type Runtime = typeof globalThis & {
  ApplicationAtlasProtocolLenses?: Partial<
    Record<ProtocolLensId, LensBundleExports>
  >;
  __AtlasProtocolsHost?: {
    staticUrlFor?: (file: string, version: string) => string;
  };
};

const loaded = new Map<ProtocolLensId, Promise<LensBundleExports>>();

function resolveStaticUrl(
  file: string,
  version: string,
  staticUrlFor?: (file: string, version: string) => string,
): string {
  const helper =
    staticUrlFor ?? (globalThis as Runtime).__AtlasProtocolsHost?.staticUrlFor;
  if (!helper) {
    throw new Error("Protocol asset URL helper is unavailable in this build.");
  }
  return helper(file, version);
}

/**
 * Loads an optional protocol lens bundle (`pages/protocol-<lens>.js`).
 * - In development and tests (`!__ADM_SPLUNK_BUILD__`), delegates to `devLoader`.
 * - In packaged Splunk builds (`__ADM_SPLUNK_BUILD__`), fails closed unless
 *   `expectedVersion` is supplied and the loaded IIFE asset version matches
 *   `expectedVersion` exactly.
 */
export async function loadProtocolLensBundle(
  lens: ProtocolLensId,
  devLoader?: () => Promise<LensBundleExports>,
  expectedVersion?: string,
  staticUrlFor?: (file: string, version: string) => string,
): Promise<LensBundleExports> {
  if (!__ADM_SPLUNK_BUILD__) {
    if (!devLoader)
      throw new Error(`Protocol lens "${lens}" is not registered yet.`);
    return devLoader();
  }
  const version = expectedVersion ?? __ADM_PROTOCOL_LENS_VERSIONS__[lens];
  if (!version) {
    throw new Error(
      `Protocol lens "${lens}" asset manifest is missing in this build.`,
    );
  }
  const existing = loaded.get(lens);
  if (existing) return existing;
  const runtime = globalThis as Runtime;
  const preloaded = runtime.ApplicationAtlasProtocolLenses?.[lens];
  if (
    preloaded &&
    preloaded.assetVersion === version &&
    typeof preloaded.LensPage === "function"
  ) {
    return preloaded;
  }
  const promise = new Promise<LensBundleExports>((resolve, reject) => {
    const jsFile = `pages/protocol-${lens}.js`;
    const script = document.createElement("script");
    let settled = false;
    const finish = (failed: boolean) => {
      if (settled) return;
      settled = true;
      clearTimeout(timer);
      script.onload = script.onerror = null;
      const entry = runtime.ApplicationAtlasProtocolLenses?.[lens];
      if (
        !failed &&
        entry?.assetVersion === version &&
        typeof entry.LensPage === "function"
      ) {
        resolve(entry);
      } else {
        script.remove();
        reject(
          new Error(
            `Protocol lens "${lens}" asset is unavailable or from a different app version.`,
          ),
        );
      }
    };
    const timer = setTimeout(() => finish(true), 10000);
    script.async = true;
    script.onload = () => finish(false);
    script.onerror = () => finish(true);
    try {
      script.src = resolveStaticUrl(jsFile, version, staticUrlFor);
      document.head.append(script);
    } catch {
      finish(true);
    }
  }).catch((error: unknown) => {
    loaded.delete(lens);
    throw error;
  });
  loaded.set(lens, promise);
  return promise;
}

export async function loadProtocolLensComponent(
  lens: ProtocolLensId,
  devLoader?: () => Promise<ComponentType<ProtocolLensComponentProps>>,
  expectedVersion?: string,
  staticUrlFor?: (file: string, version: string) => string,
): Promise<ComponentType<ProtocolLensComponentProps>> {
  const bundle = await loadProtocolLensBundle(
    lens,
    devLoader
      ? async () => ({
          assetVersion: "development",
          LensPage: await devLoader(),
        })
      : undefined,
    expectedVersion,
    staticUrlFor,
  );
  return bundle.LensPage;
}
