import type { ComponentType } from "react";
import type { ProtocolLensComponentProps, ProtocolLensId } from "./contract";

type LensBundleExports = {
  assetVersion: string;
  LensPage: ComponentType<ProtocolLensComponentProps>;
};

type Runtime = typeof globalThis & {
  ApplicationAtlasProtocolLenses?: Partial<
    Record<ProtocolLensId, LensBundleExports>
  >;
};

const loaded = new Map<
  ProtocolLensId,
  Promise<ComponentType<ProtocolLensComponentProps>>
>();

/**
 * Loads an optional protocol lens bundle.
 * - In development and tests (`!__ADM_SPLUNK_BUILD__`), delegates to the
 *   registration's dynamic import.
 * - In packaged Splunk builds (`__ADM_SPLUNK_BUILD__`), fails closed unless
 *   `expectedVersion` and `staticUrlFor` are supplied and the loaded IIFE
 *   asset version matches `expectedVersion` exactly.
 */
export async function loadProtocolLensComponent(
  lens: ProtocolLensId,
  devLoader?: () => Promise<ComponentType<ProtocolLensComponentProps>>,
  expectedVersion?: string,
  staticUrlFor?: (file: string) => string,
): Promise<ComponentType<ProtocolLensComponentProps>> {
  if (!__ADM_SPLUNK_BUILD__) {
    if (!devLoader)
      throw new Error(`Protocol lens "${lens}" is not registered yet.`);
    return devLoader();
  }
  if (!expectedVersion || !staticUrlFor) {
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
    preloaded.assetVersion === expectedVersion &&
    typeof preloaded.LensPage === "function"
  ) {
    return preloaded.LensPage;
  }
  const promise = new Promise<ComponentType<ProtocolLensComponentProps>>(
    (resolve, reject) => {
      const jsFile = `pages/protocol-${lens}.js`;
      const cssFile = `protocol-${lens}.css`;
      const script = document.createElement("script");
      const style = document.createElement("link");
      let count = 0;
      let settled = false;
      const finish = (failed: boolean) => {
        if (settled || (!failed && ++count < 2)) return;
        settled = true;
        clearTimeout(timer);
        script.onload = script.onerror = style.onload = style.onerror = null;
        const entry = runtime.ApplicationAtlasProtocolLenses?.[lens];
        if (
          !failed &&
          entry?.assetVersion === expectedVersion &&
          typeof entry.LensPage === "function"
        ) {
          resolve(entry.LensPage);
        } else {
          script.remove();
          style.remove();
          reject(
            new Error(
              `Protocol lens "${lens}" asset is unavailable or from a different app version.`,
            ),
          );
        }
      };
      const timer = setTimeout(() => finish(true), 10000);
      script.async = true;
      style.rel = "stylesheet";
      script.onload = style.onload = () => finish(false);
      script.onerror = style.onerror = () => finish(true);
      try {
        script.src = staticUrlFor(jsFile);
        style.href = staticUrlFor(cssFile);
        document.head.append(style, script);
      } catch {
        finish(true);
      }
    },
  ).catch((error: unknown) => {
    loaded.delete(lens);
    throw error;
  });
  loaded.set(lens, promise);
  return promise;
}
