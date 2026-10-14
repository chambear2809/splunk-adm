import { getUserTheme } from "@splunk/splunk-utils/themes";
import { createStaticURL } from "@splunk/splunk-utils/url";

type ThemeApi = { getTheme(): Promise<string> };
type AmdRequire = (
  deps: string[],
  loaded: (module: unknown) => void,
  failed: (error: unknown) => void,
) => void;

export interface ThemeHost {
  amdRequire?: AmdRequire;
  globalApi: () => unknown;
  staticURL: (path: string) => string;
  fallback: () => Promise<string>;
}

const isThemeApi = (value: unknown): value is ThemeApi =>
  !!value && typeof (value as ThemeApi).getTheme === "function";

function browserHost(): ThemeHost {
  const w = window as unknown as {
    require?: AmdRequire & { amd?: unknown };
    define?: { amd?: unknown };
    __get_theme__?: unknown;
  };
  return {
    amdRequire:
      typeof w.require === "function" && w.define?.amd ? w.require : undefined,
    globalApi: () => w.__get_theme__,
    staticURL: (path) => createStaticURL(path),
    fallback: getUserTheme,
  };
}

// On Simple XML pages RequireJS defines `define.amd`, so Splunk's theme API
// bundle can register as an AMD module instead of setting window.__get_theme__,
// and splunk-utils' getUserTheme() silently falls back to "enterprise".
export function resolveUserTheme(host: ThemeHost = browserHost()) {
  const { amdRequire } = host;
  if (!amdRequire) return host.fallback();
  return new Promise<string>((resolve) => {
    amdRequire(
      [host.staticURL("build/api/get_theme.js")],
      (module) => {
        const api = isThemeApi(module) ? module : host.globalApi();
        if (isThemeApi(api)) api.getTheme().then(resolve, () => resolve(""));
        else host.fallback().then(resolve);
      },
      () => {
        host.fallback().then(resolve);
      },
    );
  }).then((theme) => theme || host.fallback());
}
