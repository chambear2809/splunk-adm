import { createStaticURL } from "@splunk/splunk-utils/url";

export function versionedAssetUrl(
  file: string,
  version: string,
  locationHref: string,
  staticPath = createStaticURL(`app/splunk_adm/${file}`),
): string {
  const url = new URL(staticPath, locationHref);
  if (
    url.origin !== new URL(locationHref).origin ||
    !url.pathname.endsWith(`/app/splunk_adm/${file}`)
  )
    throw new Error("Optional asset origin could not be verified.");
  url.searchParams.set("v", version);
  return url.href;
}

export function loadVersionedAssetPair({
  javascript,
  stylesheet,
  version,
  timeoutMs = 10_000,
}: {
  javascript: string;
  stylesheet: string;
  version: string;
  timeoutMs?: number;
}): Promise<void> {
  return new Promise((resolve, reject) => {
    const script = document.createElement("script");
    const style = document.createElement("link");
    let scriptReady = false;
    let styleReady = false;
    let settled = false;
    const finish = (failed = false) => {
      if (settled || (!failed && (!scriptReady || !styleReady))) return;
      settled = true;
      clearTimeout(timer);
      script.onload = script.onerror = style.onload = style.onerror = null;
      if (failed) {
        script.remove();
        style.remove();
        reject(new Error("Optional asset unavailable or stale."));
      } else resolve();
    };
    const timer = setTimeout(() => finish(true), timeoutMs);
    script.async = true;
    style.rel = "stylesheet";
    script.onload = () => {
      scriptReady = true;
      finish();
    };
    style.onload = () => {
      styleReady = true;
      finish();
    };
    script.onerror = style.onerror = () => finish(true);
    try {
      script.src = versionedAssetUrl(javascript, version, location.href);
      style.href = versionedAssetUrl(stylesheet, version, location.href);
      document.head.append(style, script);
    } catch {
      finish(true);
    }
  });
}
