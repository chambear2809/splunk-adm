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
  js,
  css,
  version,
  validate,
}: {
  js: string;
  css: string;
  version: string;
  validate?: () => boolean;
}): Promise<void> {
  return new Promise((resolve, reject) => {
    const script = document.createElement("script");
    const style = document.createElement("link");
    let ready = 0;
    let settled = false;
    const finish = (failed = false) => {
      if (!failed && ready >= 2 && validate && !validate()) failed = true;
      if (settled || (!failed && ready < 2)) return;
      settled = true;
      clearTimeout(timer);
      script.onload = script.onerror = style.onload = style.onerror = null;
      if (failed) {
        script.remove();
        style.remove();
        reject(new Error("Optional asset unavailable."));
      } else resolve();
    };
    script.async = true;
    const timer = setTimeout(() => finish(true), 10_000);
    style.rel = "stylesheet";
    script.onload = style.onload = () => {
      ready++;
      finish();
    };
    script.onerror = style.onerror = () => finish(true);
    try {
      script.src = versionedAssetUrl(js, version, location.href);
      style.href = versionedAssetUrl(css, version, location.href);
      document.head.append(style, script);
    } catch {
      finish(true);
    }
  });
}
