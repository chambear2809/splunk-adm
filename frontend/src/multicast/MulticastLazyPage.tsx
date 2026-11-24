import * as React from "react";
import * as jsxRuntime from "react/jsx-runtime";
import { createStaticURL } from "@splunk/splunk-utils/url";
import { validateIndexName } from "../data/deploymentHealth";
import { fingerprint, isObject, literal } from "../data/evidence";
import { multicastConfigClient } from "../data/evidenceConfig";
import { optionalJobs } from "../data/optionalJobs";
import {
  SearchAccessDeniedError,
  requireNoSearchErrors,
} from "../data/searchClient";
import type { MulticastPage } from "./MulticastPage";

type Ui = { assetVersion: string; MulticastPage: typeof MulticastPage };
type Runtime = typeof globalThis & {
  ApplicationAtlasMulticast?: Ui;
  __AtlasMulticastHost?: { assetVersion: string };
};
let pending: Promise<typeof MulticastPage> | undefined;
function assetUrl(file: "pages/multicast.js" | "multicast.css") {
  const url = new URL(createStaticURL(`app/splunk_adm/${file}`), location.href);
  if (
    url.origin !== location.origin ||
    !url.pathname.endsWith(`/app/splunk_adm/${file}`)
  )
    throw new Error("The multicast asset origin could not be verified.");
  url.searchParams.set("v", __ADM_MULTICAST_ASSET_VERSION__);
  return url.href;
}
export async function loadMulticastPage() {
  if (!__ADM_SPLUNK_BUILD__)
    return (await import("./MulticastPage")).MulticastPage;
  if (pending) return pending;
  const runtime = globalThis as Runtime;
  const version = __ADM_MULTICAST_ASSET_VERSION__;
  if (
    runtime.__AtlasMulticastHost &&
    runtime.__AtlasMulticastHost.assetVersion !== version
  )
    throw new Error(
      "The multicast host belongs to a different app version. Reload the page.",
    );
  if (!runtime.__AtlasMulticastHost)
    Object.defineProperty(runtime, "__AtlasMulticastHost", {
      value: Object.freeze({
        assetVersion: version,
        react: React,
        jsxRuntime,
        deploymentHealth: { validateIndexName },
        evidence: { fingerprint, isObject, literal },
        evidenceConfig: { multicastConfigClient },
        optionalJobs: { optionalJobs },
        searchClient: { SearchAccessDeniedError, requireNoSearchErrors },
      }),
    });
  pending = new Promise<typeof MulticastPage>((resolve, reject) => {
    const script = document.createElement("script"),
      style = document.createElement("link");
    let loaded = 0,
      settled = false;
    const finish = (failed: boolean) => {
      if (settled || (!failed && ++loaded < 2)) return;
      settled = true;
      clearTimeout(timer);
      script.onload = script.onerror = style.onload = style.onerror = null;
      const ui = runtime.ApplicationAtlasMulticast;
      if (
        !failed &&
        ui?.assetVersion === version &&
        typeof ui.MulticastPage === "function"
      )
        resolve(ui.MulticastPage);
      else {
        script.remove();
        style.remove();
        reject(
          new Error(
            "Multicast assets are unavailable or from a different app version.",
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
      script.src = assetUrl("pages/multicast.js");
      style.href = assetUrl("multicast.css");
      document.head.append(style, script);
    } catch {
      finish(true);
    }
  }).catch((error: unknown) => {
    pending = undefined;
    throw error;
  });
  return pending;
}
export function MulticastLazyPage(
  props: React.ComponentProps<typeof MulticastPage>,
) {
  const [page, setPage] = React.useState<typeof MulticastPage>();
  const [error, setError] = React.useState<string>();
  const [revision, setRevision] = React.useState(0);
  React.useEffect(() => {
    let cancelled = false;
    loadMulticastPage()
      .then((component) => {
        if (!cancelled) setPage(() => component);
      })
      .catch((reason: unknown) => {
        if (!cancelled)
          setError(
            reason instanceof Error
              ? reason.message
              : "Multicast could not load.",
          );
      });
    return () => {
      cancelled = true;
    };
  }, [revision]);
  if (page) return React.createElement(page, props);
  if (error)
    return (
      <main role="alert">
        <p>{error}</p>
        <button
          type="button"
          onClick={() => {
            setError(undefined);
            setRevision((value) => value + 1);
          }}
        >
          Retry
        </button>
      </main>
    );
  return <main role="status">Loading multicast investigation…</main>;
}
