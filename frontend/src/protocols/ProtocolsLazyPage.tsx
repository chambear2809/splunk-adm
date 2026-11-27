import * as React from "react";
import * as jsxRuntime from "react/jsx-runtime";
import { createStaticURL } from "@splunk/splunk-utils/url";
import { validateIndexName } from "../data/deploymentHealth";
import {
  fingerprint,
  isObject,
  literal,
  normalizeIp,
  routingScope,
  validText,
} from "../data/evidence";
import { protocolConfigClient } from "../data/evidenceConfig";
import { optionalJobs } from "../data/optionalJobs";
import {
  SearchAccessDeniedError,
  requireNoSearchErrors,
} from "../data/searchClient";
import { pageURL, URL_STATE_CHANGED } from "../app/urlState";
import type { ProtocolsPage } from "./ProtocolsPage";

type Ui = { assetVersion: string; ProtocolsPage: typeof ProtocolsPage };
type Runtime = typeof globalThis & {
  ApplicationAtlasProtocolsCore?: Ui;
  __AtlasProtocolsHost?: { assetVersion: string };
};
let pending: Promise<typeof ProtocolsPage> | undefined;

function assetUrl(file: "pages/protocols-core.js" | "protocols-core.css") {
  const url = new URL(createStaticURL(`app/splunk_adm/${file}`), location.href);
  if (
    url.origin !== location.origin ||
    !url.pathname.endsWith(`/app/splunk_adm/${file}`)
  )
    throw new Error("The protocols asset origin could not be verified.");
  url.searchParams.set("v", __ADM_PROTOCOLS_CORE_ASSET_VERSION__);
  return url.href;
}

export async function loadProtocolsPage() {
  if (!__ADM_SPLUNK_BUILD__)
    return (await import("./ProtocolsPage")).ProtocolsPage;
  if (pending) return pending;
  const runtime = globalThis as Runtime;
  const version = __ADM_PROTOCOLS_CORE_ASSET_VERSION__;
  if (
    runtime.__AtlasProtocolsHost &&
    runtime.__AtlasProtocolsHost.assetVersion !== version
  )
    throw new Error(
      "The protocols host belongs to a different app version. Reload the page.",
    );
  if (!runtime.__AtlasProtocolsHost)
    Object.defineProperty(runtime, "__AtlasProtocolsHost", {
      value: Object.freeze({
        assetVersion: version,
        react: React,
        jsxRuntime,
        deploymentHealth: { validateIndexName },
        evidence: {
          fingerprint,
          isObject,
          literal,
          normalizeIp,
          routingScope,
          validText,
        },
        evidenceConfig: { protocolConfigClient },
        optionalJobs: { optionalJobs },
        searchClient: { SearchAccessDeniedError, requireNoSearchErrors },
        urlState: { pageURL, URL_STATE_CHANGED },
      }),
    });
  pending = new Promise<typeof ProtocolsPage>((resolve, reject) => {
    const script = document.createElement("script"),
      style = document.createElement("link");
    let loaded = 0,
      settled = false;
    const finish = (failed: boolean) => {
      if (settled || (!failed && ++loaded < 2)) return;
      settled = true;
      clearTimeout(timer);
      script.onload = script.onerror = style.onload = style.onerror = null;
      const ui = runtime.ApplicationAtlasProtocolsCore;
      if (
        !failed &&
        ui?.assetVersion === version &&
        typeof ui.ProtocolsPage === "function"
      )
        resolve(ui.ProtocolsPage);
      else {
        script.remove();
        style.remove();
        reject(
          new Error(
            "Protocols assets are unavailable or from a different app version.",
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
      script.src = assetUrl("pages/protocols-core.js");
      style.href = assetUrl("protocols-core.css");
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

export function ProtocolsLazyPage(
  props: React.ComponentProps<typeof ProtocolsPage>,
) {
  const [page, setPage] = React.useState<typeof ProtocolsPage>();
  const [error, setError] = React.useState<string>();
  const [revision, setRevision] = React.useState(0);
  React.useEffect(() => {
    let cancelled = false;
    loadProtocolsPage()
      .then((component) => {
        if (!cancelled) setPage(() => component);
      })
      .catch((reason: unknown) => {
        if (!cancelled)
          setError(
            reason instanceof Error
              ? reason.message
              : "Protocols workbench could not load.",
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
  return <main role="status">Loading protocols workbench…</main>;
}
