import * as React from "react";
import * as jsxRuntime from "react/jsx-runtime";
import { createStaticURL } from "@splunk/splunk-utils/url";
import type { ImpactPage } from "./ImpactPage";
import { SearchAccessDeniedError } from "../data/searchClient";
import { downloadBlob } from "../download";
import { plural, prettyBytes } from "../glossary";
import { TimePicker } from "../map/TimePicker";
import { ExploreTabs, deviceURL, traceURL } from "../pages/ExploreTools";
import { pageURL } from "../app/urlState";
import { VirtualTable } from "../scale/VirtualTable";
import { JourneyLazyEvidence } from "../JourneyLazyEvidence";
import {
  emptyTopology,
  indexTopology,
  parseObserver,
  rowsToTopology,
  fabricLayersMulti,
  resolveDevice,
  virtualPortFor,
} from "../topology";
import { findDevices } from "../trace/traceModel";
import { parsePathEvidenceRows } from "../trace/pathEvidence";
import { isSafeTime, resolveTime } from "../data/timeBounds";
import { csvRow } from "../csv";

type ImpactUi = { assetVersion: string; ImpactPage: typeof ImpactPage };
type ImpactRuntime = typeof globalThis & {
  ApplicationAtlasImpact?: ImpactUi;
  __AtlasImpactHost?: { assetVersion: string };
};
let pending: Promise<typeof ImpactPage> | undefined;
function assetUrl(file: "pages/impact.js" | "impact.css") {
  const url = new URL(createStaticURL(`app/splunk_adm/${file}`), location.href);
  if (
    url.origin !== location.origin ||
    !url.pathname.endsWith(`/app/splunk_adm/${file}`)
  )
    throw new Error("The Impact asset origin could not be verified.");
  url.searchParams.set("v", __ADM_IMPACT_ASSET_VERSION__);
  return url.href;
}

export async function loadImpactPage() {
  if (!__ADM_SPLUNK_BUILD__) return (await import("./ImpactPage")).ImpactPage;
  if (pending) return pending;
  const runtime = globalThis as ImpactRuntime;
  const version = __ADM_IMPACT_ASSET_VERSION__;
  if (
    runtime.__AtlasImpactHost &&
    runtime.__AtlasImpactHost.assetVersion !== version
  )
    throw new Error(
      "The Impact host belongs to a different app version. Reload the page.",
    );
  if (!runtime.__AtlasImpactHost)
    Object.defineProperty(runtime, "__AtlasImpactHost", {
      value: Object.freeze({
        assetVersion: version,
        react: React,
        jsxRuntime,
        searchClient: { SearchAccessDeniedError },
        download: { downloadBlob },
        glossary: { plural, prettyBytes },
        timePicker: { TimePicker },
        explore: { ExploreTabs, deviceURL, traceURL },
        urlState: { pageURL },
        virtualTable: { VirtualTable },
        journey: { JourneyLazyEvidence },
        topology: {
          emptyTopology,
          indexTopology,
          parseObserver,
          rowsToTopology,
          fabricLayersMulti,
          resolveDevice,
          virtualPortFor,
        },
        traceModel: { findDevices },
        pathEvidence: { parsePathEvidenceRows },
        timeBounds: { isSafeTime, resolveTime },
        csv: { csvRow },
      }),
    });

  pending = new Promise<typeof ImpactPage>((resolve, reject) => {
    const script = document.createElement("script");
    const style = document.createElement("link");
    let loaded = 0;
    let settled = false;
    const finish = (failed: boolean) => {
      if (settled || (!failed && ++loaded < 2)) return;
      settled = true;
      clearTimeout(timer);
      script.onload = script.onerror = style.onload = style.onerror = null;
      const ui = runtime.ApplicationAtlasImpact;
      if (
        !failed &&
        ui?.assetVersion === version &&
        typeof ui.ImpactPage === "function"
      ) {
        resolve(ui.ImpactPage);
      } else {
        script.remove();
        style.remove();
        reject(
          new Error(
            "Impact assets are unavailable or from a different app version.",
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
      script.src = assetUrl("pages/impact.js");
      style.href = assetUrl("impact.css");
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

export function ImpactLazyPage(props: React.ComponentProps<typeof ImpactPage>) {
  const [Page, setPage] = React.useState<typeof ImpactPage>();
  const [error, setError] = React.useState<string>();
  const [attempt, setAttempt] = React.useState(0);
  React.useEffect(() => {
    let cancelled = false;
    void loadImpactPage().then(
      (page) => {
        if (!cancelled) setPage(() => page);
      },
      (reason: unknown) => {
        if (!cancelled)
          setError(
            reason instanceof Error ? reason.message : "Impact could not load.",
          );
      },
    );
    return () => {
      cancelled = true;
    };
  }, [attempt]);
  if (Page) return <Page {...props} />;
  return (
    <main className="atlas-page">
      <h1>Impact</h1>
      {error ? (
        <>
          <p role="alert">{error}</p>
          <button
            type="button"
            className="atlas-button"
            onClick={() => {
              setError(undefined);
              setAttempt((previous) => previous + 1);
            }}
          >
            Retry
          </button>
        </>
      ) : (
        <p role="status">Loading Impact…</p>
      )}
    </main>
  );
}
