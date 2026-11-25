import * as React from "react";
import * as jsxRuntime from "react/jsx-runtime";
import { createStaticURL } from "@splunk/splunk-utils/url";
import { routingScope } from "./data/evidence";
import {
  configuredHttpsOrigin,
  evidenceConfigClient,
} from "./data/evidenceConfig";
import {
  requireNoSearchErrors,
  SearchAccessDeniedError,
} from "./data/searchClient";
import { indexNames, validateIndexName } from "./data/deploymentHealth";
import { optionalJobs } from "./data/optionalJobs";
import * as canonicalJson from "./changeCorrelation/canonicalJson";
import type { ChangeTimelineInspectionProps } from "./changeCorrelation/ChangeTimelineInspection";

type Runtime = typeof globalThis & {
  ApplicationAtlasHistory?: {
    assetVersion: string;
    ChangeTimelineInspection: React.ComponentType<ChangeTimelineInspectionProps>;
  };
  __AtlasHistoryHost?: unknown;
};
type HistoryUi = NonNullable<Runtime["ApplicationAtlasHistory"]>;
let pending: Promise<HistoryUi> | undefined;

export function historyAssetUrl(
  file: "pages/history.js" | "history.css",
  version: string,
  locationHref: string,
  staticPath = createStaticURL(`app/splunk_adm/${file}`),
): string {
  const value = new URL(staticPath, locationHref);
  const expectedPath = `/app/splunk_adm/${file}`;
  if (
    value.origin !== new URL(locationHref).origin ||
    !value.pathname.endsWith(expectedPath)
  )
    throw new Error("History asset origin could not be verified.");
  value.searchParams.set("v", version);
  return value.href;
}

export function loadHistoryUi(): Promise<HistoryUi> {
  if (!__ADM_SPLUNK_BUILD__)
    return import("./history-entry").then((module): HistoryUi => ({
      assetVersion: "development",
      ChangeTimelineInspection: module.ChangeTimelineInspection,
    }));
  if (pending) return pending;
  const runtime = globalThis as Runtime;
  if (!runtime.__AtlasHistoryHost)
    Object.defineProperty(runtime, "__AtlasHistoryHost", {
      value: Object.freeze({
        assetVersion: __ADM_HISTORY_ASSET_VERSION__,
        react: React,
        jsxRuntime,
        evidence: Object.freeze({ routingScope }),
        evidenceConfig: Object.freeze({
          configuredHttpsOrigin,
          evidenceConfigClient,
        }),
        searchClient: Object.freeze({
          requireNoSearchErrors,
          SearchAccessDeniedError,
        }),
        deploymentHealth: Object.freeze({ indexNames, validateIndexName }),
        optionalJobs: Object.freeze({ optionalJobs }),
        canonicalJson,
      }),
    });
  pending = new Promise((resolve, reject) => {
    const script = document.createElement("script");
    const style = document.createElement("link");
    let scriptReady = false;
    let styleReady = false;
    const timer = setTimeout(
      () => reject(new Error("Configuration history assets are unavailable.")),
      10_000,
    );
    const finish = () => {
      if (!scriptReady || !styleReady) return;
      clearTimeout(timer);
      const ui = runtime.ApplicationAtlasHistory;
      if (
        !ui ||
        ui.assetVersion !== __ADM_HISTORY_ASSET_VERSION__ ||
        typeof ui.ChangeTimelineInspection !== "function"
      ) {
        reject(
          new Error(
            "Configuration history assets are unavailable or from another app version.",
          ),
        );
      } else resolve(ui);
    };
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
    script.onerror = style.onerror = () =>
      reject(new Error("Configuration history assets are unavailable."));
    try {
      script.src = historyAssetUrl(
        "pages/history.js",
        __ADM_HISTORY_ASSET_VERSION__,
        location.href,
      );
      style.href = historyAssetUrl(
        "history.css",
        __ADM_HISTORY_ASSET_VERSION__,
        location.href,
      );
      document.head.append(style, script);
    } catch {
      reject(new Error("Configuration history assets are unavailable."));
    }
  }).catch((error): never => {
    pending = undefined;
    throw error;
  }) as Promise<HistoryUi>;
  return pending;
}

export function LazyChangeTimelineInspection(
  props: ChangeTimelineInspectionProps,
) {
  const [ui, setUi] = React.useState<HistoryUi>();
  const [error, setError] = React.useState<string>();
  React.useEffect(() => {
    let active = true;
    void loadHistoryUi()
      .then((next) => active && setUi(next))
      .catch(
        (reason) =>
          active &&
          setError(
            reason instanceof Error
              ? reason.message
              : "Configuration history unavailable.",
          ),
      );
    return () => {
      active = false;
    };
  }, []);
  if (ui) {
    const Component = ui.ChangeTimelineInspection;
    return <Component {...props} />;
  }
  return (
    <section
      className="change-timeline"
      aria-label="Optional configuration change timeline"
    >
      <h3>Configuration change timeline</h3>
      <p role={error ? "alert" : "status"}>
        {error ?? "Loading configuration history…"}
      </p>
    </section>
  );
}
