import * as React from "react";
import * as jsxRuntime from "react/jsx-runtime";
import { loadVersionedAssetPair } from "./optionalAssetLoader";
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
import type { ChangeTimelineInspectionProps } from "./changeCorrelation/ChangeTimelineInspection";

type Runtime = typeof globalThis & {
  ApplicationAtlasHistory?: {
    assetVersion: string;
    ChangeTimelineInspection: React.ComponentType<ChangeTimelineInspectionProps>;
  };
  __AtlasHistoryHost?: unknown;
  __ADM_FORCE_SPLUNK_BUILD__?: boolean;
};
type HistoryUi = NonNullable<Runtime["ApplicationAtlasHistory"]>;
let pending: Promise<HistoryUi> | undefined;
const HISTORY_ASSET_ERROR = "History unavailable.";

export function loadHistoryUi(): Promise<HistoryUi> {
  const runtime = globalThis as Runtime;
  if (!__ADM_SPLUNK_BUILD__ && !runtime.__ADM_FORCE_SPLUNK_BUILD__)
    return import("./history-entry").then((module): HistoryUi => ({
      assetVersion: "development",
      ChangeTimelineInspection: module.ChangeTimelineInspection,
    }));
  if (pending) return pending;
  if (!runtime.__AtlasHistoryHost)
    Object.defineProperty(runtime, "__AtlasHistoryHost", {
      value: Object.freeze({
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
      }),
    });
  pending = new Promise((resolve, reject) => {
    loadVersionedAssetPair({
      javascript: "pages/history.js",
      stylesheet: "history.css",
      version: __ADM_HISTORY_ASSET_VERSION__,
    })
      .then(() => {
        const ui = runtime.ApplicationAtlasHistory;
        if (
          !ui ||
          ui.assetVersion !== __ADM_HISTORY_ASSET_VERSION__ ||
          typeof ui.ChangeTimelineInspection !== "function"
        ) {
          reject(new Error("History unavailable or stale."));
        } else resolve(ui);
      })
      .catch(() => reject(new Error(HISTORY_ASSET_ERROR)));
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
  return error ? <p role="alert">{error}</p> : null;
}
