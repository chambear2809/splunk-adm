import * as React from "react";
import * as jsxRuntime from "react/jsx-runtime";
import ButtonExport from "@splunk/react-ui/Button";
import TextExport from "@splunk/react-ui/Text";
import { getDefaultFetchInit } from "@splunk/splunk-utils/fetch";
import { createRESTURL } from "@splunk/splunk-utils/url";
import { loadVersionedAssetPair } from "../optionalAssetLoader";
import Table from "../SimpleTable";
import { toolkitDefault } from "../app/interop";
import { pageURL, URL_STATE_CHANGED } from "../app/urlState";
import { JourneyLazyEvidence } from "../JourneyLazyEvidence";
import { LazyEcosystemReceiptPanel } from "../ecosystem/EcosystemLazyEvidence";
import {
  evaluatedAt,
  jobRunAssessment,
  jobStatus,
  loadHealth,
  sourceStatus,
} from "../health";
import { useHealthStatus } from "../data/healthStatus";
import {
  DeploymentWriteError,
  ToolkitDeploymentClient,
} from "../data/deploymentClient";
import {
  applicableJobs,
  CISCO_V2_SELECTORS,
  DATA_CONTRACT_SELECTORS,
  defaultExpectations,
  expectationFor,
  indexName,
  indexNames,
  isCoreSource,
  JOB_DEFINITIONS,
  normalizeDefinition,
  SOURCE_DEFINITIONS,
  validateExpectations,
  validateIndexName,
} from "../data/deploymentHealth";
import { observerMappingClient } from "../data/observerMappingClient";
import { requireNoSearchErrors } from "../data/searchClient";
import { isSafeTime, resolveTime, timeError } from "../data/timeBounds";
import { TimePicker } from "../map/TimePicker";
import { formatUtc } from "../time";
import type { AdminView, AdminViewProps } from "./admin-entry";

type AdminUi = {
  assetVersion: string;
  AdminView: typeof AdminView;
};
type Runtime = typeof globalThis & {
  ApplicationAtlasAdmin?: AdminUi;
  __AtlasAdminHost?: { assetVersion: string };
  __ADM_FORCE_SPLUNK_BUILD__?: boolean;
};

let pending: Promise<AdminUi> | undefined;

export function loadAdminUi(): Promise<AdminUi> {
  const runtime = globalThis as Runtime;
  if (!__ADM_SPLUNK_BUILD__ && !runtime.__ADM_FORCE_SPLUNK_BUILD__)
    return import("./admin-entry").then((module): AdminUi => ({
      assetVersion: "development",
      AdminView: module.AdminView,
    }));
  if (pending) return pending;
  const version = __ADM_ADMIN_ASSET_VERSION__;
  if (
    runtime.__AtlasAdminHost &&
    runtime.__AtlasAdminHost.assetVersion !== version
  )
    return Promise.reject(
      new Error(
        "The Admin host belongs to a different app version. Reload the page.",
      ),
    );
  if (!runtime.__AtlasAdminHost)
    Object.defineProperty(runtime, "__AtlasAdminHost", {
      value: Object.freeze({
        assetVersion: version,
        react: React,
        jsxRuntime,
        splunkButton: ButtonExport,
        splunkText: TextExport,
        splunkFetch: Object.freeze({ getDefaultFetchInit }),
        splunkUrl: Object.freeze({ createRESTURL }),
        simpleTable: Table,
        interop: Object.freeze({ toolkitDefault }),
        urlState: Object.freeze({ pageURL, URL_STATE_CHANGED }),
        journeys: Object.freeze({ JourneyLazyEvidence }),
        ecosystem: Object.freeze({ LazyEcosystemReceiptPanel }),
        health: Object.freeze({
          evaluatedAt,
          jobRunAssessment,
          jobStatus,
          loadHealth,
          sourceStatus,
        }),
        healthStatus: Object.freeze({ useHealthStatus }),
        deploymentClient: Object.freeze({
          DeploymentWriteError,
          ToolkitDeploymentClient,
        }),
        deploymentHealth: Object.freeze({
          applicableJobs,
          CISCO_V2_SELECTORS,
          DATA_CONTRACT_SELECTORS,
          defaultExpectations,
          expectationFor,
          indexName,
          indexNames,
          isCoreSource,
          JOB_DEFINITIONS,
          normalizeDefinition,
          SOURCE_DEFINITIONS,
          validateExpectations,
          validateIndexName,
        }),
        observerMappingClient: Object.freeze({ observerMappingClient }),
        searchClient: Object.freeze({ requireNoSearchErrors }),
        timeBounds: Object.freeze({ isSafeTime, resolveTime, timeError }),
        timePicker: Object.freeze({ TimePicker }),
        time: Object.freeze({ formatUtc }),
      }),
    });
  pending = loadVersionedAssetPair({
    js: "pages/admin.js",
    css: "admin.css",
    version,
    validate: () => {
      const ui = runtime.ApplicationAtlasAdmin;
      return ui?.assetVersion === version && typeof ui.AdminView === "function";
    },
  })
    .then(() => runtime.ApplicationAtlasAdmin!)
    .catch((error: unknown) => {
      pending = undefined;
      throw error;
    });
  return pending;
}

export function AdminLazyPage(props: AdminViewProps) {
  const [ui, setUi] = React.useState<AdminUi>();
  const [error, setError] = React.useState<string>();
  const [attempt, setAttempt] = React.useState(0);
  React.useEffect(() => {
    let active = true;
    void loadAdminUi().then(
      (next) => {
        if (active) setUi(next);
      },
      (reason: unknown) => {
        if (active)
          setError(
            reason instanceof Error
              ? reason.message
              : "Admin tools could not load. Reload the page to retry.",
          );
      },
    );
    return () => {
      active = false;
    };
  }, [attempt]);
  if (ui) return <ui.AdminView {...props} />;
  const label = props.tab === "setup" ? "Setup" : "Data health";
  return (
    <main className="atlas-page atlas-admin">
      <h1>{label}</h1>
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
        <p role="status">Loading {label}…</p>
      )}
    </main>
  );
}
