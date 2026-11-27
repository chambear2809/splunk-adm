import * as React from "react";
import * as jsxRuntime from "react/jsx-runtime";
import { loadVersionedAssetPair } from "../optionalAssetLoader";
import { LazyChangeTimelineInspection } from "../HistoryLazyInspection";
import { JourneyLazyEvidence } from "../JourneyLazyEvidence";
import { fitText } from "../MapView";
import { RoutingScopeSelect } from "../RoutingScopeSelect";
import { EndpointCombobox } from "../SuggestCombobox";
import { ThousandEyesLazyInspection } from "../ThousandEyesLazyInspection";
import { pageURL, parseUrlState, stateParams } from "../app/urlState";
import { csvRow } from "../csv";
import {
  APPDYNAMICS_COVERAGE,
  loadAppDynamicsEvidence,
} from "../data/appdynamicsEvidence";
import { indexNames, validateIndexName } from "../data/deploymentHealth";
import {
  EVIDENCE_LIMITS,
  fingerprint,
  isObject,
  literal,
  normalizeIp,
  routingScope,
  scopedAddressPredicate,
  validText,
  validateDnsResult,
  validateSelection,
  validateWindow,
} from "../data/evidence";
import { evidenceConfigClient } from "../data/evidenceConfig";
import { useHealthStatus } from "../data/healthStatus";
import { optionalJobs } from "../data/optionalJobs";
import {
  buildProxySearch,
  normalizeProxyEvidence,
  PROXY_COVERAGE,
  proxySearchWindow,
} from "../data/proxyEvidence";
import { useRoutingScopes } from "../data/routingScopes";
import { requireNoSearchErrors } from "../data/searchClient";
import { loadSupplementalEvidence } from "../data/supplementalEvidence";
import { downloadBlob } from "../download";
import {
  ECOSYSTEM_EVIDENCE_SOURCES,
  LazyEcosystemEvidencePanel,
} from "../ecosystem/EcosystemLazyEvidence";
import type { MapDnsInspection } from "../MapDnsInspection";
import type { EndpointsView, EndpointsViewProps } from "./endpoints-entry";

type EndpointsUi = {
  assetVersion: string;
  EndpointsView: typeof EndpointsView;
  MapDnsInspection: typeof MapDnsInspection;
};
type Runtime = typeof globalThis & {
  ApplicationAtlasEndpoints?: EndpointsUi;
  __AtlasEndpointsHost?: { assetVersion: string };
  __ADM_FORCE_SPLUNK_BUILD__?: boolean;
};

let pending: Promise<EndpointsUi> | undefined;

export function loadEndpointsUi(): Promise<EndpointsUi> {
  const runtime = globalThis as Runtime;
  if (!__ADM_SPLUNK_BUILD__ && !runtime.__ADM_FORCE_SPLUNK_BUILD__)
    return import("./endpoints-entry").then((module): EndpointsUi => ({
      assetVersion: "development",
      EndpointsView: module.EndpointsView,
      MapDnsInspection: module.MapDnsInspection,
    }));
  if (pending) return pending;
  const version = __ADM_ENDPOINTS_ASSET_VERSION__;
  if (
    runtime.__AtlasEndpointsHost &&
    runtime.__AtlasEndpointsHost.assetVersion !== version
  )
    return Promise.reject(
      new Error(
        "The Endpoints host belongs to a different app version. Reload the page.",
      ),
    );
  if (!runtime.__AtlasEndpointsHost)
    Object.defineProperty(runtime, "__AtlasEndpointsHost", {
      value: Object.freeze({
        assetVersion: version,
        react: React,
        jsxRuntime,
        history: Object.freeze({ LazyChangeTimelineInspection }),
        journeys: Object.freeze({ JourneyLazyEvidence }),
        mapView: Object.freeze({ fitText }),
        routingScopeSelect: Object.freeze({ RoutingScopeSelect }),
        suggestCombobox: Object.freeze({ EndpointCombobox }),
        thousandEyes: Object.freeze({ ThousandEyesLazyInspection }),
        urlState: Object.freeze({ pageURL, parseUrlState, stateParams }),
        csv: Object.freeze({ csvRow }),
        appdynamicsEvidence: Object.freeze({
          APPDYNAMICS_COVERAGE,
          loadAppDynamicsEvidence,
        }),
        deploymentHealth: Object.freeze({ indexNames, validateIndexName }),
        evidence: Object.freeze({
          EVIDENCE_LIMITS,
          fingerprint,
          isObject,
          literal,
          normalizeIp,
          routingScope,
          scopedAddressPredicate,
          validText,
          validateDnsResult,
          validateSelection,
          validateWindow,
        }),
        evidenceConfig: Object.freeze({ evidenceConfigClient }),
        healthStatus: Object.freeze({ useHealthStatus }),
        optionalJobs: Object.freeze({ optionalJobs }),
        proxyEvidence: Object.freeze({
          buildProxySearch,
          normalizeProxyEvidence,
          PROXY_COVERAGE,
          proxySearchWindow,
        }),
        routingScopes: Object.freeze({ useRoutingScopes }),
        searchClient: Object.freeze({ requireNoSearchErrors }),
        supplementalEvidence: Object.freeze({ loadSupplementalEvidence }),
        download: Object.freeze({ downloadBlob }),
        ecosystem: Object.freeze({
          ECOSYSTEM_EVIDENCE_SOURCES,
          LazyEcosystemEvidencePanel,
        }),
      }),
    });
  pending = loadVersionedAssetPair({
    js: "pages/endpoints.js",
    css: "endpoints.css",
    version,
    validate: () => {
      const ui = runtime.ApplicationAtlasEndpoints;
      return (
        ui?.assetVersion === version &&
        typeof ui.EndpointsView === "function" &&
        typeof ui.MapDnsInspection === "function"
      );
    },
  })
    .then(() => runtime.ApplicationAtlasEndpoints!)
    .catch((error: unknown) => {
      pending = undefined;
      throw error;
    });
  return pending;
}

export function EndpointsLazyPage(props: EndpointsViewProps) {
  const [ui, setUi] = React.useState<EndpointsUi>();
  const [error, setError] = React.useState<string>();
  const [attempt, setAttempt] = React.useState(0);
  React.useEffect(() => {
    let active = true;
    void loadEndpointsUi().then(
      (next) => {
        if (active) setUi(next);
      },
      (reason: unknown) => {
        if (active)
          setError(
            reason instanceof Error
              ? reason.message
              : "Endpoint investigation could not load. Reload the page to retry.",
          );
      },
    );
    return () => {
      active = false;
    };
  }, [attempt]);
  if (ui) return <ui.EndpointsView {...props} />;
  return error ? (
    <div role="alert">
      <p>{error}</p>
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
    </div>
  ) : (
    <p role="status">Loading endpoint investigation…</p>
  );
}

export function MapDnsLazyInspection(
  props: React.ComponentProps<typeof MapDnsInspection>,
) {
  const edge =
    props.selection.kind === "edge"
      ? props.index.edge.get(props.selection.id)
      : undefined;
  const node =
    props.selection.kind === "node"
      ? props.index.node.get(props.selection.id)
      : edge
        ? props.index.node.get(edge.source)
        : undefined;
  const supported =
    props.live &&
    !!props.client &&
    !!node &&
    ["workload", "endpoint", "client"].includes(node.kind) &&
    (!edge ||
      ["communicates_with", "traffic_observation"].includes(edge.relationship));
  const [ui, setUi] = React.useState<EndpointsUi>();
  const [error, setError] = React.useState<string>();
  const [attempt, setAttempt] = React.useState(0);
  React.useEffect(() => {
    if (!supported) return;
    let active = true;
    void loadEndpointsUi().then(
      (next) => {
        if (active) setUi(next);
      },
      (reason: unknown) => {
        if (active)
          setError(
            reason instanceof Error
              ? reason.message
              : "Optional DNS investigation could not load. Reload the page to retry.",
          );
      },
    );
    return () => {
      active = false;
    };
  }, [supported, attempt]);
  if (!supported) return null;
  if (ui) return <ui.MapDnsInspection {...props} />;
  return (
    <section className="inspector-body" aria-label="DNS selection context">
      <h3>Optional DNS investigation</h3>
      {error ? (
        <>
          <p role="alert">{error}</p>
          <button
            type="button"
            onClick={() => {
              setError(undefined);
              setAttempt((previous) => previous + 1);
            }}
          >
            Retry
          </button>
        </>
      ) : (
        <p role="status">Loading optional DNS investigation…</p>
      )}
    </section>
  );
}
