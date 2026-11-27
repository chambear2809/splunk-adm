import * as React from "react";
import * as jsxRuntime from "react/jsx-runtime";
import { loadVersionedAssetPair } from "../optionalAssetLoader";
import { indexNames } from "../data/deploymentHealth";
import {
  EVIDENCE_LIMITS,
  fingerprint,
  isObject,
  literal,
  routingScope,
  validText,
  validateServiceHealthSelection,
} from "../data/evidence";
import {
  configuredDetectorIds,
  configuredHttpsOrigin,
  evidenceConfigClient,
} from "../data/evidenceConfig";
import { optionalJobs } from "../data/optionalJobs";
import { requireNoSearchErrors } from "../data/searchClient";
import { parseSupplementalEnvelope } from "../data/supplementalEvidence";
import type { MapServiceHealthInspection } from "../MapServiceHealthInspection";

type O11yUi = {
  assetVersion: string;
  MapServiceHealthInspection: typeof MapServiceHealthInspection;
};
type Runtime = typeof globalThis & {
  ApplicationAtlasO11y?: O11yUi;
  __AtlasO11yHost?: { assetVersion: string };
  __ADM_FORCE_SPLUNK_BUILD__?: boolean;
};

let pending: Promise<O11yUi> | undefined;

export function loadO11yUi(): Promise<O11yUi> {
  const runtime = globalThis as Runtime;
  if (!__ADM_SPLUNK_BUILD__ && !runtime.__ADM_FORCE_SPLUNK_BUILD__)
    return import("./o11y-entry").then((module): O11yUi => ({
      assetVersion: "development",
      MapServiceHealthInspection: module.MapServiceHealthInspection,
    }));
  if (pending) return pending;
  const version = __ADM_O11Y_ASSET_VERSION__;
  if (
    runtime.__AtlasO11yHost &&
    runtime.__AtlasO11yHost.assetVersion !== version
  )
    return Promise.reject(
      new Error(
        "The Observability host belongs to a different app version. Reload the page.",
      ),
    );
  if (!runtime.__AtlasO11yHost)
    Object.defineProperty(runtime, "__AtlasO11yHost", {
      value: Object.freeze({
        assetVersion: version,
        react: React,
        jsxRuntime,
        deploymentHealth: Object.freeze({ indexNames }),
        evidence: Object.freeze({
          EVIDENCE_LIMITS,
          fingerprint,
          isObject,
          literal,
          routingScope,
          validText,
          validateServiceHealthSelection,
        }),
        evidenceConfig: Object.freeze({
          configuredDetectorIds,
          configuredHttpsOrigin,
          evidenceConfigClient,
        }),
        optionalJobs: Object.freeze({ optionalJobs }),
        searchClient: Object.freeze({ requireNoSearchErrors }),
        supplementalEvidence: Object.freeze({ parseSupplementalEnvelope }),
      }),
    });
  pending = loadVersionedAssetPair({
    js: "pages/o11y.js",
    css: "o11y.css",
    version,
    validate: () => {
      const ui = runtime.ApplicationAtlasO11y;
      return (
        ui?.assetVersion === version &&
        typeof ui.MapServiceHealthInspection === "function"
      );
    },
  })
    .then(() => runtime.ApplicationAtlasO11y!)
    .catch((error: unknown) => {
      pending = undefined;
      throw error;
    });
  return pending;
}

export function MapServiceHealthLazyInspection(
  props: React.ComponentProps<typeof MapServiceHealthInspection>,
) {
  const root = props.index.node.get(props.graph.boundary.root_node_id);
  const supported =
    props.live &&
    !!props.client &&
    props.selection.kind === "node" &&
    props.selection.id === props.graph.boundary.root_node_id &&
    root?.kind === "service";
  const [ui, setUi] = React.useState<O11yUi>();
  const [error, setError] = React.useState<string>();
  const [attempt, setAttempt] = React.useState(0);
  React.useEffect(() => {
    if (!supported) return;
    let active = true;
    void loadO11yUi().then(
      (next) => {
        if (active) setUi(next);
      },
      (reason: unknown) => {
        if (active)
          setError(
            reason instanceof Error
              ? reason.message
              : "Service health evidence could not load. Reload the page to retry.",
          );
      },
    );
    return () => {
      active = false;
    };
  }, [supported, attempt]);
  if (!supported) return null;
  if (ui) return <ui.MapServiceHealthInspection {...props} />;
  return (
    <section className="inspector-body" aria-label="Service health evidence">
      <h3>Service health evidence</h3>
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
        <p role="status">Loading service health evidence…</p>
      )}
    </section>
  );
}
