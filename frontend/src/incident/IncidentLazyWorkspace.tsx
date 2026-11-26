import * as React from "react";
import * as jsxRuntime from "react/jsx-runtime";
import { createStaticURL } from "@splunk/splunk-utils/url";
import type {
  IncidentWorkspace,
  IncidentWorkspaceProps,
} from "./IncidentWorkspace";
import { diffGraphs } from "../diff";
import { formatInZone } from "../time";
import { downloadBlob } from "../download";
import { ARG_RULES } from "../provider";
import { JourneyLazyEvidence } from "../JourneyLazyEvidence";

type Workspace = typeof IncidentWorkspace;
type IncidentUi = { assetVersion: string; IncidentWorkspace: Workspace };
type IncidentRuntime = typeof globalThis & {
  ApplicationAtlasIncident?: IncidentUi;
  __AtlasIncidentHost?: { assetVersion: string };
};
let pending: Promise<Workspace> | undefined;
function assetUrl(file: "pages/incident.js" | "incident.css") {
  const url = new URL(createStaticURL(`app/splunk_adm/${file}`), location.href);
  if (
    url.origin !== location.origin ||
    !url.pathname.endsWith(`/app/splunk_adm/${file}`)
  )
    throw new Error(
      "The investigation workspace asset origin could not be verified.",
    );
  url.searchParams.set("v", __ADM_INCIDENT_ASSET_VERSION__);
  return url.href;
}

export async function loadIncidentWorkspace() {
  if (!__ADM_SPLUNK_BUILD__)
    return (await import("./IncidentWorkspace")).IncidentWorkspace;
  if (pending) return pending;
  const runtime = globalThis as IncidentRuntime;
  const version = __ADM_INCIDENT_ASSET_VERSION__;
  if (
    runtime.__AtlasIncidentHost &&
    runtime.__AtlasIncidentHost.assetVersion !== version
  )
    throw new Error(
      "The investigation workspace host belongs to a different app version. Reload the page.",
    );
  if (!runtime.__AtlasIncidentHost)
    Object.defineProperty(runtime, "__AtlasIncidentHost", {
      value: Object.freeze({
        assetVersion: version,
        react: React,
        jsxRuntime,
        diff: { diffGraphs },
        time: { formatInZone },
        download: { downloadBlob },
        provider: { ARG_RULES },
        journeys: { JourneyLazyEvidence },
      }),
    });

  pending = new Promise<Workspace>((resolve, reject) => {
    const script = document.createElement("script");
    const style = document.createElement("link");
    let loaded = 0;
    let settled = false;
    const finish = (failed: boolean) => {
      if (settled || (!failed && ++loaded < 2)) return;
      settled = true;
      clearTimeout(timer);
      script.onload = script.onerror = style.onload = style.onerror = null;
      const ui = runtime.ApplicationAtlasIncident;
      if (
        !failed &&
        ui?.assetVersion === version &&
        typeof ui.IncidentWorkspace === "function"
      ) {
        resolve(ui.IncidentWorkspace);
      } else {
        script.remove();
        style.remove();
        reject(
          new Error(
            "Investigation workspace assets are unavailable or from a different app version.",
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
      script.src = assetUrl("pages/incident.js");
      style.href = assetUrl("incident.css");
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

export function IncidentLazyWorkspace(props: IncidentWorkspaceProps) {
  const [Workspace, setWorkspace] = React.useState<Workspace>();
  const [error, setError] = React.useState<string>();
  const [attempt, setAttempt] = React.useState(0);
  React.useEffect(() => {
    let cancelled = false;
    void loadIncidentWorkspace().then(
      (workspace) => {
        if (!cancelled) setWorkspace(() => workspace);
      },
      (reason: unknown) => {
        if (!cancelled)
          setError(
            reason instanceof Error
              ? reason.message
              : "The investigation workspace could not load.",
          );
      },
    );
    return () => {
      cancelled = true;
    };
  }, [attempt]);
  if (Workspace) return <Workspace {...props} />;
  return error ? (
    <section aria-label="Investigation workspace unavailable">
      <p role="alert">{error}</p>
      <button
        type="button"
        className="secondary-button"
        onClick={() => {
          setError(undefined);
          setAttempt((previous) => previous + 1);
        }}
      >
        Retry
      </button>{" "}
      {props.onBack && (
        <button
          type="button"
          className="secondary-button"
          onClick={props.onBack}
        >
          Back to map
        </button>
      )}
    </section>
  ) : (
    <p role="status">Opening investigation…</p>
  );
}
