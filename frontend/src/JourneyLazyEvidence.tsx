import * as React from "react";
import * as jsxRuntime from "react/jsx-runtime";
import { createStaticURL } from "@splunk/splunk-utils/url";
import {
  validNatObservation,
  type GraphIndex,
  type NatObservation,
} from "./graph";
import {
  EVIDENCE_LIMITS,
  normalizeIp,
  validateSelection,
  type EvidenceWindow,
} from "./data/evidence";
import {
  PROXY_SCHEMA,
  proxySearchWindow,
  type ProxyObservation,
} from "./data/proxyEvidence";
import type { SupplementalResult } from "./data/supplementalEvidence";
import { clientHandoffResolution } from "./topology";
import { handoffShort } from "./glossary";

export type JourneyEvidenceProps =
  | {
      kind: "nat";
      observations: NatObservation[];
      truncated?: boolean;
      window?: EvidenceWindow;
    }
  | { kind: "proxy"; result: SupplementalResult<ProxyObservation> }
  | {
      kind: "hubble";
      edgeId: string;
      index: GraphIndex;
      window?: EvidenceWindow;
    };
interface OptionalUi {
  assetVersion: string;
  JourneyEvidenceInspection: React.ComponentType<JourneyEvidenceProps>;
}
type OptionalRuntime = typeof globalThis & {
  ApplicationAtlasJourneys?: OptionalUi;
  __AtlasJourneysHost?: unknown;
};
let pending: Promise<OptionalUi> | undefined;
function assetUrl(file: "pages/journeys.js" | "journeys.css"): string {
  const url = new URL(createStaticURL(`app/splunk_adm/${file}`), location.href);
  if (
    url.origin !== location.origin ||
    !url.pathname.endsWith(`/app/splunk_adm/${file}`)
  )
    throw new Error("The journey packaged asset origin could not be verified.");
  url.searchParams.set("v", __ADM_JOURNEYS_ASSET_VERSION__);
  return url.href;
}
export function loadJourneyUi(): Promise<OptionalUi> {
  if (!__ADM_SPLUNK_BUILD__) return import("./journeys-entry");
  if (pending) return pending;
  const runtime = globalThis as OptionalRuntime;
  if (
    runtime.__AtlasJourneysHost &&
    (typeof runtime.__AtlasJourneysHost !== "object" ||
      (runtime.__AtlasJourneysHost as { assetVersion?: unknown })
        .assetVersion !== __ADM_JOURNEYS_ASSET_VERSION__)
  )
    return Promise.reject(
      new Error(
        "The journey host belongs to a different app version. Reload the page.",
      ),
    );
  if (!runtime.__AtlasJourneysHost)
    Object.defineProperty(runtime, "__AtlasJourneysHost", {
      value: Object.freeze({
        assetVersion: __ADM_JOURNEYS_ASSET_VERSION__,
        react: React,
        jsxRuntime,
        graph: Object.freeze({ validNatObservation }),
        evidence: Object.freeze({
          EVIDENCE_LIMITS: Object.freeze({ ...EVIDENCE_LIMITS }),
          normalizeIp,
          validateSelection,
        }),
        proxyEvidence: Object.freeze({ PROXY_SCHEMA, proxySearchWindow }),
        topology: Object.freeze({ clientHandoffResolution }),
        glossary: Object.freeze({ handoffShort }),
      }),
    });
  pending = new Promise<OptionalUi>((resolve, reject) => {
    const script = document.createElement("script"),
      style = document.createElement("link");
    let scriptReady = false,
      styleReady = false,
      settled = false;
    const finish = (failed = false) => {
      if (settled || (!failed && (!scriptReady || !styleReady))) return;
      settled = true;
      clearTimeout(timer);
      script.onload = script.onerror = style.onload = style.onerror = null;
      const ui = runtime.ApplicationAtlasJourneys;
      if (
        failed ||
        !ui ||
        ui.assetVersion !== __ADM_JOURNEYS_ASSET_VERSION__ ||
        typeof ui.JourneyEvidenceInspection !== "function"
      ) {
        script.remove();
        style.remove();
        reject(
          new Error(
            "Journey evidence assets are unavailable or from a different app version. Reload and retry.",
          ),
        );
      } else resolve(ui);
    };
    const timer = setTimeout(() => finish(true), 10000);
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
    script.onerror = style.onerror = () => finish(true);
    try {
      script.src = assetUrl("pages/journeys.js");
      style.href = assetUrl("journeys.css");
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
export function JourneyLazyEvidence(props: JourneyEvidenceProps) {
  const [ui, setUi] = React.useState<OptionalUi>();
  const [loading, setLoading] = React.useState(false);
  const [error, setError] = React.useState<string>();
  const generation = React.useRef(0);
  const region = React.useRef<HTMLDivElement>(null);
  const trigger = React.useRef<HTMLButtonElement>(null);
  React.useEffect(() => {
    if (ui) region.current?.focus();
  }, [ui]);
  React.useEffect(() => {
    if (error) trigger.current?.focus();
  }, [error]);
  React.useEffect(
    () => () => {
      generation.current++;
    },
    [],
  );
  const open = async () => {
    const current = ++generation.current;
    setLoading(true);
    setError(undefined);
    try {
      const next = await loadJourneyUi();
      if (current === generation.current) setUi(next);
    } catch (reason) {
      if (current === generation.current)
        setError(
          reason instanceof Error
            ? reason.message
            : "Journey evidence could not load.",
        );
    } finally {
      if (current === generation.current) setLoading(false);
    }
  };
  if (ui) {
    const Inspection = ui.JourneyEvidenceInspection;
    return (
      <div
        ref={region}
        tabIndex={-1}
        role="region"
        aria-label="Journey investigation"
      >
        <Inspection {...props} />
      </div>
    );
  }
  const label =
    props.kind === "nat"
      ? "firewall translation"
      : props.kind === "proxy"
        ? "proxy request"
        : "service forwarding";
  return (
    <section className="atlas-journeys">
      <button
        ref={trigger}
        className="secondary-button"
        type="button"
        disabled={loading}
        onClick={() => void open()}
      >
        {loading ? "Loading journey evidence…" : `Open ${label} evidence`}
      </button>
      {error && <p role="alert">{error}</p>}
    </section>
  );
}
