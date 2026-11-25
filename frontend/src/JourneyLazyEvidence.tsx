import * as React from "react";
import * as jsxRuntime from "react/jsx-runtime";
import { loadVersionedAssetPair } from "./optionalAssetLoader";
import {
  validNatObservation,
  type GraphIndex,
  type Graph,
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
import { appsOf } from "./impact/model";
import type { CatalogRow } from "./data/catalog";
import type { ImpactPlanningProps } from "./maintenance/ImpactMaintenancePlanner";
import type { BaselineRepository, DependencySource } from "./drift/client";
import type { CaseClient, CaseWindow } from "./investigations/caseClient";
import { CaseError } from "./investigations/caseClient";

export type JourneyEvidenceProps =
  | {
      kind: "cases";
      client?: CaseClient;
      window: CaseWindow;
      comparisonReference?: string;
      initiallyOpen?: boolean;
    }
  | { kind: "ownershipImport" }
  | {
      kind: "ownership";
      initiallyOpen?: boolean;
      onClose?: () => void;
      graph?: Graph;
      catalogRow?: CatalogRow;
      unavailableReason?: string;
    }
  | ({ kind: "maintenance" } & ImpactPlanningProps)
  | {
      kind: "baseline";
      window: EvidenceWindow;
      mapWarnings?: string[];
      nativePersistence?: boolean;
      selection?: {
        service: string;
        environment: string;
        cluster: string;
        namespace: string;
      };
      source?: DependencySource;
      repository?: BaselineRepository;
    }
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
        impact: Object.freeze({ appsOf }),
        caseClient: Object.freeze({ CaseError }),
      }),
    });
  pending = loadVersionedAssetPair({
    javascript: "pages/journeys.js",
    stylesheet: "journeys.css",
    version: __ADM_JOURNEYS_ASSET_VERSION__,
    validate: () => {
      const ui = runtime.ApplicationAtlasJourneys;
      return Boolean(
        ui &&
        ui.assetVersion === __ADM_JOURNEYS_ASSET_VERSION__ &&
        typeof ui.JourneyEvidenceInspection === "function",
      );
    },
  })
    .then(() => runtime.ApplicationAtlasJourneys!)
    .catch((error: unknown) => {
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
  const restoreFocus = React.useRef(false);
  React.useEffect(() => {
    if (ui) region.current?.focus();
    else if (restoreFocus.current) {
      trigger.current?.focus();
      restoreFocus.current = false;
    }
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
  const open = React.useCallback(async () => {
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
  }, []);
  const initiallyOpen =
    (props.kind === "ownership" || props.kind === "cases") &&
    props.initiallyOpen;
  React.useEffect(() => {
    if (initiallyOpen) void open();
  }, [initiallyOpen, open]);
  if (ui) {
    const Inspection = ui.JourneyEvidenceInspection;
    return (
      <div
        ref={region}
        tabIndex={-1}
        role="region"
        aria-label={
          props.kind === "cases"
            ? "Shared cases"
            : props.kind === "ownershipImport"
              ? "Business-service import"
              : props.kind === "ownership"
                ? "Business ownership"
                : "Journey investigation"
        }
      >
        {props.kind === "ownership" && (
          <button
            type="button"
            className="secondary-button"
            onClick={() => {
              restoreFocus.current = true;
              setUi(undefined);
              props.onClose?.();
            }}
          >
            Close business ownership
          </button>
        )}
        <Inspection {...props} />
      </div>
    );
  }
  const label =
    props.kind === "cases"
      ? "shared case records"
      : props.kind === "ownershipImport"
        ? "business-service import"
        : props.kind === "ownership"
          ? "business ownership"
          : props.kind === "nat"
            ? "firewall translation"
            : props.kind === "maintenance"
              ? "maintenance planning"
              : props.kind === "baseline"
                ? "dependency baseline"
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
        {props.kind === "cases"
          ? loading
            ? "Loading shared cases…"
            : "Open shared cases"
          : loading
            ? "Loading journey evidence…"
            : `Open ${label} evidence`}
      </button>
      {error && <p role="alert">{error}</p>}
    </section>
  );
}
