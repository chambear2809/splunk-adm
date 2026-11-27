import * as React from "react";
import * as jsxRuntime from "react/jsx-runtime";
import { loadVersionedAssetPair } from "../optionalAssetLoader";
import {
  EVIDENCE_LIMITS,
  fingerprint,
  literal,
  normalizeIp,
  routingScope,
  validateSelection,
} from "../data/evidence";
import { evidenceConfigClient } from "../data/evidenceConfig";
import { optionalJobs } from "../data/optionalJobs";
import {
  requireNoSearchErrors,
  SearchAccessDeniedError,
} from "../data/searchClient";
import { loadSupplementalEvidence } from "../data/supplementalEvidence";
import type { EcosystemReceiptPanel } from "./EcosystemReceiptPanel";
import type { EcosystemEvidencePanel } from "./EcosystemEvidencePanel";
import type { EcosystemSource } from "./ecosystemReceipt";

type EcosystemUi = {
  assetVersion: string;
  EcosystemEvidencePanel: typeof EcosystemEvidencePanel;
  EcosystemReceiptPanel: typeof EcosystemReceiptPanel;
};
type Runtime = typeof globalThis & {
  ApplicationAtlasEcosystem?: EcosystemUi;
  __AtlasEcosystemHost?: { assetVersion: string };
  __ADM_FORCE_SPLUNK_BUILD__?: boolean;
};
let pending: Promise<EcosystemUi> | undefined;

/** Placeholder labels, in panel order; the source contracts live in the optional bundle. */
const ECOSYSTEM_LABELS: Record<EcosystemSource, string> = {
  pan_traffic: "Palo Alto Networks traffic",
  fortigate_traffic: "FortiGate traffic",
  f5_ltm_http: "F5 BIG-IP LTM request legs",
  aws_elb_access: "AWS ALB/NLB access legs",
  azure_vnet_flow: "Azure VNet flow logs",
  gcp_vpc_flow: "GCP VPC flow logs",
};
export const ECOSYSTEM_EVIDENCE_SOURCES = Object.keys(
  ECOSYSTEM_LABELS,
) as EcosystemSource[];

export function loadEcosystemUi(): Promise<EcosystemUi> {
  const runtime = globalThis as Runtime;
  if (!__ADM_SPLUNK_BUILD__ && !runtime.__ADM_FORCE_SPLUNK_BUILD__)
    return import("./ecosystem-entry").then((module): EcosystemUi => ({
      assetVersion: "development",
      EcosystemEvidencePanel: module.EcosystemEvidencePanel,
      EcosystemReceiptPanel: module.EcosystemReceiptPanel,
    }));
  if (pending) return pending;
  const version = __ADM_ECOSYSTEM_ASSET_VERSION__;
  if (
    runtime.__AtlasEcosystemHost &&
    runtime.__AtlasEcosystemHost.assetVersion !== version
  )
    return Promise.reject(
      new Error(
        "The Ecosystem host belongs to a different app version. Reload the page.",
      ),
    );
  if (!runtime.__AtlasEcosystemHost)
    Object.defineProperty(runtime, "__AtlasEcosystemHost", {
      value: Object.freeze({
        assetVersion: version,
        react: React,
        jsxRuntime,
        evidence: Object.freeze({
          EVIDENCE_LIMITS,
          fingerprint,
          literal,
          normalizeIp,
          routingScope,
          validateSelection,
        }),
        evidenceConfig: Object.freeze({ evidenceConfigClient }),
        optionalJobs: Object.freeze({ optionalJobs }),
        searchClient: Object.freeze({
          requireNoSearchErrors,
          SearchAccessDeniedError,
        }),
        supplementalEvidence: Object.freeze({ loadSupplementalEvidence }),
      }),
    });
  pending = loadVersionedAssetPair({
    js: "pages/ecosystem.js",
    css: "ecosystem.css",
    version,
    validate: () => {
      const ui = runtime.ApplicationAtlasEcosystem;
      return (
        ui?.assetVersion === version &&
        typeof ui.EcosystemEvidencePanel === "function" &&
        typeof ui.EcosystemReceiptPanel === "function"
      );
    },
  })
    .then(() => runtime.ApplicationAtlasEcosystem!)
    .catch((error: unknown) => {
      pending = undefined;
      throw error;
    });
  return pending;
}

function useEcosystemUi() {
  const [ui, setUi] = React.useState<EcosystemUi>();
  const [error, setError] = React.useState<string>();
  React.useEffect(() => {
    let active = true;
    void loadEcosystemUi()
      .then((next) => active && setUi(next))
      .catch(
        () =>
          active &&
          setError(
            "Ecosystem evidence could not load. Reload the page to retry.",
          ),
      );
    return () => {
      active = false;
    };
  }, []);
  return { ui, error };
}

export function LazyEcosystemEvidencePanel(
  props: React.ComponentProps<typeof EcosystemEvidencePanel>,
) {
  const { ui, error } = useEcosystemUi();
  if (ui) return <ui.EcosystemEvidencePanel {...props} />;
  return (
    <section
      className="dns-evidence inspector-body"
      aria-label={ECOSYSTEM_LABELS[props.source]}
    >
      <h3>{ECOSYSTEM_LABELS[props.source]}</h3>
      <p role={error ? "alert" : "status"}>
        {error ?? "Loading optional ecosystem evidence…"}
      </p>
    </section>
  );
}

export function LazyEcosystemReceiptPanel(
  props: React.ComponentProps<typeof EcosystemReceiptPanel>,
) {
  const { ui, error } = useEcosystemUi();
  if (ui) return <ui.EcosystemReceiptPanel {...props} />;
  return (
    <section aria-label="Ecosystem TA traffic receipt">
      <h3>Ecosystem TA traffic receipt</h3>
      <p role={error ? "alert" : "status"}>
        {error ?? "Loading optional receipt check…"}
      </p>
    </section>
  );
}
