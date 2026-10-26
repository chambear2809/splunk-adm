import * as React from "react";
import * as jsxRuntime from "react/jsx-runtime";
import { createStaticURL } from "@splunk/splunk-utils/url";
import * as evidence from "./data/evidence";
import {
  configuredHttpsOrigin,
  evidenceConfigClient,
  type EvidenceConfigClient,
} from "./data/evidenceConfig";
import { loadSupplementalEvidence } from "./data/supplementalEvidence";
import { indexNames } from "./data/deploymentHealth";
import {
  requireNoSearchErrors,
  SearchAccessDeniedError,
  type SearchClient,
} from "./data/searchClient";
import type { EvidenceSelection } from "./data/evidence";

export interface ThousandEyesInspectionProps {
  selection: EvidenceSelection;
  client: SearchClient;
  configurationClient?: EvidenceConfigClient;
}

interface OptionalUi {
  assetVersion: string;
  ThousandEyesEvidenceInspection: React.ComponentType<ThousandEyesInspectionProps>;
}

type OptionalRuntime = typeof globalThis & {
  ApplicationAtlasThousandEyes?: OptionalUi;
  __AtlasThousandEyesHost?: unknown;
};
let pending: Promise<OptionalUi> | undefined;

/** Only fixed packaged same-origin assets enter this script-loading boundary. */
function assetUrl(file: "pages/thousandeyes.js" | "thousandeyes.css"): string {
  const url = new URL(createStaticURL(`app/splunk_adm/${file}`), location.href);
  if (
    url.origin !== location.origin ||
    !url.pathname.endsWith(`/app/splunk_adm/${file}`)
  )
    throw new Error(
      "The ThousandEyes packaged asset origin could not be verified.",
    );
  url.searchParams.set("v", __ADM_TE_ASSET_VERSION__);
  return url.href;
}

export function loadThousandEyesUi(): Promise<OptionalUi> {
  if (!__ADM_SPLUNK_BUILD__) return import("./thousandeyes-entry");
  if (pending) return pending;
  const runtime = globalThis as OptionalRuntime;
  if (
    runtime.__AtlasThousandEyesHost &&
    (typeof runtime.__AtlasThousandEyesHost !== "object" ||
      (runtime.__AtlasThousandEyesHost as { assetVersion?: unknown })
        .assetVersion !== __ADM_TE_ASSET_VERSION__)
  )
    return Promise.reject(
      new Error(
        "The ThousandEyes host belongs to a different app version. Reload the page.",
      ),
    );
  if (!runtime.__AtlasThousandEyesHost)
    Object.defineProperty(runtime, "__AtlasThousandEyesHost", {
      value: Object.freeze({
        assetVersion: __ADM_TE_ASSET_VERSION__,
        react: React,
        jsxRuntime,
        evidence,
        evidenceConfig: Object.freeze({
          configuredHttpsOrigin,
          evidenceConfigClient,
        }),
        supplementalEvidence: Object.freeze({ loadSupplementalEvidence }),
        deploymentHealth: Object.freeze({ indexNames }),
        searchClient: Object.freeze({
          requireNoSearchErrors,
          SearchAccessDeniedError,
        }),
      }),
    });
  pending = new Promise<OptionalUi>((resolve, reject) => {
    const script = document.createElement("script");
    const style = document.createElement("link");
    let scriptReady = false,
      styleReady = false,
      settled = false;
    const finish = (failed = false) => {
      if (settled || (!failed && (!scriptReady || !styleReady))) return;
      settled = true;
      clearTimeout(timer);
      script.onload = script.onerror = style.onload = style.onerror = null;
      const ui = runtime.ApplicationAtlasThousandEyes;
      if (
        failed ||
        !ui ||
        ui.assetVersion !== __ADM_TE_ASSET_VERSION__ ||
        typeof ui.ThousandEyesEvidenceInspection !== "function"
      ) {
        script.remove();
        style.remove();
        reject(
          new Error(
            "ThousandEyes investigation assets are unavailable or from a different app version. Reload and retry.",
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
      script.src = assetUrl("pages/thousandeyes.js");
      style.href = assetUrl("thousandeyes.css");
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

export function ThousandEyesLazyInspection(props: ThousandEyesInspectionProps) {
  const [ui, setUi] = React.useState<OptionalUi>();
  const [loading, setLoading] = React.useState(false);
  const [error, setError] = React.useState<string>();
  const generation = React.useRef(0);
  const invalidate = React.useCallback(() => {
    generation.current++;
  }, []);
  React.useEffect(() => {
    invalidate();
    setUi(undefined);
    setLoading(false);
    setError(undefined);
    return invalidate;
  }, [props.selection, invalidate]);
  const open = async () => {
    const current = ++generation.current;
    setLoading(true);
    setError(undefined);
    try {
      const next = await loadThousandEyesUi();
      if (current === generation.current) setUi(next);
    } catch (reason) {
      if (current === generation.current)
        setError(
          reason instanceof Error
            ? reason.message
            : "ThousandEyes investigation could not load.",
        );
    } finally {
      if (current === generation.current) setLoading(false);
    }
  };
  if (ui) {
    const Inspection = ui.ThousandEyesEvidenceInspection;
    return <Inspection {...props} />;
  }
  return (
    <section
      className="dns-evidence"
      aria-label="Optional ThousandEyes evidence"
    >
      <h3>ThousandEyes synthetic evidence</h3>
      <p>
        Inspect measurements and probe paths from configured ThousandEyes tests
        for this scoped selection.
      </p>
      <button type="button" disabled={loading} onClick={() => void open()}>
        {loading
          ? "Loading ThousandEyes investigation…"
          : "Open ThousandEyes investigation"}
      </button>
      {error && <p role="alert">{error}</p>}
    </section>
  );
}
