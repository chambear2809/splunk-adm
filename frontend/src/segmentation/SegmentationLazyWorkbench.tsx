import * as React from "react";
import * as jsxRuntime from "react/jsx-runtime";
import { createStaticURL } from "@splunk/splunk-utils/url";
import type { PolicyWorkbench, PolicyWorkbenchProps } from "./PolicyWorkbench";
import { downloadBlob } from "../download";
import { plural } from "../glossary";
import { traceURL } from "../pages/ExploreTools";
import { csvRow } from "../csv";

type Workbench = typeof PolicyWorkbench;
type SegmentationUi = { assetVersion: string; PolicyWorkbench: Workbench };
type SegmentationRuntime = typeof globalThis & {
  ApplicationAtlasSegmentation?: SegmentationUi;
  __AtlasSegmentationHost?: { assetVersion: string };
};
let pending: Promise<Workbench> | undefined;
function assetUrl(file: "pages/segmentation.js" | "segmentation.css") {
  const url = new URL(createStaticURL(`app/splunk_adm/${file}`), location.href);
  if (
    url.origin !== location.origin ||
    !url.pathname.endsWith(`/app/splunk_adm/${file}`)
  )
    throw new Error("The segmentation asset origin could not be verified.");
  url.searchParams.set("v", __ADM_SEGMENTATION_ASSET_VERSION__);
  return url.href;
}

export async function loadPolicyWorkbench() {
  if (!__ADM_SPLUNK_BUILD__)
    return (await import("./PolicyWorkbench")).PolicyWorkbench;
  if (pending) return pending;
  const runtime = globalThis as SegmentationRuntime;
  const version = __ADM_SEGMENTATION_ASSET_VERSION__;
  if (
    runtime.__AtlasSegmentationHost &&
    runtime.__AtlasSegmentationHost.assetVersion !== version
  )
    throw new Error(
      "The segmentation host belongs to a different app version. Reload the page.",
    );
  if (!runtime.__AtlasSegmentationHost)
    Object.defineProperty(runtime, "__AtlasSegmentationHost", {
      value: Object.freeze({
        assetVersion: version,
        react: React,
        jsxRuntime,
        download: { downloadBlob },
        glossary: { plural },
        explore: { traceURL },
        csv: { csvRow },
      }),
    });

  pending = new Promise<Workbench>((resolve, reject) => {
    const script = document.createElement("script");
    const style = document.createElement("link");
    let loaded = 0;
    let settled = false;
    const finish = (failed: boolean) => {
      if (settled || (!failed && ++loaded < 2)) return;
      settled = true;
      clearTimeout(timer);
      script.onload = script.onerror = style.onload = style.onerror = null;
      const ui = runtime.ApplicationAtlasSegmentation;
      if (
        !failed &&
        ui?.assetVersion === version &&
        typeof ui.PolicyWorkbench === "function"
      ) {
        resolve(ui.PolicyWorkbench);
      } else {
        script.remove();
        style.remove();
        reject(
          new Error(
            "Segmentation assets are unavailable or from a different app version.",
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
      script.src = assetUrl("pages/segmentation.js");
      style.href = assetUrl("segmentation.css");
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

export function SegmentationLazyWorkbench(props: PolicyWorkbenchProps) {
  const [Workbench, setWorkbench] = React.useState<Workbench>();
  const [error, setError] = React.useState<string>();
  const [attempt, setAttempt] = React.useState(0);
  React.useEffect(() => {
    let cancelled = false;
    void loadPolicyWorkbench().then(
      (workbench) => {
        if (!cancelled) setWorkbench(() => workbench);
      },
      (reason: unknown) => {
        if (!cancelled)
          setError(
            reason instanceof Error
              ? reason.message
              : "The segmentation workbench could not load.",
          );
      },
    );
    return () => {
      cancelled = true;
    };
  }, [attempt]);
  if (Workbench) return <Workbench {...props} />;
  return (
    <section className="atlas-seg" aria-label="Segmentation policy workbench">
      {error ? (
        <>
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
          <button
            type="button"
            className="secondary-button"
            onClick={props.onClose}
          >
            Close
          </button>
        </>
      ) : (
        <p role="status">Loading segmentation workbench…</p>
      )}
    </section>
  );
}
