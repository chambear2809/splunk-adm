import * as React from "react";
import * as jsxRuntime from "react/jsx-runtime";
import { createStaticURL } from "@splunk/splunk-utils/url";
import {
  literal,
  normalizeIp,
  routingScope,
  validText,
} from "../data/evidence";
import { evidenceConfigClient } from "../data/evidenceConfig";
import { requireNoSearchErrors } from "../data/searchClient";
import { csvRow } from "../csv";
import { downloadBlob } from "../download";
import type { MigrationPlannerPage } from "./MigrationPlannerPage";

type Ui = {
  assetVersion: string;
  MigrationPlannerPage: typeof MigrationPlannerPage;
};
type Runtime = typeof globalThis & {
  ApplicationAtlasMigration?: Ui;
  __AtlasMigrationHost?: { assetVersion: string };
};
let pending: Promise<typeof MigrationPlannerPage> | undefined;
function assetUrl(file: "pages/migration.js" | "migration.css") {
  const url = new URL(createStaticURL(`app/splunk_adm/${file}`), location.href);
  if (
    url.origin !== location.origin ||
    !url.pathname.endsWith(`/app/splunk_adm/${file}`)
  )
    throw new Error(
      "The migration planner asset origin could not be verified.",
    );
  url.searchParams.set("v", __ADM_MIGRATION_ASSET_VERSION__);
  return url.href;
}
export async function loadMigrationPlannerPage() {
  if (!__ADM_SPLUNK_BUILD__)
    return (await import("./MigrationPlannerPage")).MigrationPlannerPage;
  if (pending) return pending;
  const runtime = globalThis as Runtime;
  const version = __ADM_MIGRATION_ASSET_VERSION__;
  if (
    runtime.__AtlasMigrationHost &&
    runtime.__AtlasMigrationHost.assetVersion !== version
  )
    throw new Error(
      "The migration planner host belongs to a different app version. Reload the page.",
    );
  if (!runtime.__AtlasMigrationHost)
    Object.defineProperty(runtime, "__AtlasMigrationHost", {
      value: Object.freeze({
        assetVersion: version,
        react: React,
        jsxRuntime,
        evidence: { literal, normalizeIp, routingScope, validText },
        evidenceConfig: { evidenceConfigClient },
        searchClient: { requireNoSearchErrors },
        csv: { csvRow },
        download: { downloadBlob },
      }),
    });
  pending = new Promise<typeof MigrationPlannerPage>((resolve, reject) => {
    const script = document.createElement("script"),
      style = document.createElement("link");
    let loaded = 0,
      settled = false;
    const finish = (failed: boolean) => {
      if (settled || (!failed && ++loaded < 2)) return;
      settled = true;
      clearTimeout(timer);
      script.onload = script.onerror = style.onload = style.onerror = null;
      const ui = runtime.ApplicationAtlasMigration;
      if (
        !failed &&
        ui?.assetVersion === version &&
        typeof ui.MigrationPlannerPage === "function"
      )
        resolve(ui.MigrationPlannerPage);
      else {
        script.remove();
        style.remove();
        reject(
          new Error(
            "Migration planner assets are unavailable or from a different app version.",
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
      script.src = assetUrl("pages/migration.js");
      style.href = assetUrl("migration.css");
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
export function MigrationLazyPage(
  props: React.ComponentProps<typeof MigrationPlannerPage>,
) {
  const [page, setPage] = React.useState<typeof MigrationPlannerPage>();
  const [error, setError] = React.useState<string>();
  const [revision, setRevision] = React.useState(0);
  React.useEffect(() => {
    let cancelled = false;
    loadMigrationPlannerPage()
      .then((component) => {
        if (!cancelled) setPage(() => component);
      })
      .catch((reason: unknown) => {
        if (!cancelled)
          setError(
            reason instanceof Error
              ? reason.message
              : "The migration planner could not load.",
          );
      });
    return () => {
      cancelled = true;
    };
  }, [revision]);
  if (page) return React.createElement(page, props);
  if (error)
    return (
      <div role="alert">
        <p>{error}</p>
        <button
          type="button"
          onClick={() => {
            setError(undefined);
            setRevision((value) => value + 1);
          }}
        >
          Retry
        </button>
      </div>
    );
  return <p role="status">Loading migration planner…</p>;
}
