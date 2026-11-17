import { createRoot } from "react-dom/client";
import ThemeProviderExport from "@splunk/themes/SplunkThemeProvider";
import { toolkitDefault } from "../../frontend/src/app/interop";
import { Shell } from "../../frontend/src/app/Shell";
import { TrafficEvidence } from "../../frontend/src/Inspector";
import type { TrafficObservation } from "../../frontend/src/graph";
import sample from "../../fixtures/feature-replay/sanitized-source-sample.json";
import "../../frontend/src/styles.css";

const theme =
  new URLSearchParams(location.search).get("theme") === "dark"
    ? "dark"
    : "light";
const ThemeProvider = toolkitDefault(ThemeProviderExport);
const observations = sample.observations as TrafficObservation[];
createRoot(document.getElementById("root")!).render(
  <ThemeProvider family="enterprise" colorScheme={theme} density="comfortable">
    <Shell page="map">
      <main className="adm" data-adm-theme={theme}>
        <div
          className="inspector"
          style={{ maxWidth: "64rem", margin: "1rem auto" }}
        >
          <div className="inspector-body">
            <header>
              <h1>Sanitized source sample</h1>
              <p>
                {observations.length} Hubble observations ·{" "}
                {sample.families.pods.length} pod records retained separately
              </p>
              <p>
                Replay window:{" "}
                {new Date(sample.window.start * 1000).toISOString()} to{" "}
                {new Date(sample.window.end * 1000).toISOString()}
              </p>
              <p className="callout warn">
                Bounded sample; completeness and identity/path qualification not
                established. Parser acceptance does not establish collection
                coverage or application health.
              </p>
            </header>
            <TrafficEvidence observations={observations} />
            <details>
              <summary>Replay provenance</summary>
              <p>
                Observed records were projected through a reviewed allowlist and
                pseudonymized. Source relationships and receipt lag were
                preserved; timestamps use a common shift. These are transformed
                source samples, not untouched production events.
              </p>
              <p>
                Documentation addresses do not preserve routing or address-class
                semantics. Pod conditions report observations, not qualified
                readiness or complete membership.
              </p>
              <p>
                No graph identity, physical path, NAT association or
                client-specific backend handoff was manufactured for this
                replay.
              </p>
            </details>
          </div>
        </div>
      </main>
    </Shell>
  </ThemeProvider>,
);
