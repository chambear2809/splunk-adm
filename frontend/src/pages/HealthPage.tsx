import ButtonExport from "@splunk/react-ui/Button";
import { toolkitDefault } from "../app/interop";
import { HealthResults, useHealthData } from "../HealthPanel";
import type { SearchClient } from "../data/searchClient";
const Button = toolkitDefault(ButtonExport);
export function HealthPage({
  client,
  live,
}: {
  client?: SearchClient;
  live: boolean;
}) {
  const { report, error, busy, checkAgain } = useHealthData(client, live);
  return (
    <main className="atlas-page" aria-labelledby="health-title">
      <h1 id="health-title">Data health</h1>
      {!live ? (
        <p role="status">
          Synthetic demo data cannot establish pipeline health. Switch to Splunk
          to check live data and scheduled searches.
        </p>
      ) : (
        <>
          <Button
            appearance="secondary"
            label={busy ? "Checking…" : "Check again"}
            onClick={checkAgain}
            disabled={busy || !client}
          />
          {busy && (
            <p role="status">
              Checking data sources, flow quality and scheduled searches…
            </p>
          )}
          {error && <p role="alert">{error}</p>}
          {report && <HealthResults report={report} />}
        </>
      )}
    </main>
  );
}
