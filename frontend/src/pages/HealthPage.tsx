import { HealthPanel } from "../HealthPanel";
import type { SearchClient } from "../data/searchClient";
export function HealthPage({
  client,
  live,
}: {
  client?: SearchClient;
  live: boolean;
}) {
  return (
    <main className="atlas-page">
      <h1>Data health</h1>
      <HealthPanel client={client} live={live} close={() => {}} />
    </main>
  );
}
