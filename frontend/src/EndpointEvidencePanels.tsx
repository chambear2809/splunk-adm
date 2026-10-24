import type { EvidenceSelection } from "./data/evidence";
import type { EvidenceConfigClient } from "./data/evidenceConfig";
import type { SearchClient } from "./data/searchClient";
import { DnsEvidencePanel } from "./DnsEvidencePanel";
import { ProxyEvidenceInspection } from "./ProxyEvidencePanel";
import { CloudFlowEvidencePanel } from "./CloudFlowEvidencePanel";
import { InventoryEvidencePanel } from "./InventoryEvidencePanel";

/** The existing scoped endpoint and map investigation owns all optional evidence. */
export function EndpointEvidencePanels({
  selection,
  client,
  configurationClient,
}: {
  selection: EvidenceSelection;
  client: SearchClient;
  configurationClient?: EvidenceConfigClient;
}) {
  return (
    <div aria-label="Scoped endpoint evidence">
      <DnsEvidencePanel
        selection={selection}
        client={client}
        configurationClient={configurationClient}
      />
      <ProxyEvidenceInspection
        selection={selection}
        client={client}
        configurationClient={configurationClient}
      />
      <CloudFlowEvidencePanel
        selection={selection}
        client={client}
        configurationClient={configurationClient}
      />
      <InventoryEvidencePanel
        selection={selection}
        client={client}
        configurationClient={configurationClient}
      />
    </div>
  );
}
