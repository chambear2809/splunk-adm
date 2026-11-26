import type { EvidenceSelection } from "./data/evidence";
import type { EvidenceConfigClient } from "./data/evidenceConfig";
import type { SearchClient } from "./data/searchClient";
import { DnsEvidencePanel } from "./DnsEvidencePanel";
import { ProxyEvidenceInspection } from "./ProxyEvidencePanel";
import { CloudFlowEvidencePanel } from "./CloudFlowEvidencePanel";
import { InventoryEvidencePanel } from "./InventoryEvidencePanel";
import { AppDynamicsEvidenceInspection } from "./AppDynamicsEvidencePanel";
import { ThousandEyesLazyInspection } from "./ThousandEyesLazyInspection";
import { LazyChangeTimelineInspection } from "./HistoryLazyInspection";
import {
  ECOSYSTEM_EVIDENCE_SOURCES,
  LazyEcosystemEvidencePanel,
} from "./ecosystem/EcosystemLazyEvidence";

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
      <LazyChangeTimelineInspection
        client={client}
        view={{ scope: selection.scope, window: selection.window }}
        context={{ application: selection.application }}
      />
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
      {ECOSYSTEM_EVIDENCE_SOURCES.map((source) => (
        <LazyEcosystemEvidencePanel
          key={source}
          source={source}
          selection={selection}
          client={client}
          configurationClient={configurationClient}
        />
      ))}
      <InventoryEvidencePanel
        selection={selection}
        client={client}
        configurationClient={configurationClient}
      />
      <AppDynamicsEvidenceInspection
        selection={selection}
        client={client}
        configurationClient={configurationClient}
      />
      <ThousandEyesLazyInspection
        selection={selection}
        client={client}
        configurationClient={configurationClient}
      />
    </div>
  );
}
