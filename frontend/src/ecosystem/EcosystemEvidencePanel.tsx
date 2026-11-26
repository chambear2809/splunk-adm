import type { EvidenceConfigClient } from "../data/evidenceConfig";
import type { EvidenceSelection } from "../data/evidence";
import type { SearchClient } from "../data/searchClient";
import type { EcosystemSource } from "./ecosystemReceipt";
import { FirewallTrafficEvidencePanel } from "./FirewallTrafficEvidencePanel";
import { LoadBalancerEvidencePanel } from "./LoadBalancerEvidencePanel";
import { CloudFlowEvidencePanel } from "./CloudFlowEvidencePanel";

/** One optional ecosystem source in the scoped endpoint investigation. */
export function EcosystemEvidencePanel({
  source,
  ...props
}: {
  source: EcosystemSource;
  selection: EvidenceSelection;
  client: SearchClient;
  configurationClient?: EvidenceConfigClient;
}) {
  if (source === "pan_traffic" || source === "fortigate_traffic")
    return <FirewallTrafficEvidencePanel source={source} {...props} />;
  if (source === "f5_ltm_http" || source === "aws_elb_access")
    return <LoadBalancerEvidencePanel source={source} {...props} />;
  return <CloudFlowEvidencePanel source={source} {...props} />;
}
