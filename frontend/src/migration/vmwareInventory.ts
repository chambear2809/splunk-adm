import { normalizeIp, validText } from "../data/evidence";
import { requireNoSearchErrors, type SearchClient } from "../data/searchClient";

export const VMWARE_LABEL_LIMITS = {
  addresses: 200,
  rows: 400,
  lookback: 30 * 86400,
} as const;

/**
 * Context only: vCenter's primary guest IP for a VM. The address match is not
 * scoped to a routing domain and never changes grouping.
 */
export interface VmwareInventoryLabel {
  address: string;
  vmName: string;
  vmId?: string;
  hypervisor?: string;
  cluster?: string;
  vcenter: string;
  reportedAt: number;
  /** Distinct VMs whose latest change set reports this primary IP. */
  claims: number;
}
export interface VmwareInventoryResult {
  labels: VmwareInventoryLabel[];
  capped: boolean;
  window: { start: number; end: number };
}

export function buildVmwareInventorySearch(
  addresses: string[],
  end: number,
): string {
  if (
    !addresses.length ||
    addresses.length > VMWARE_LABEL_LIMITS.addresses ||
    !Number.isInteger(end)
  )
    throw new Error("Choose between 1 and 200 addresses for VMware labels.");
  const list = addresses
    .map((address) => {
      const ip = normalizeIp(address);
      if (ip !== address)
        throw new Error("VMware label addresses must be canonical.");
      return `"${ip}"`;
    })
    .join(",");
  // changeSet.guest.ipAddress is the TA-VMW-FieldExtractions `ip` alias source.
  return `search \`adm_index_vmware_inv\` sourcetype="vmware:inv:vm" | spath path=changeSet.guest.ipAddress output=adm_ip | where isnotnull(adm_ip) | spath path=moid output=adm_moid | spath path=vm_name output=adm_vm_name | spath path=vm_id output=adm_vm_id | spath path=changeSet.summary.runtime.host.name output=adm_hypervisor | spath path=cluster.name output=adm_cluster | stats latest(_time) as reported latest(adm_ip) as adm_ip latest(adm_vm_name) as vm_name latest(adm_vm_id) as vm_id latest(adm_hypervisor) as hypervisor latest(adm_cluster) as cluster by host adm_moid | where adm_ip IN (${list}) | eventstats dc(adm_moid) as claims by adm_ip | sort 0 adm_ip host adm_moid | head ${VMWARE_LABEL_LIMITS.rows + 1} | fields adm_ip host vm_name vm_id hypervisor cluster reported claims`;
}

export function parseVmwareInventory(
  rows: Record<string, unknown>[],
  addresses: string[],
): { labels: VmwareInventoryLabel[]; capped: boolean } {
  const wanted = new Set(addresses);
  const optional = (value: unknown) =>
    value === undefined || value === null || value === ""
      ? undefined
      : validText(value, 255)
        ? value
        : (() => {
            throw new Error("VMware inventory returned an invalid label.");
          })();
  const labels = rows.slice(0, VMWARE_LABEL_LIMITS.rows).map((row) => {
    const address = normalizeIp(String(row.adm_ip ?? ""));
    const reportedAt = Number(row.reported);
    const claims = Number(row.claims);
    if (
      !wanted.has(address) ||
      !validText(row.vm_name, 255) ||
      !validText(row.host, 255) ||
      !Number.isFinite(reportedAt) ||
      !Number.isInteger(claims) ||
      claims < 1
    )
      throw new Error("VMware inventory returned an invalid label.");
    const vmId = optional(row.vm_id),
      hypervisor = optional(row.hypervisor),
      cluster = optional(row.cluster);
    return {
      address,
      vmName: row.vm_name,
      ...(vmId ? { vmId } : {}),
      ...(hypervisor ? { hypervisor } : {}),
      ...(cluster ? { cluster } : {}),
      vcenter: row.host,
      reportedAt,
      claims,
    };
  });
  return { labels, capped: rows.length > VMWARE_LABEL_LIMITS.rows };
}

export async function loadVmwareInventoryLabels(
  client: SearchClient,
  addresses: string[],
  end: number,
  signal: AbortSignal,
): Promise<VmwareInventoryResult> {
  const window = { start: end - VMWARE_LABEL_LIMITS.lookback, end };
  const result = await client.search({
    search: buildVmwareInventorySearch(addresses, end),
    earliest: String(window.start),
    latest: String(window.end),
    maxRows: VMWARE_LABEL_LIMITS.rows + 1,
    allowEmpty: true,
    signal,
  });
  requireNoSearchErrors(result, "VMware inventory label search");
  if (result.warnings.length)
    throw new Error(
      `VMware inventory label search was incomplete: ${result.warnings[0]}`,
    );
  return { ...parseVmwareInventory(result.rows, addresses), window };
}
