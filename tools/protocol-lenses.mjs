import { createHash } from "node:crypto";
import { readFileSync, readdirSync } from "node:fs";
import { resolve } from "node:path";

export const PROTOCOLS_HOST_MODULES = {
  "frontend/src/data/deploymentHealth": "deploymentHealth",
  "frontend/src/data/evidence": "evidence",
  "frontend/src/data/evidenceConfig": "evidenceConfig",
  "frontend/src/data/optionalJobs": "optionalJobs",
  "frontend/src/data/searchClient": "searchClient",
  "frontend/src/app/urlState": "urlState",
};

export const PROTOCOLS_CORE_SDK_MODULES = {
  "frontend/src/protocols/shared/contract": "contract",
  "frontend/src/protocols/shared/fields": "fields",
  "frontend/src/protocols/shared/filterSpl": "filterSpl",
  "frontend/src/protocols/shared/format": "format",
  "frontend/src/protocols/shared/runner": "runner",
  "frontend/src/protocols/shared/metricsRunner": "metricsRunner",
  "frontend/src/protocols/shared/streamReadiness": "streamReadiness",
  "frontend/src/protocols/shared/adapters/nxosSyslog": "nxosSyslog",
  "frontend/src/protocols/shared/adapters/multiVendorSyslog":
    "multiVendorSyslog",
  "frontend/src/protocols/shared/ui": "ui",
  "frontend/src/protocols/shared/ui/index": "ui",
};

/**
 * Every implemented protocol lens compiled as its own optional IIFE asset
 * (`pages/protocol-<id>.js` + `protocol-<id>-manifest.json`, <= 64 KiB gzip).
 */
export const IMPLEMENTED_PROTOCOL_LENSES = [
  {
    id: "tcp_tls",
    pageExport: "TcpTlsLensPage",
    summarizeExport: "summarizeTcpTls",
  },
  {
    id: "dns_ops",
    pageExport: "DnsOpsLensPage",
    summarizeExport: "summarizeDnsOps",
  },
  {
    id: "routing",
    pageExport: "RoutingLensPage",
    summarizeExport: "summarizeRouting",
  },
  {
    id: "l2_control",
    pageExport: "L2ControlLensPage",
    summarizeExport: "summarizeL2Control",
  },
  {
    id: "interface_health",
    pageExport: "InterfaceHealthLensPage",
    summarizeExport: "summarizeInterfaceHealth",
  },
  {
    id: "qos_icmp",
    pageExport: "QosIcmpLensPage",
    summarizeExport: "summarizeQosIcmp",
  },
  {
    id: "enterprise_l7",
    pageExport: "EnterpriseL7LensPage",
    summarizeExport: "summarizeEnterpriseL7",
  },
  {
    id: "drops",
    pageExport: "DropsLensPage",
    summarizeExport: "summarizeDrops",
  },
  {
    id: "endpoint_mobility",
    pageExport: "EndpointMobilityLensPage",
    summarizeExport: "summarizeEndpointMobility",
  },
  {
    id: "app_transactions",
    pageExport: "AppTransactionsLensPage",
    summarizeExport: "summarizeAppTransactions",
  },
  {
    id: "state_events",
    pageExport: "StateEventsLensPage",
    summarizeExport: "summarizeStateEvents",
  },
  {
    id: "mgmt_plane",
    pageExport: "MgmtPlaneLensPage",
    summarizeExport: "summarizeMgmtPlane",
  },
  {
    id: "lb_health",
    pageExport: "LbHealthLensPage",
    summarizeExport: "summarizeLbHealth",
  },
];

function collectLensFiles(lensId) {
  const dir = `frontend/src/protocols/lenses/${lensId}`;
  const out = [];
  for (const entry of readdirSync(resolve(dir), { withFileTypes: true })) {
    if (!entry.isFile()) continue;
    if (/\.(tsx?|css)$/.test(entry.name) && !entry.name.includes(".test.")) {
      out.push(`${dir}/${entry.name}`);
    }
  }
  return out;
}

export function protocolLensAssetVersion(lensId) {
  const hash = createHash("sha256");
  const files = [
    "package-lock.json",
    "tools/protocol-lenses.mjs",
    "tools/build-protocol-lenses.mjs",
    ...collectLensFiles(lensId),
  ];
  for (const file of files.sort()) {
    hash.update(file).update(readFileSync(resolve(file)));
  }
  return hash.digest("hex").slice(0, 24);
}

export function protocolLensVersions() {
  const versions = {};
  for (const lens of IMPLEMENTED_PROTOCOL_LENSES) {
    versions[lens.id] = protocolLensAssetVersion(lens.id);
  }
  return versions;
}

const hostModules = new Map([
  ["react", "react"],
  ["react/jsx-runtime", "jsxRuntime"],
  ...Object.entries(PROTOCOLS_HOST_MODULES).map(([path, name]) => [
    resolve(path),
    name,
  ]),
]);

const coreModules = new Map(
  Object.entries(PROTOCOLS_CORE_SDK_MODULES).map(([path, name]) => [
    resolve(path),
    name,
  ]),
);

export function protocolsCoreHostModule(id) {
  return hostModules.get(id.replace(/\.tsx?$/, ""));
}

export function protocolLensExternalGlobal(id) {
  const normalized = id.replace(/\.tsx?$/, "");
  const hostName = hostModules.get(normalized);
  if (hostName) return `__AtlasProtocolsHost.${hostName}`;
  const coreName = coreModules.get(normalized);
  if (coreName) return `__AtlasProtocolsCore.${coreName}`;
  return undefined;
}
