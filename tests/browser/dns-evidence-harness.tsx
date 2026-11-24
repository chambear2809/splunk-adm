import { createRoot } from "react-dom/client";
import { EndpointsPage } from "../../frontend/src/pages/EndpointsPage";
import { EndpointEvidencePanels } from "../../frontend/src/EndpointEvidencePanels";
import type {
  EvidenceConfiguration,
  EvidenceConfigClient,
} from "../../frontend/src/data/evidenceConfig";
import type { SearchClient } from "../../frontend/src/data/searchClient";
import {
  CLOUD_FLOW_PROJECTION,
  parseCloudFlowLine,
} from "../../frontend/src/data/cloudFlowEvidence";
import flowLogs from "../../fixtures/cloud-flow/records-v5.json";
import stream from "../../fixtures/dns/stream-transaction.json";
import "../../frontend/src/styles.css";

const params = new URLSearchParams(location.search),
  fault = params.get("fault");
const now = 1791373600;
const config: EvidenceConfiguration = {
  fingerprint: "a".repeat(64),
  trafficContract: 1,
  summaryIndexes: ["adm_summary"],
  maxAgeSeconds: 3600,
  identityAvailable: true,
  identities: [],
  mappings: [
    {
      observer_kind: "dns_sensor",
      observer: "sensor-east",
      scope: "prod",
      cluster: "",
      mapping_status: "verified",
    },
  ],
  dns: [
    {
      source: "dns_stream",
      state: fault === "off" ? "not_selected" : "active",
      indexes: [stream.index],
      authorities: [stream.host],
      schemaQualified: false,
    },
    {
      source: "dns_hubble",
      state: "not_selected",
      indexes: [],
      authorities: [],
      schemaQualified: false,
    },
  ],
  supplemental: (
    ["proxy_envoy", "aws_vpc_flow", "asset_history", "o11y_health"] as const
  ).map((source) => ({
    source,
    state: "not_selected" as const,
    indexes: [],
    authorities: [],
    schemaQualified: false,
    staleAfterSeconds: 3600,
    mappings: [],
  })),
};
if (fault === "cloud-cap") {
  config.supplemental = [
    ...(config.supplemental ?? []).filter(
      (item) => item.source !== "aws_vpc_flow",
    ),
    {
      source: "aws_vpc_flow",
      state: "active",
      indexes: ["aws_flow"],
      authorities: ["collector-a"],
      schemaQualified: true,
      staleAfterSeconds: 3600,
      mappings: [
        {
          observer_kind: "aws_vpc_flow",
          observer: "collector-a",
          scope: "prod",
          cluster: "",
          mapping_status: "verified",
          account_id: "123456789012",
          region: "us-east-1",
          vpc_id: "vpc-0abc1234",
        },
      ],
    },
  ];
}
const configClient: EvidenceConfigClient = {
  read: async () => structuredClone(config),
};
const client: SearchClient = {
  search: async (request) => {
    const target = window as Window & { __DNS_SEARCHES__?: string[] };
    (target.__DNS_SEARCHES__ ??= []).push(request.search);
    request.onLifecycle?.({ state: "creating" });
    request.onLifecycle?.({ state: "created", sid: "mock-id" });
    try {
      if (
        fault === "cloud-cap" &&
        request.search.includes('sourcetype="aws:vpcflow:v5"')
      ) {
        const status = !request.search.includes("192.0.2.10");
        const record = flowLogs.records.find(
          (row) =>
            row.id === (status ? "skipped-capture-interval" : "accepted-flow"),
        )!;
        const fields = parseCloudFlowLine(
          record.raw.replaceAll("10.0.1.25", "192.0.2.10"),
        );
        const projection = Object.fromEntries(
          CLOUD_FLOW_PROJECTION.map(([field, column]) => [
            column,
            fields[field],
          ]),
        );
        const count = status ? 64 : 1;
        return {
          rows: [
            ...Array.from({ length: count }, (_, i) => ({
              ...projection,
              kind: "supplemental_record",
              flow_field_count: 29,
              host: "collector-a",
              index: "aws_flow",
              event_fingerprint: i.toString(16).padStart(64, "0"),
              event_time_epoch: fields.start,
              _indextime: "1791373500",
            })),
            {
              kind: "supplemental_completion",
              schema_version: 1,
              input_count: status ? 65 : 1,
              returned_count: count,
              input_capped: 0,
              oversized: 0,
            },
          ],
          warnings: [],
          errors: [],
        };
      }
      if (request.search.includes("dns_completion")) {
        if (fault === "denied") throw Error("caller permission denied");
        if (fault === "slow")
          await new Promise<void>((resolve, reject) => {
            const timer = setTimeout(resolve, 10000);
            request.signal.addEventListener(
              "abort",
              () => {
                clearTimeout(timer);
                reject(Error("cancelled"));
              },
              { once: true },
            );
          });
        const n = fault === "cap" ? 64 : 1;
        return {
          rows: [
            ...Array.from({ length: n }, (_, i) => ({
              ...stream,
              event_fingerprint: i.toString(16).padStart(64, "0"),
              kind: "dns_record",
            })),
            {
              kind: "dns_completion",
              schema_version: "1",
              input_count: fault === "cap" ? "65" : String(n),
              returned_count: String(n),
              input_capped: "0",
              oversized: "0",
            },
          ],
          warnings: [],
          errors: [],
        };
      }
      const rows =
        fault === "dns-only"
          ? []
          : [
              {
                row_type: "conversation",
                scope: "prod",
                adm_root: "192.0.2.10",
                adm_client: "192.0.2.10",
                adm_server: "198.51.100.20",
                adm_peer: "198.51.100.20",
                adm_port: "443",
                adm_transport: "tcp",
                adm_first: "1791373501",
                adm_last: "1791373502",
                adm_records: "1",
                adm_conns: "50000@1791373501@1791373502",
                adm_sampled: "0",
                adm_context_capped: "0",
                adm_direction: "initiator",
                adm_source: "hubble",
                adm_observer: "hubble:worker",
                adm_bcs: "100",
                adm_bsc: "200",
                adm_packets: "3",
              },
            ];
      return {
        rows: [
          ...rows,
          {
            row_type: "completion",
            schema_version: "1",
            input_count: String(rows.length),
            output_count: String(rows.length),
            unprotected_count: "0",
            input_capped: "0",
            output_capped: "0",
          },
        ],
        warnings: [],
        errors: [],
      };
    } finally {
      request.onLifecycle?.({ state: "released", sid: "mock-id" });
    }
  },
};
document.documentElement.dataset.theme =
  params.get("theme") === "dark" ? "dark" : "light";
// Exercise the same validated peer-link path as a native Splunk view.
history.replaceState(
  null,
  "",
  `/en-US/app/splunk_adm/endpoints${location.search}`,
);
createRoot(document.getElementById("root")!).render(
  <div
    className="adm atlas dns-verification"
    data-adm-theme={params.get("theme") === "dark" ? "dark" : "light"}
  >
    <EndpointsPage
      client={client}
      live
      configurationClient={configClient}
      initial={{
        address: "192.0.2.10",
        scope: "prod",
        start: now - 3600,
        end: now,
      }}
      renderEvidence={(selection) => (
        <EndpointEvidencePanels
          selection={selection}
          client={client}
          configurationClient={configClient}
        />
      )}
    />
  </div>,
);
