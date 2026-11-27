import { useState } from "react";
import { createRoot } from "react-dom/client";
import ThemeProviderExport from "@splunk/themes/SplunkThemeProvider";
import { toolkitDefault } from "../../frontend/src/app/interop";
import { Shell } from "../../frontend/src/app/Shell";
import { ProtocolsPage } from "../../frontend/src/protocols/ProtocolsPage";
import { TcpTlsLensPage } from "../../frontend/src/protocols/lenses/tcp_tls/TcpTlsLensPage";
import {
  buildTcpTlsAnalysis,
  normalizeTcpTlsRow,
  DEFAULT_TCP_TLS_THRESHOLDS,
} from "../../frontend/src/protocols/lenses/tcp_tls/adapter";
import { DnsOpsLensPage } from "../../frontend/src/protocols/lenses/dns_ops/DnsOpsLensPage";
import {
  buildDnsOpsAnalysis,
  normalizeDnsOpsRow,
  DEFAULT_DNS_OPS_THRESHOLDS,
} from "../../frontend/src/protocols/lenses/dns_ops/adapter";
import { RoutingLensPage } from "../../frontend/src/protocols/lenses/routing/RoutingLensPage";
import {
  buildRoutingAnalysis,
  normalizeRoutingDmeRow,
  normalizeRoutingSyslogRow,
  DEFAULT_ROUTING_THRESHOLDS,
} from "../../frontend/src/protocols/lenses/routing/adapter";
import { L2ControlLensPage } from "../../frontend/src/protocols/lenses/l2_control/L2ControlLensPage";
import {
  buildL2ControlAnalysis,
  normalizeL2ControlRow,
  DEFAULT_L2_CONTROL_THRESHOLDS,
} from "../../frontend/src/protocols/lenses/l2_control/adapter";
import { InterfaceHealthLensPage } from "../../frontend/src/protocols/lenses/interface_health/InterfaceHealthLensPage";
import {
  buildInterfaceHealthAnalysis,
  normalizeInterfaceDmeRow,
  normalizeInterfaceSyslogRow,
  DEFAULT_INTERFACE_HEALTH_THRESHOLDS,
} from "../../frontend/src/protocols/lenses/interface_health/adapter";
import { QosIcmpLensPage } from "../../frontend/src/protocols/lenses/qos_icmp/QosIcmpLensPage";
import {
  buildQosIcmpAnalysis,
  normalizeQosIcmpRow,
  DEFAULT_QOS_ICMP_THRESHOLDS,
} from "../../frontend/src/protocols/lenses/qos_icmp/adapter";
import { EnterpriseL7LensPage } from "../../frontend/src/protocols/lenses/enterprise_l7/EnterpriseL7LensPage";
import {
  buildEnterpriseL7Analysis,
  normalizeEnterpriseL7Row,
  DEFAULT_ENTERPRISE_L7_THRESHOLDS,
} from "../../frontend/src/protocols/lenses/enterprise_l7/adapter";
import { DropsLensPage } from "../../frontend/src/protocols/lenses/drops/DropsLensPage";
import {
  buildDropsAnalysis,
  normalizeDropsRow,
  DEFAULT_DROPS_THRESHOLDS,
} from "../../frontend/src/protocols/lenses/drops/adapter";
import { EndpointMobilityLensPage } from "../../frontend/src/protocols/lenses/endpoint_mobility/EndpointMobilityLensPage";
import {
  buildEndpointMobilityAnalysis,
  normalizeEndpointMobilityRow,
  DEFAULT_ENDPOINT_MOBILITY_THRESHOLDS,
} from "../../frontend/src/protocols/lenses/endpoint_mobility/adapter";
import { AppTransactionsLensPage } from "../../frontend/src/protocols/lenses/app_transactions/AppTransactionsLensPage";
import {
  buildAppTransactionsAnalysis,
  normalizeAppTransactionRow,
  DEFAULT_APP_TRANSACTIONS_THRESHOLDS,
} from "../../frontend/src/protocols/lenses/app_transactions/adapter";
import { StateEventsLensPage } from "../../frontend/src/protocols/lenses/state_events/StateEventsLensPage";
import {
  buildStateEventsAnalysis,
  normalizeStateSyslogRow,
  normalizeAciFaultEventRow,
  DEFAULT_STATE_EVENTS_THRESHOLDS,
} from "../../frontend/src/protocols/lenses/state_events/adapter";
import { MgmtPlaneLensPage } from "../../frontend/src/protocols/lenses/mgmt_plane/MgmtPlaneLensPage";
import {
  buildMgmtPlaneAnalysis,
  normalizeMgmtPlaneRow,
  DEFAULT_MGMT_PLANE_THRESHOLDS,
} from "../../frontend/src/protocols/lenses/mgmt_plane/adapter";
import { LbHealthLensPage } from "../../frontend/src/protocols/lenses/lb_health/LbHealthLensPage";
import {
  buildLbHealthAnalysis,
  normalizeLbHealthRow,
  DEFAULT_LB_HEALTH_THRESHOLDS,
} from "../../frontend/src/protocols/lenses/lb_health/adapter";
import {
  AdjacencyOverlay,
  CopyableIp,
  DistributionBar,
  HeatMatrix,
  ProtocolLensLayout,
  StatusChip,
  SwimlaneTimeline,
  type BannerState,
} from "../../frontend/src/protocols/shared/ui";
import type { ProtocolViewMode } from "../../frontend/src/protocols/shared/contract";
import "../../frontend/src/styles.css";
import "../../frontend/src/protocols/protocols.css";

const ThemeProvider = toolkitDefault(ThemeProviderExport);
const params = new URLSearchParams(location.search);
const theme = params.get("theme") === "dark" ? "dark" : "light";
const scenario = params.get("scenario") ?? "sample_lens";
const stateParam = params.get("state") as BannerState | null;

const NOW = 1800000000;
const EARLIEST = NOW - 900;

interface SampleRow {
  id: string;
  attention: boolean;
  client: string;
  server: string;
  rttMs: number;
  retransPct: string;
  status: "ok" | "attention";
}

const SAMPLE_ROWS: SampleRow[] = [
  {
    id: "pair-1",
    attention: true,
    client: "198.18.38.241",
    server: "198.18.38.242",
    rttMs: 48.2,
    retransPct: "4.8%",
    status: "attention",
  },
  {
    id: "pair-2",
    attention: true,
    client: "198.18.38.241",
    server: "198.18.131.3",
    rttMs: 31.4,
    retransPct: "2.1%",
    status: "attention",
  },
  {
    id: "pair-3",
    attention: false,
    client: "10.64.9.241",
    server: "198.18.38.242",
    rttMs: 2.3,
    retransPct: "0.0%",
    status: "ok",
  },
];

function SampleLensShowcase() {
  const [view, setView] = useState<ProtocolViewMode>(
    params.get("view") === "matrix" ? "matrix" : "overview",
  );
  const [scope, setScope] = useState("lab:dc1");
  const [selected, setSelected] = useState<SampleRow | undefined>(
    params.get("drawer") === "open" ? SAMPLE_ROWS[0] : undefined,
  );
  const [selectedCell, setSelectedCell] = useState<
    { row: string; col: string } | undefined
  >(
    params.get("drawer") === "open"
      ? { row: "198.18.38.241", col: "198.18.38.242" }
      : undefined,
  );

  return (
    <ProtocolLensLayout
      title="TCP Health & TLS"
      scope={scope}
      scopes={["lab:dc1", "lab:dc2"]}
      earliest={EARLIEST}
      latest={NOW}
      view={view}
      coverageStatus={stateParam === "unavailable" ? "not_covered" : "ok"}
      coverageLabel={stateParam === "unavailable" ? "Not covered" : "2 sources"}
      verdict="2 of 3 pairs need attention: 4.8% retransmits on 198.18.38.241 → 198.18.38.242"
      verdictStatus="attention"
      kpis={[
        {
          id: "rtt",
          label: "Server RTT p95",
          value: "48.2",
          unit: "ms",
          status: "attention",
          sparkline: [12, 18, 22, 34, 48],
        },
        {
          id: "retrans",
          label: "Retransmits",
          value: "4.8",
          unit: "%",
          status: "attention",
          sparkline: [0.4, 0.9, 1.8, 3.2, 4.8],
        },
        {
          id: "resets",
          label: "Resets",
          value: "14",
          unit: "flows",
          status: "ok",
          sparkline: [10, 12, 11, 13, 14],
        },
        {
          id: "tls",
          label: "Expiring certs",
          value: "1",
          unit: "cert",
          status: "attention",
          sparkline: [0, 0, 1, 1, 1],
        },
      ]}
      banner={
        stateParam
          ? {
              state: stateParam,
              ...(stateParam === "stale_config" ? { onAction: () => {} } : {}),
            }
          : undefined
      }
      rows={stateParam === "empty" ? [] : SAMPLE_ROWS}
      columns={[
        {
          key: "client",
          header: "Client",
          render: (r) => <CopyableIp value={r.client} />,
        },
        {
          key: "server",
          header: "Server",
          render: (r) => <CopyableIp value={r.server} />,
        },
        {
          key: "rtt",
          header: "Server RTT",
          align: "right",
          render: (r) => `${r.rttMs} ms`,
        },
        {
          key: "retrans",
          header: "Retransmits",
          align: "right",
          render: (r) => r.retransPct,
        },
        {
          key: "status",
          header: "Status",
          render: (r) => <StatusChip status={r.status} />,
        },
      ]}
      matrixView={
        <HeatMatrix
          title="Client × server health"
          rowHeader="Client"
          rows={["198.18.38.241", "10.64.9.241"]}
          columns={["198.18.38.242", "198.18.131.3", "198.18.131.4"]}
          selectedCell={selectedCell}
          cells={[
            {
              row: "198.18.38.241",
              col: "198.18.38.242",
              status: "attention",
              value: "4.8%",
            },
            {
              row: "198.18.38.241",
              col: "198.18.131.3",
              status: "attention",
              value: "2.1%",
            },
            {
              row: "198.18.38.241",
              col: "198.18.131.4",
              status: "not_covered",
              value: "Not covered",
            },
            {
              row: "10.64.9.241",
              col: "198.18.38.242",
              status: "ok",
              value: "0.0%",
            },
            {
              row: "10.64.9.241",
              col: "198.18.131.3",
              status: "none_observed",
              value: "",
            },
            {
              row: "10.64.9.241",
              col: "198.18.131.4",
              status: "unknown",
              value: "Unknown",
            },
          ]}
          onSelectCell={(cell) => {
            setSelectedCell({ row: cell.row, col: cell.col });
            const matched = SAMPLE_ROWS.find(
              (r) => r.client === cell.row && r.server === cell.col,
            );
            setSelected(
              matched ?? {
                id: `${cell.row}-${cell.col}`,
                attention: cell.status === "attention",
                client: cell.row,
                server: cell.col,
                rttMs: 0,
                retransPct: cell.value || "—",
                status: cell.status === "attention" ? "attention" : "ok",
              },
            );
          }}
        />
      }
      extraOverview={
        <>
          <DistributionBar
            title="RTT distribution"
            items={[
              {
                id: "s1",
                label: "198.18.38.242",
                p50: 14,
                p95: 48,
                unit: "ms",
                status: "attention",
              },
              {
                id: "s2",
                label: "198.18.131.3",
                p50: 8,
                p95: 31,
                unit: "ms",
                status: "ok",
              },
            ]}
          />
          <SwimlaneTimeline
            title="Pair event timeline"
            earliest={EARLIEST}
            latest={NOW}
            events={[
              {
                id: "e1",
                lane: "198.18.38.242",
                timestamp: EARLIEST + 180,
                kind: "attention",
                label: "Retransmit burst",
              },
              {
                id: "e2",
                lane: "198.18.38.242",
                timestamp: EARLIEST + 620,
                kind: "ok",
                label: "Recovered",
              },
            ]}
          />
          <AdjacencyOverlay
            title="Observed adjacency"
            nodes={[
              { id: "n1", label: "Leaf1", status: "ok" },
              { id: "n2", label: "Leaf2", status: "attention" },
              { id: "n3", label: "Spine1", status: "ok" },
            ]}
            edges={[
              { id: "ed1", from: "n1", to: "n3", status: "ok" },
              { id: "ed2", from: "n2", to: "n3", status: "attention" },
            ]}
          />
        </>
      }
      drawerTitle={
        selected ? `${selected.client} → ${selected.server}` : undefined
      }
      drawerTitleNode={
        selected ? (
          <span>
            <CopyableIp value={selected.client} label="client" /> →{" "}
            <CopyableIp value={selected.server} label="server" />
          </span>
        ) : undefined
      }
      drawerOpen={!!selected}
      drawerBody={
        selected ? (
          <dl className="pl-kv">
            <dt>Server RTT p95</dt>
            <dd className="pl-mono">{selected.rttMs} ms</dd>
            <dt>Retransmit ratio</dt>
            <dd className="pl-mono">{selected.retransPct}</dd>
            <dt>Status</dt>
            <dd>
              <StatusChip status={selected.status} />
            </dd>
          </dl>
        ) : undefined
      }
      rawEventsLink="/app/splunk_adm/search"
      onScopeChange={setScope}
      onViewChange={setView}
      onInvestigate={() => {}}
      onBackToHub={() => {}}
      onSelectRow={setSelected}
      onCloseDrawer={() => {
        setSelected(undefined);
        setSelectedCell(undefined);
      }}
    />
  );
}

function TcpTlsShowcase({ mode }: { mode: "stream_tcp" | "netflow" }) {
  const [view, setView] = useState<ProtocolViewMode>(
    params.get("view") === "matrix" ? "matrix" : "overview",
  );
  const [scope, setScope] = useState("lab:dc1");
  const [selectedItem, setSelectedItem] = useState<string | undefined>(
    params.get("drawer") === "open" ? "198.18.38.11__198.18.38.21" : undefined,
  );
  const rawRows =
    mode === "netflow"
      ? [
          {
            _time: EARLIEST + 120,
            host: "leaf1",
            sourcetype: "stream:netflow",
            exporter_ip: "198.18.131.3",
            src_ip: "198.18.38.11",
            dest_ip: "198.18.38.21",
            src_port: 51200,
            dest_port: 443,
            total_bytes: 512000,
            total_packets: 500,
          },
          {
            _time: EARLIEST + 240,
            host: "leaf2",
            sourcetype: "stream:netflow",
            exporter_ip: "198.18.131.4",
            src_ip: "198.18.38.10",
            dest_ip: "198.18.38.20",
            src_port: 51422,
            dest_port: 443,
            total_bytes: 22600,
            total_packets: 40,
          },
        ]
      : [
          {
            _time: EARLIEST + 100,
            host: "stream-fwd-01",
            sourcetype: "stream:tcp",
            src_ip: "198.18.38.10",
            dest_ip: "198.18.38.20",
            dest_port: 443,
            client_rtt: 4200,
            server_rtt: 11800,
            client_rtt_packets: 12,
            server_rtt_packets: 12,
            bytes_in: 18400,
            bytes_out: 4200,
            packets_in: 24,
            packets_out: 16,
            tcp_status: 0,
            ssl_version: "TLSv1.3",
            ssl_cipher_name: "TLS_AES_256_GCM_SHA384",
            ssl_subject: "CN=api.internal.example",
            ssl_issuer: "CN=Corp Internal CA",
            ssl_cert_days_remaining: 180,
          },
          {
            _time: EARLIEST + 200,
            host: "stream-fwd-01",
            sourcetype: "stream:tcp",
            src_ip: "198.18.38.11",
            dest_ip: "198.18.38.21",
            dest_port: 443,
            client_rtt: 14200,
            server_rtt: 68400,
            client_rtt_packets: 20,
            server_rtt_packets: 20,
            bytes_in: 512000,
            bytes_out: 12800,
            packets_in: 400,
            packets_out: 100,
            duplicate_packets_in: 18,
            duplicate_packets_out: 6,
            tcp_status: 0,
            ssl_version: "TLSv1.2",
            ssl_cipher_name: "ECDHE-RSA-AES128-GCM-SHA256",
            ssl_subject: "CN=orders.internal.example",
            ssl_issuer: "CN=Corp Internal CA",
            ssl_cert_days_remaining: 9,
          },
          {
            _time: EARLIEST + 300,
            host: "stream-fwd-01",
            sourcetype: "stream:tcp",
            src_ip: "198.18.38.12",
            dest_ip: "198.18.38.22",
            dest_port: 8443,
            client_rtt: 6500,
            server_rtt: 18900,
            client_rtt_packets: 4,
            server_rtt_packets: 4,
            bytes_in: 1200,
            bytes_out: 980,
            packets_in: 8,
            packets_out: 6,
            refused: true,
            tcp_status: 1,
            ssl_version: "TLSv1.0",
            ssl_cipher_name: "ECDHE-RSA-AES128-SHA",
            ssl_subject: "CN=legacy-erp.internal.example",
            ssl_issuer: "CN=Legacy Root CA",
            ssl_cert_days_remaining: 95,
          },
        ];
  const st = mode === "netflow" ? "stream:netflow" : "stream:tcp";
  const indexName = mode === "netflow" ? "netflow" : "stream_tcp";
  const events = rawRows
    .map((row) => normalizeTcpTlsRow(row, st, NOW))
    .filter((ev): ev is NonNullable<typeof ev> => Boolean(ev))
    .map((event) => ({ event, indexName }));
  const initialResult = buildTcpTlsAnalysis({
    events,
    thresholds: { ...DEFAULT_TCP_TLS_THRESHOLDS, sourcetype: st },
    outcomes: [
      {
        source: "protocol_tcp_tls",
        profile: mode === "netflow" ? "nf-dc1" : "tcp-dc1",
        state: "complete",
        inputRows: events.length,
        capped: false,
      },
    ],
    capped: false,
    earliest: EARLIEST,
    latest: NOW,
  });

  return (
    <TcpTlsLensPage
      live={false}
      theme={theme}
      scope={scope}
      scopes={["lab:dc1"]}
      earliest={EARLIEST}
      latest={NOW}
      view={view}
      selectedItem={selectedItem}
      configuration={{
        profiles: [
          {
            id: mode === "netflow" ? "nf-dc1" : "tcp-dc1",
            source: "protocol_tcp_tls",
            lens: "tcp_tls",
            scope: "lab:dc1",
            index: mode === "netflow" ? "netflow" : "stream_tcp",
            observer: "stream-fwd-01",
            validFrom: EARLIEST - 3600,
            validUntil: NOW + 3600,
            extra: { sourcetype: st },
          },
        ],
        fingerprint: "harness-fp",
      }}
      initialResult={initialResult}
      skipConfigRecheck
      onBackToHub={() => {}}
      onRefreshConfig={() => {}}
      onChangeParams={(patch) => {
        if (patch.scope) setScope(patch.scope);
        if (patch.view) setView(patch.view);
        if ("item" in patch) setSelectedItem(patch.item);
      }}
    />
  );
}

function TcpTlsScopeRaceShowcase() {
  const [scope, setScope] = useState("lab:dc1");
  const [view, setView] = useState<ProtocolViewMode>("overview");
  const [abortedCount, setAbortedCount] = useState(0);
  const client = {
    search: ({ signal }: { signal?: AbortSignal }) =>
      new Promise<{
        rows: Record<string, unknown>[];
        warnings: string[];
        errors: string[];
      }>((resolve) => {
        signal?.addEventListener("abort", () => {
          setAbortedCount((n) => n + 1);
        });
        setTimeout(() => {
          resolve({
            rows: [
              {
                _time: EARLIEST + 60,
                host: "stream-fwd-01",
                sourcetype: "stream:tcp",
                src_ip: "198.18.99.1",
                dest_ip: "198.18.99.2",
                dest_port: 443,
                client_rtt: 4000,
                server_rtt: 85000,
                packets_in: 100,
                packets_out: 100,
                tcp_status: 1,
              },
            ],
            warnings: [],
            errors: [],
          });
        }, 200);
      }),
  };

  return (
    <div
      data-testid="scope-race-root"
      data-aborted-count={String(abortedCount)}
    >
      <TcpTlsLensPage
        client={client}
        live
        theme={theme}
        scope={scope}
        scopes={["lab:dc1", "lab:dc2"]}
        earliest={EARLIEST}
        latest={NOW}
        view={view}
        configuration={{
          profiles: [
            {
              id: "tcp-dc1",
              source: "protocol_tcp_tls",
              lens: "tcp_tls",
              scope: "lab:dc1",
              index: "stream_tcp",
              observer: "stream-fwd-01",
              validFrom: EARLIEST - 3600,
              validUntil: NOW + 3600,
              extra: { sourcetype: "stream:tcp" },
            },
            {
              id: "tcp-dc2",
              source: "protocol_tcp_tls",
              lens: "tcp_tls",
              scope: "lab:dc2",
              index: "stream_tcp",
              observer: "stream-fwd-02",
              validFrom: EARLIEST - 3600,
              validUntil: NOW + 3600,
              extra: { sourcetype: "stream:tcp" },
            },
          ],
          fingerprint: "race-fp",
        }}
        skipConfigRecheck
        onBackToHub={() => {}}
        onRefreshConfig={() => {}}
        onChangeParams={(patch) => {
          if (patch.scope) setScope(patch.scope);
          if (patch.view) setView(patch.view);
        }}
      />
    </div>
  );
}

function DnsOpsShowcase() {
  const [view, setView] = useState<ProtocolViewMode>(
    params.get("view") === "matrix" ? "matrix" : "overview",
  );
  const [scope, setScope] = useState("lab:dc1");
  const [selectedItem, setSelectedItem] = useState<string | undefined>(
    params.get("drawer") === "open" ? "10.10.20.12__10.10.0.53" : undefined,
  );
  const rows = [
    {
      _time: EARLIEST + 60,
      host: "stream-01",
      sourcetype: "stream:dns",
      src_ip: "10.10.20.11",
      dest_ip: "10.10.0.53",
      query: "api.prod.example.com",
      query_type: "A",
      reply_code: "NOERROR",
      answer: "10.10.30.40",
      time_taken: 4200,
    },
    {
      _time: EARLIEST + 180,
      host: "stream-01",
      sourcetype: "stream:dns",
      src_ip: "10.10.20.12",
      dest_ip: "10.10.0.53",
      query: "payments.prod.example.com",
      query_type: "A",
      reply_code: "SERVFAIL",
      time_taken: 84000,
    },
    {
      _time: EARLIEST + 240,
      host: "stream-01",
      sourcetype: "stream:dns",
      src_ip: "10.10.20.12",
      dest_ip: "10.10.0.53",
      query: "db.svc.cluster.local.prod.example.com",
      query_type: "A",
      reply_code: "NXDOMAIN",
      time_taken: 62000,
    },
    {
      _time: EARLIEST + 360,
      host: "stream-01",
      sourcetype: "stream:dns",
      src_ip: "10.10.20.15",
      dest_ip: "10.10.0.54",
      query: "auth.prod.example.com",
      query_type: "A",
      reply_code: "NOERROR",
      answer: "10.10.30.50",
      time_taken: 8100,
    },
  ];
  const events = rows
    .map((r) => normalizeDnsOpsRow(r, "stream:dns"))
    .filter((e): e is NonNullable<typeof e> => Boolean(e))
    .map((event) => ({ event, indexName: "stream" }));
  const initialResult = buildDnsOpsAnalysis({
    events,
    thresholds: DEFAULT_DNS_OPS_THRESHOLDS,
    earliest: EARLIEST,
    latest: NOW,
    outcomes: [
      { source: "protocol_dns_ops", profile: "dns-dc1", state: "complete" },
    ],
    capped: false,
  });
  return (
    <DnsOpsLensPage
      live={false}
      theme={theme}
      scope={scope}
      scopes={["lab:dc1"]}
      earliest={EARLIEST}
      latest={NOW}
      view={view}
      selectedItem={selectedItem}
      configuration={{
        profiles: [
          {
            id: "dns-dc1",
            source: "protocol_dns_ops",
            lens: "dns_ops",
            scope: "lab:dc1",
            index: "stream",
            observer: "stream-01",
            validFrom: EARLIEST - 3600,
            validUntil: NOW + 3600,
          },
        ],
        fingerprint: "dns-fp",
      }}
      initialResult={initialResult}
      skipConfigRecheck
      onBackToHub={() => {}}
      onRefreshConfig={() => {}}
      onChangeParams={(patch) => {
        if (patch.scope) setScope(patch.scope);
        if (patch.view) setView(patch.view);
        if ("item" in patch) setSelectedItem(patch.item);
      }}
    />
  );
}

function RoutingShowcase() {
  const [view, setView] = useState<ProtocolViewMode>(
    params.get("view") === "matrix" ? "matrix" : "overview",
  );
  const [scope, setScope] = useState("lab:dc1");
  const [selectedItem, setSelectedItem] = useState<string | undefined>(
    params.get("drawer") === "open"
      ? "leaf1.pseudo.co__BGP__10.255.0.2"
      : undefined,
  );
  const syslogEvents = [
    {
      _time: EARLIEST + 120,
      host: "leaf1.pseudo.co",
      sourcetype: "cisco:ios",
      syslog_msg:
        "%BGP-5-ADJCHANGE: bgp-65001 [default] neighbor 10.255.0.2 Down - Hold Timer Expired",
      neighbor_ip: "10.255.0.2",
      vrf: "default",
    },
    {
      _time: EARLIEST + 300,
      host: "leaf1.pseudo.co",
      sourcetype: "cisco:dc:nexus9k:syslog",
      category: "BFD",
      severity_id: "5",
      mnemonics: "SESSION_STATE_DOWN",
      syslog_msg: "BFD session to 10.255.0.2 on Ethernet1/49 went Down",
      neighbor_ip: "10.255.0.2",
      vrf: "default",
    },
  ]
    .map((r, i) => normalizeRoutingSyslogRow(r, i))
    .filter((e): e is NonNullable<typeof e> => Boolean(e))
    .map((event) => ({ event, indexName: "cisco_dc" }));
  const dmeEvents = [
    {
      _time: EARLIEST + 400,
      host: "leaf1.pseudo.co",
      sourcetype: "cisco:dc:nexus9k:dme",
      dn: "sys/bgp/inst/dom-default/peer-[10.255.0.1]",
      peer_ip: "10.255.0.1",
      peer_asn: "65000",
      local_asn: "65001",
      operSt: "established",
      vrf: "default",
      prefixes_received: 128,
      flap_count: 0,
    },
    {
      _time: EARLIEST + 420,
      host: "leaf2.pseudo.co",
      sourcetype: "cisco:dc:nexus9k:dme",
      dn: "sys/bgp/inst/dom-default/peer-[10.255.0.1]",
      peer_ip: "10.255.0.1",
      peer_asn: "65000",
      local_asn: "65002",
      operSt: "established",
      vrf: "default",
      prefixes_received: 128,
      flap_count: 0,
    },
  ]
    .map((r, i) => normalizeRoutingDmeRow(r, i))
    .filter((e): e is NonNullable<typeof e> => Boolean(e))
    .map((event) => ({ event, indexName: "cisco_dc" }));
  const initialResult = buildRoutingAnalysis({
    events: [...syslogEvents, ...dmeEvents],
    thresholds: DEFAULT_ROUTING_THRESHOLDS,
    earliest: EARLIEST,
    latest: NOW,
    outcomes: [
      { source: "protocol_routing", profile: "routing-dc1", state: "complete" },
    ],
    capped: false,
  });
  return (
    <RoutingLensPage
      live={false}
      theme={theme}
      scope={scope}
      scopes={["lab:dc1"]}
      earliest={EARLIEST}
      latest={NOW}
      view={view}
      selectedItem={selectedItem}
      configuration={{
        profiles: [
          {
            id: "routing-dc1",
            source: "protocol_routing",
            lens: "routing",
            scope: "lab:dc1",
            index: "cisco_dc",
            observer: "leaf1",
            validFrom: EARLIEST - 3600,
            validUntil: NOW + 3600,
          },
        ],
        fingerprint: "routing-fp",
      }}
      initialResult={initialResult}
      skipConfigRecheck
      onBackToHub={() => {}}
      onRefreshConfig={() => {}}
      onChangeParams={(patch) => {
        if (patch.scope) setScope(patch.scope);
        if (patch.view) setView(patch.view);
        if ("item" in patch) setSelectedItem(patch.item);
      }}
    />
  );
}

function L2ControlShowcase() {
  const [view, setView] = useState<ProtocolViewMode>(
    params.get("view") === "matrix" ? "matrix" : "overview",
  );
  const [scope, setScope] = useState("lab:dc1");
  const [selectedItem, setSelectedItem] = useState<string | undefined>();
  const rawRows = [
    {
      _time: EARLIEST + 100,
      host: "dhcp-01",
      sourcetype: "stream:dhcp",
      src_ip: "10.10.20.1",
      dest_ip: "10.10.20.99",
      client_mac: "00:50:56:aa:bb:01",
      dhcp_message_type: "NAK",
      vlan_id: "120",
    },
    {
      _time: EARLIEST + 220,
      host: "leaf1.pseudo.co",
      sourcetype: "cisco:ios",
      syslog_msg:
        "%STP-2-ROOTGUARD_BLOCK: Root guard blocking port Ethernet1/12 on VLAN0120.",
      interface: "Ethernet1/12",
      vlan: "120",
    },
    {
      _time: EARLIEST + 340,
      host: "leaf2.pseudo.co",
      sourcetype: "cisco:dc:nexus9k:syslog",
      category: "LACP",
      severity_id: "5",
      mnemonics: "PORT_STATE",
      syslog_msg: "Ethernet1/8 suspended in port-channel10 (LACP timeout)",
      interface: "Ethernet1/8",
    },
    {
      _time: EARLIEST + 460,
      host: "dhcp-01",
      sourcetype: "stream:dhcp",
      src_ip: "10.10.20.1",
      dest_ip: "10.10.20.55",
      client_mac: "00:50:56:aa:bb:02",
      yiaddr: "10.10.20.55",
      lease_time: 3600,
      dhcp_message_type: "ACK",
      vlan_id: "120",
    },
  ];
  const events = rawRows
    .map((r, i) => normalizeL2ControlRow(r, i))
    .filter((e): e is NonNullable<typeof e> => Boolean(e))
    .map((event) => ({ event, indexName: "cisco_dc" }));
  const initialResult = buildL2ControlAnalysis({
    events,
    thresholds: DEFAULT_L2_CONTROL_THRESHOLDS,
    earliest: EARLIEST,
    latest: NOW,
    outcomes: [
      { source: "protocol_l2_control", profile: "l2-dc1", state: "complete" },
    ],
    capped: false,
    activeSourceKinds: ["stream_dhcp", "syslog"],
  });
  return (
    <L2ControlLensPage
      live={false}
      theme={theme}
      scope={scope}
      scopes={["lab:dc1"]}
      earliest={EARLIEST}
      latest={NOW}
      view={view}
      selectedItem={selectedItem}
      configuration={{
        profiles: [
          {
            id: "l2-dc1",
            source: "protocol_l2_control",
            lens: "l2_control",
            scope: "lab:dc1",
            index: "cisco_dc",
            observer: "leaf1",
            validFrom: EARLIEST - 3600,
            validUntil: NOW + 3600,
          },
        ],
        fingerprint: "l2-fp",
      }}
      initialResult={initialResult}
      skipConfigRecheck
      onBackToHub={() => {}}
      onRefreshConfig={() => {}}
      onChangeParams={(patch) => {
        if (patch.scope) setScope(patch.scope);
        if (patch.view) setView(patch.view);
        if ("item" in patch) setSelectedItem(patch.item);
      }}
    />
  );
}

function InterfaceHealthShowcase() {
  const [view, setView] = useState<ProtocolViewMode>(
    params.get("view") === "matrix" ? "matrix" : "overview",
  );
  const [scope, setScope] = useState("lab:dc1");
  const [selectedItem, setSelectedItem] = useState<string | undefined>();
  const dmeEvents = [
    {
      _time: EARLIEST + 100,
      host: "leaf1.pseudo.co",
      sourcetype: "cisco:dc:nexus9k:dme",
      interface: "Ethernet1/10",
      adminSt: "up",
      operSt: "down",
      speed: "25G",
      mtu: 9216,
      crc_errors: 42,
      in_errors: 48,
      in_discards: 12,
      utilization_pct: 0,
    },
    {
      _time: EARLIEST + 200,
      host: "leaf1.pseudo.co",
      sourcetype: "cisco:dc:nexus9k:dme",
      interface: "Ethernet1/49",
      adminSt: "up",
      operSt: "up",
      speed: "100G",
      mtu: 9216,
      crc_errors: 0,
      in_errors: 0,
      in_discards: 0,
      utilization_pct: 62,
    },
    {
      _time: EARLIEST + 260,
      host: "leaf2.pseudo.co",
      sourcetype: "cisco:dc:nexus9k:dme",
      interface: "Ethernet1/50",
      adminSt: "up",
      operSt: "up",
      speed: "100G",
      mtu: 9216,
      crc_errors: 0,
      in_errors: 0,
      in_discards: 4,
      utilization_pct: 86,
    },
  ]
    .map((r) => normalizeInterfaceDmeRow(r))
    .filter((e): e is NonNullable<typeof e> => Boolean(e))
    .map((event) => ({ event, indexName: "cisco_dc" }));
  const syslogEvents = [
    {
      _time: EARLIEST + 150,
      host: "leaf1.pseudo.co",
      sourcetype: "cisco:dc:nexus9k:syslog",
      category: "ETHPORT",
      severity_id: "5",
      mnemonics: "IF_DOWN_LINK_FAILURE",
      syslog_msg: "Interface Ethernet1/10 is down (Link failure)",
      interface: "Ethernet1/10",
    },
    {
      _time: EARLIEST + 310,
      host: "leaf1.pseudo.co",
      sourcetype: "cisco:dc:nexus9k:syslog",
      category: "ETHPORT",
      severity_id: "5",
      mnemonics: "IF_UP",
      syslog_msg: "Interface Ethernet1/10 is up in mode trunk",
      interface: "Ethernet1/10",
    },
  ]
    .map((r, i) => normalizeInterfaceSyslogRow(r, i))
    .filter((e): e is NonNullable<typeof e> => Boolean(e))
    .map((event) => ({ event, indexName: "cisco_dc" }));
  const initialResult = buildInterfaceHealthAnalysis({
    dmeEvents,
    syslogEvents,
    thresholds: DEFAULT_INTERFACE_HEALTH_THRESHOLDS,
    earliest: EARLIEST,
    latest: NOW,
    outcomes: [
      {
        source: "protocol_interface_health",
        profile: "iface-dc1",
        state: "complete",
      },
    ],
    capped: false,
  });
  return (
    <InterfaceHealthLensPage
      live={false}
      theme={theme}
      scope={scope}
      scopes={["lab:dc1"]}
      earliest={EARLIEST}
      latest={NOW}
      view={view}
      selectedItem={selectedItem}
      configuration={{
        profiles: [
          {
            id: "iface-dc1",
            source: "protocol_interface_health",
            lens: "interface_health",
            scope: "lab:dc1",
            index: "cisco_dc",
            observer: "leaf1",
            validFrom: EARLIEST - 3600,
            validUntil: NOW + 3600,
          },
        ],
        fingerprint: "iface-fp",
      }}
      initialResult={initialResult}
      skipConfigRecheck
      onBackToHub={() => {}}
      onRefreshConfig={() => {}}
      onChangeParams={(patch) => {
        if (patch.scope) setScope(patch.scope);
        if (patch.view) setView(patch.view);
        if ("item" in patch) setSelectedItem(patch.item);
      }}
    />
  );
}

function QosIcmpShowcase() {
  const [view, setView] = useState<ProtocolViewMode>(
    params.get("view") === "matrix" ? "matrix" : "overview",
  );
  const [scope, setScope] = useState("lab:dc1");
  const [selectedItem, setSelectedItem] = useState<string | undefined>();
  const rawRows = [
    {
      _time: EARLIEST + 120,
      host: "leaf1.pseudo.co",
      sourcetype: "stream:netflow",
      exporter_ip: "198.18.131.3",
      src_ip: "10.10.20.11",
      dest_ip: "10.10.30.22",
      src_port: 52100,
      dest_port: 5060,
      protoid: 17,
      tos: 184,
      bytes: 48000,
      packets: 60,
    },
    {
      _time: EARLIEST + 135,
      host: "leaf2.pseudo.co",
      sourcetype: "stream:netflow",
      exporter_ip: "198.18.131.4",
      src_ip: "10.10.20.11",
      dest_ip: "10.10.30.22",
      src_port: 52100,
      dest_port: 5060,
      protoid: 17,
      tos: 0,
      bytes: 48000,
      packets: 60,
    },
    {
      _time: EARLIEST + 240,
      host: "leaf1.pseudo.co",
      sourcetype: "stream:netflow",
      exporter_ip: "198.18.131.3",
      src_ip: "10.10.20.15",
      dest_ip: "10.10.30.40",
      src_port: 49200,
      dest_port: 443,
      protoid: 6,
      tos: 104,
      bytes: 92000,
      packets: 90,
    },
    {
      _time: EARLIEST + 300,
      host: "stream-01",
      sourcetype: "stream:icmp",
      src_ip: "10.10.20.11",
      dest_ip: "10.10.30.22",
      icmp_type: 3,
      icmp_code: 4,
      packets_in: 4,
      bytes_in: 512,
    },
    {
      _time: EARLIEST + 420,
      host: "nd-01",
      sourcetype: "cisco:dc:nd:flows",
      srcIp: "10.10.20.11",
      dstIp: "10.10.30.22",
      srcPort: 52100,
      dstPort: 5060,
      protocolName: "UDP",
      dropPktCount: 14,
      dropReasons: ["QUEUE_DROP"],
      nodeName: "leaf2.pseudo.co",
      fabricName: "pseudoco",
    },
  ];
  const events = rawRows
    .map((r) => normalizeQosIcmpRow(r, "stream:netflow"))
    .filter((e): e is NonNullable<typeof e> => Boolean(e))
    .map((event) => ({ event, indexName: "netflow" }));
  const initialResult = buildQosIcmpAnalysis({
    events,
    thresholds: DEFAULT_QOS_ICMP_THRESHOLDS,
    earliest: EARLIEST,
    latest: NOW,
    outcomes: [
      { source: "protocol_qos_icmp", profile: "qos-dc1", state: "complete" },
    ],
    capped: false,
    netflowConfigured: true,
    icmpConfigured: true,
    ndConfigured: true,
  });
  return (
    <QosIcmpLensPage
      live={false}
      theme={theme}
      scope={scope}
      scopes={["lab:dc1"]}
      earliest={EARLIEST}
      latest={NOW}
      view={view}
      selectedItem={selectedItem}
      configuration={{
        profiles: [
          {
            id: "qos-dc1",
            source: "protocol_qos_icmp",
            lens: "qos_icmp",
            scope: "lab:dc1",
            index: "netflow",
            observer: "leaf1",
            validFrom: EARLIEST - 3600,
            validUntil: NOW + 3600,
          },
        ],
        fingerprint: "qos-fp",
      }}
      initialResult={initialResult}
      skipConfigRecheck
      onBackToHub={() => {}}
      onRefreshConfig={() => {}}
      onChangeParams={(patch) => {
        if (patch.scope) setScope(patch.scope);
        if (patch.view) setView(patch.view);
        if ("item" in patch) setSelectedItem(patch.item);
      }}
    />
  );
}

function EnterpriseL7Showcase() {
  const [view, setView] = useState<ProtocolViewMode>(
    params.get("view") === "matrix" ? "matrix" : "overview",
  );
  const [scope, setScope] = useState("lab:dc1");
  const [selectedItem, setSelectedItem] = useState<string | undefined>();
  const rawRows = [
    {
      _time: EARLIEST + 100,
      host: "stream-01",
      sourcetype: "stream:smb",
      src_ip: "10.10.20.11",
      dest_ip: "10.10.40.10",
      dest_port: 445,
      dialect: "NT LM 0.12",
      status: "STATUS_ACCESS_DENIED",
      time_taken: 42000,
    },
    {
      _time: EARLIEST + 200,
      host: "stream-01",
      sourcetype: "stream:ldap",
      src_ip: "10.10.20.12",
      dest_ip: "10.10.40.20",
      dest_port: 389,
      auth_type: "simple",
      result_code: "0",
      time_taken: 18000,
    },
    {
      _time: EARLIEST + 300,
      host: "stream-01",
      sourcetype: "stream:radius",
      src_ip: "10.10.1.5",
      dest_ip: "10.10.40.30",
      dest_port: 1812,
      nas_ip_address: "10.10.1.5",
      code: "Access-Reject",
      time_taken: 12000,
    },
    {
      _time: EARLIEST + 360,
      host: "stream-01",
      sourcetype: "stream:rtp",
      src_ip: "10.10.20.50",
      dest_ip: "10.10.40.40",
      dest_port: 16384,
      mos: 2.9,
      rtp_jitter: 48,
      packet_loss_pct: 3.2,
      codec: "G.711",
    },
    {
      _time: EARLIEST + 420,
      host: "stream-01",
      sourcetype: "stream:nfs",
      src_ip: "10.10.20.22",
      dest_ip: "10.10.40.50",
      dest_port: 2049,
      nfs_version: "4.1",
      status: "NFS4_OK",
      time_taken: 6500,
    },
  ];
  const events = rawRows
    .map((r) => normalizeEnterpriseL7Row(r))
    .filter((e): e is NonNullable<typeof e> => Boolean(e))
    .map((event) => ({ event, indexName: "stream" }));
  const initialResult = buildEnterpriseL7Analysis({
    events,
    thresholds: DEFAULT_ENTERPRISE_L7_THRESHOLDS,
    configuredProtocols: ["SMB", "NFS", "LDAP", "RADIUS", "VoIP"],
    earliest: EARLIEST,
    latest: NOW,
    outcomes: [
      {
        source: "protocol_enterprise_l7",
        profile: "l7-dc1",
        state: "complete",
      },
    ],
    capped: false,
  });
  return (
    <EnterpriseL7LensPage
      live={false}
      theme={theme}
      scope={scope}
      scopes={["lab:dc1"]}
      earliest={EARLIEST}
      latest={NOW}
      view={view}
      selectedItem={selectedItem}
      configuration={{
        profiles: [
          {
            id: "l7-dc1",
            source: "protocol_enterprise_l7",
            lens: "enterprise_l7",
            scope: "lab:dc1",
            index: "stream",
            observer: "stream-01",
            validFrom: EARLIEST - 3600,
            validUntil: NOW + 3600,
          },
        ],
        fingerprint: "l7-fp",
      }}
      initialResult={initialResult}
      skipConfigRecheck
      onBackToHub={() => {}}
      onRefreshConfig={() => {}}
      onChangeParams={(patch) => {
        if (patch.scope) setScope(patch.scope);
        if (patch.view) setView(patch.view);
        if ("item" in patch) setSelectedItem(patch.item);
      }}
    />
  );
}

function DropsShowcase() {
  const [view, setView] = useState<ProtocolViewMode>(
    params.get("view") === "matrix" ? "matrix" : "overview",
  );
  const [scope, setScope] = useState("lab:dc1");
  const [selectedItem, setSelectedItem] = useState<string | undefined>();
  const rawRows = [
    {
      _time: EARLIEST + 100,
      host: "ftd-01",
      sourcetype: "cisco:sfw:estreamer",
      InitiatorIP: "10.10.20.11",
      InitiatorPort: 51400,
      ResponderIP: "10.10.50.10",
      ResponderPort: 443,
      Protocol: "TCP",
      AC_RuleAction: "Block with reset",
      AccessControlRuleName: "Deny-PCI-EastWest",
      Device: "ftd-edge-01",
      IngressZone: "app",
      EgressZone: "pci",
      InitiatorPackets: 12,
      InitiatorBytes: 1440,
    },
    {
      _time: EARLIEST + 240,
      host: "k8s-worker-01",
      sourcetype: "cilium:hubble:flow",
      verdict: "DROPPED",
      drop_reason_desc: "POLICY_DENIED",
      src_ip: "10.244.1.12",
      dest_ip: "10.244.2.25",
      dest_port: 5432,
      transport: "TCP",
      src_namespace: "frontend",
      dest_namespace: "payments",
    },
    {
      _time: EARLIEST + 360,
      host: "nd-01",
      sourcetype: "cisco:dc:nd:flows",
      srcIp: "10.10.20.18",
      dstIp: "10.10.60.5",
      dstPort: 9092,
      protocolName: "TCP",
      dropPktCount: 48,
      dropReasons: ["ACL_DROP"],
      fabricName: "pseudoco",
    },
  ];
  const events = rawRows
    .map((r) => normalizeDropsRow(r))
    .filter((e): e is NonNullable<typeof e> => Boolean(e))
    .map((event) => ({ event, indexName: "cisco_secure_fw" }));
  const initialResult = buildDropsAnalysis({
    events,
    thresholds: DEFAULT_DROPS_THRESHOLDS,
    earliest: EARLIEST,
    latest: NOW,
    outcomes: [
      { source: "protocol_drops", profile: "drops-dc1", state: "complete" },
    ],
    capped: false,
  });
  return (
    <DropsLensPage
      live={false}
      theme={theme}
      scope={scope}
      scopes={["lab:dc1"]}
      earliest={EARLIEST}
      latest={NOW}
      view={view}
      selectedItem={selectedItem}
      configuration={{
        profiles: [
          {
            id: "drops-dc1",
            source: "protocol_drops",
            lens: "drops",
            scope: "lab:dc1",
            index: "cisco_secure_fw",
            observer: "ftd-01",
            validFrom: EARLIEST - 3600,
            validUntil: NOW + 3600,
          },
        ],
        fingerprint: "drops-fp",
      }}
      initialResult={initialResult}
      skipConfigRecheck
      onBackToHub={() => {}}
      onRefreshConfig={() => {}}
      onChangeParams={(patch) => {
        if (patch.scope) setScope(patch.scope);
        if (patch.view) setView(patch.view);
        if ("item" in patch) setSelectedItem(patch.item);
      }}
    />
  );
}

function EndpointMobilityShowcase() {
  const [view, setView] = useState<ProtocolViewMode>(
    params.get("view") === "matrix" ? "matrix" : "overview",
  );
  const [scope, setScope] = useState("lab:dc1");
  const [selectedItem, setSelectedItem] = useState<string | undefined>();
  const rawRows = [
    {
      _time: EARLIEST + 100,
      host: "stream-01",
      sourcetype: "stream:arp",
      sender_ip: "10.10.20.42",
      sender_mac: "00:50:56:aa:11:01",
      target_ip: "10.10.20.1",
      arp_opcode: "request",
      vlan_id: "120",
    },
    {
      _time: EARLIEST + 180,
      host: "stream-01",
      sourcetype: "stream:arp",
      sender_ip: "10.10.20.42",
      sender_mac: "00:50:56:bb:22:02",
      target_ip: "10.10.20.1",
      arp_opcode: "reply",
      vlan_id: "120",
    },
    {
      _time: EARLIEST + 260,
      host: "nd-01",
      sourcetype: "cisco:dc:nd:endpoints",
      mac: "00:50:56:cc:33:03",
      ip: "10.10.20.77",
      nodeName: "leaf1.pseudo.co",
      displayInterface: "Ethernet1/12",
      modType: "creation",
      encap: "vlan-120",
    },
    {
      _time: EARLIEST + 340,
      host: "nd-01",
      sourcetype: "cisco:dc:nd:endpoints",
      mac: "00:50:56:cc:33:03",
      ip: "10.10.20.77",
      nodeName: "leaf2.pseudo.co",
      displayInterface: "Ethernet1/14",
      modType: "move",
      encap: "vlan-120",
    },
    {
      _time: EARLIEST + 420,
      host: "nd-01",
      sourcetype: "cisco:dc:nd:endpoints",
      mac: "00:50:56:dd:44:04",
      ip: "10.10.20.88",
      nodeName: "leaf1.pseudo.co",
      displayInterface: "Ethernet1/20",
      modType: "creation",
      encap: "vlan-120",
    },
  ];
  const events = rawRows
    .map((r, i) => normalizeEndpointMobilityRow(r, i))
    .filter((e): e is NonNullable<typeof e> => Boolean(e))
    .map((event) => ({ event, indexName: "cisco_dc" }));
  const initialResult = buildEndpointMobilityAnalysis({
    events,
    thresholds: DEFAULT_ENDPOINT_MOBILITY_THRESHOLDS,
    earliest: EARLIEST,
    latest: NOW,
    outcomes: [
      {
        source: "protocol_endpoint_mobility",
        profile: "mob-dc1",
        state: "complete",
      },
    ],
    capped: false,
    activeSourceKinds: ["stream_arp", "nd_endpoints"],
  });
  return (
    <EndpointMobilityLensPage
      live={false}
      theme={theme}
      scope={scope}
      scopes={["lab:dc1"]}
      earliest={EARLIEST}
      latest={NOW}
      view={view}
      selectedItem={selectedItem}
      configuration={{
        profiles: [
          {
            id: "mob-dc1",
            source: "protocol_endpoint_mobility",
            lens: "endpoint_mobility",
            scope: "lab:dc1",
            index: "cisco_dc",
            observer: "nd-01",
            validFrom: EARLIEST - 3600,
            validUntil: NOW + 3600,
          },
        ],
        fingerprint: "mob-fp",
      }}
      initialResult={initialResult}
      skipConfigRecheck
      onBackToHub={() => {}}
      onRefreshConfig={() => {}}
      onChangeParams={(patch) => {
        if (patch.scope) setScope(patch.scope);
        if (patch.view) setView(patch.view);
        if ("item" in patch) setSelectedItem(patch.item);
      }}
    />
  );
}

function AppTransactionsShowcase() {
  const [view, setView] = useState<ProtocolViewMode>(
    params.get("view") === "matrix" ? "matrix" : "overview",
  );
  const [scope, setScope] = useState("lab:dc1");
  const [selectedItem, setSelectedItem] = useState<string | undefined>(
    undefined,
  );
  const rawRows = [
    {
      _time: EARLIEST + 60,
      host: "stream-01",
      sourcetype: "stream:http",
      src_ip: "10.10.20.11",
      dest_ip: "10.10.30.10",
      dest_port: 8080,
      site: "orders.prod.internal",
      http_method: "POST",
      uri_path: "/api/v1/checkout",
      status: 503,
      time_taken: 840000,
      bytes_in: 1420,
      bytes_out: 680,
    },
    {
      _time: EARLIEST + 140,
      host: "stream-01",
      sourcetype: "stream:http",
      src_ip: "10.10.20.12",
      dest_ip: "10.10.30.10",
      dest_port: 8080,
      site: "orders.prod.internal",
      http_method: "POST",
      uri_path: "/api/v1/checkout",
      status: 200,
      time_taken: 185000,
      bytes_in: 1120,
      bytes_out: 3820,
    },
    {
      _time: EARLIEST + 210,
      host: "stream-01",
      sourcetype: "stream:postgres",
      src_ip: "10.10.30.10",
      dest_ip: "10.10.40.25",
      dest_port: 5432,
      dbname: "orders_prod",
      sql_error_code: "40P01",
      response_time: 640000,
      result_row_count: 0,
      bytes_in: 420,
      bytes_out: 210,
    },
    {
      _time: EARLIEST + 300,
      host: "stream-01",
      sourcetype: "stream:postgres",
      src_ip: "10.10.30.10",
      dest_ip: "10.10.40.25",
      dest_port: 5432,
      dbname: "orders_prod",
      response_time: 18000,
      result_row_count: 14,
      bytes_in: 380,
      bytes_out: 4100,
    },
    {
      _time: EARLIEST + 420,
      host: "stream-01",
      sourcetype: "stream:http",
      src_ip: "10.10.20.11",
      dest_ip: "10.10.30.18",
      dest_port: 443,
      site: "catalog.prod.internal",
      http_method: "GET",
      uri_path: "/api/v1/items",
      status: 200,
      time_taken: 24000,
      bytes_in: 410,
      bytes_out: 18200,
    },
  ];
  const events = rawRows
    .map((r) => normalizeAppTransactionRow(r))
    .filter((e): e is NonNullable<typeof e> => Boolean(e))
    .map((event) => ({ event, indexName: "stream_app" }));
  const initialResult = buildAppTransactionsAnalysis({
    events,
    thresholds: DEFAULT_APP_TRANSACTIONS_THRESHOLDS,
    earliest: EARLIEST,
    latest: NOW,
    outcomes: [
      {
        source: "protocol_app_transactions",
        profile: "app-dc1",
        state: "complete",
      },
    ],
    httpOutcomes: [
      {
        source: "protocol_app_transactions",
        profile: "app-dc1",
        state: "complete",
      },
    ],
    dbOutcomes: [
      {
        source: "protocol_app_transactions",
        profile: "app-dc1",
        state: "complete",
      },
    ],
    capped: false,
    httpConfigured: true,
    dbConfigured: true,
  });
  return (
    <AppTransactionsLensPage
      live={false}
      theme={theme}
      scope={scope}
      scopes={["lab:dc1"]}
      earliest={EARLIEST}
      latest={NOW}
      view={view}
      selectedItem={selectedItem}
      configuration={{
        profiles: [
          {
            id: "app-dc1",
            source: "protocol_app_transactions",
            lens: "app_transactions",
            scope: "lab:dc1",
            index: "stream_app",
            observer: "stream-01",
            validFrom: EARLIEST - 3600,
            validUntil: NOW + 3600,
          },
        ],
        fingerprint: "app-fp",
      }}
      initialResult={initialResult}
      skipConfigRecheck
      onBackToHub={() => {}}
      onRefreshConfig={() => {}}
      onChangeParams={(patch) => {
        if (patch.scope) setScope(patch.scope);
        if (patch.view) setView(patch.view);
        if ("item" in patch) setSelectedItem(patch.item);
      }}
    />
  );
}

function StateEventsShowcase() {
  const [view, setView] = useState<ProtocolViewMode>(
    params.get("view") === "matrix" ? "matrix" : "overview",
  );
  const [scope, setScope] = useState("lab:dc1");
  const [selectedItem, setSelectedItem] = useState<string | undefined>(
    undefined,
  );
  const syslogRows = [
    {
      _time: EARLIEST + 60,
      host: "leaf1.pseudo.co",
      sourcetype: "cisco:ios",
      category: "ETHPORT",
      severity_id: 3,
      mnemonics: "IF_DOWN_LINK_FAILURE",
      interface: "Ethernet1/49",
      syslog_msg: "Interface Ethernet1/49 is down (Link failure)",
    },
    {
      _time: EARLIEST + 95,
      host: "leaf1.pseudo.co",
      sourcetype: "cisco:ios",
      category: "BGP",
      severity_id: 3,
      mnemonics: "ADJCHANGE",
      neighbor_ip: "10.0.0.1",
      vrf: "default",
      syslog_msg: "neighbor 10.0.0.1 Down - hold timer expired",
    },
    {
      _time: EARLIEST + 140,
      host: "leaf1.pseudo.co",
      sourcetype: "cisco:ios",
      category: "BFD",
      severity_id: 3,
      mnemonics: "SESSION_STATE_DOWN",
      neighbor_ip: "10.0.0.1",
      interface: "Ethernet1/49",
      syslog_msg: "BFD session to 10.0.0.1 transitioned to Down",
    },
    {
      _time: EARLIEST + 210,
      host: "leaf2.pseudo.co",
      sourcetype: "cisco:dc:nexus9k:syslog",
      category: "HSRP",
      severity_id: 5,
      mnemonics: "STATECHANGE",
      interface: "Vlan120",
      syslog_msg: "Vlan120 Grp 120 state Standby -> Active",
    },
    {
      _time: EARLIEST + 320,
      host: "spine1.pseudo.co",
      sourcetype: "cisco:ios",
      category: "STP",
      severity_id: 4,
      mnemonics: "ROOTCHANGE",
      interface: "port-channel10",
      syslog_msg: "Topology change detected on VLAN 120",
    },
  ];
  const aciRows = [
    {
      _time: EARLIEST + 180,
      host: "apic1.pseudo.co",
      apic_host: "apic1.pseudo.co",
      sourcetype: "cisco:dc:aci:fault",
      component: "faultInst",
      code: "F0532",
      severity: "major",
      domain: "access",
      cause: "port-down",
      affected: "topology/pod-1/node-101/sys/phys-[eth1/5]",
      dn: "topology/pod-1/node-101/sys/phys-[eth1/5]/fault-F0532",
      descr: "Port eth1/5 is down (reason: link-failure)",
    },
  ];
  const events = [
    ...syslogRows
      .map((r, i) => normalizeStateSyslogRow(r, i))
      .filter((e): e is NonNullable<typeof e> => Boolean(e))
      .map((event) => ({ event, indexName: "cisco_dc" })),
    ...aciRows
      .map((r, i) => normalizeAciFaultEventRow(r, i))
      .filter((e): e is NonNullable<typeof e> => Boolean(e))
      .map((event) => ({ event, indexName: "cisco_dc" })),
  ];
  const initialResult = buildStateEventsAnalysis({
    events,
    thresholds: DEFAULT_STATE_EVENTS_THRESHOLDS,
    earliest: EARLIEST,
    latest: NOW,
    outcomes: [
      {
        source: "protocol_state_events",
        profile: "state-dc1",
        state: "complete",
      },
    ],
    capped: false,
  });
  return (
    <StateEventsLensPage
      live={false}
      theme={theme}
      scope={scope}
      scopes={["lab:dc1"]}
      earliest={EARLIEST}
      latest={NOW}
      view={view}
      selectedItem={selectedItem}
      configuration={{
        profiles: [
          {
            id: "state-dc1",
            source: "protocol_state_events",
            lens: "state_events",
            scope: "lab:dc1",
            index: "cisco_dc",
            observer: "sc4s-01",
            validFrom: EARLIEST - 3600,
            validUntil: NOW + 3600,
          },
        ],
        fingerprint: "state-fp",
      }}
      initialResult={initialResult}
      skipConfigRecheck
      onBackToHub={() => {}}
      onRefreshConfig={() => {}}
      onChangeParams={(patch) => {
        if (patch.scope) setScope(patch.scope);
        if (patch.view) setView(patch.view);
        if ("item" in patch) setSelectedItem(patch.item);
      }}
    />
  );
}

function MgmtPlaneShowcase() {
  const [view, setView] = useState<ProtocolViewMode>(
    params.get("view") === "matrix" ? "matrix" : "overview",
  );
  const [scope, setScope] = useState("lab:dc1");
  const [selectedItem, setSelectedItem] = useState<string | undefined>(
    undefined,
  );
  const rawRows: {
    row: Record<string, unknown>;
    defaultSt: "stream:snmp" | "stream:ftp" | "stream:netflow" | "cisco:ios";
  }[] = [
    {
      defaultSt: "stream:snmp",
      row: {
        _time: EARLIEST + 60,
        host: "stream-01",
        sourcetype: "stream:snmp",
        src_ip: "10.10.99.50",
        dest_ip: "192.0.2.11",
        dest_port: 161,
        snmp_version: "2c",
        pdu_type: "SetRequest",
        status: "noError",
        bytes_in: 192,
        bytes_out: 204,
      },
    },
    {
      defaultSt: "stream:ftp",
      row: {
        _time: EARLIEST + 140,
        host: "stream-01",
        sourcetype: "stream:ftp",
        src_ip: "10.10.99.55",
        dest_ip: "192.0.2.12",
        dest_port: 21,
        command: "RETR",
        reply_code: 226,
        bytes_in: 128,
        bytes_out: 18400,
      },
    },
    {
      defaultSt: "stream:netflow",
      row: {
        _time: EARLIEST + 200,
        host: "leaf1.pseudo.co",
        sourcetype: "stream:netflow",
        src_ip: "10.10.99.60",
        dest_ip: "192.0.2.14",
        dest_port: 23,
        transport: "tcp",
        bytes: 4200,
        packets: 34,
        exporter_ip: "192.0.2.11",
      },
    },
    {
      defaultSt: "cisco:ios",
      row: {
        _time: EARLIEST + 30,
        host: "leaf4.pseudo.co",
        sourcetype: "cisco:ios",
        category: "ETHPORT",
      },
    },
    {
      defaultSt: "cisco:ios",
      row: {
        _time: NOW - 30,
        host: "leaf1.pseudo.co",
        sourcetype: "cisco:ios",
        category: "ETHPORT",
      },
    },
    {
      defaultSt: "cisco:ios",
      row: {
        _time: NOW - 10,
        host: "leaf2.pseudo.co",
        sourcetype: "cisco:ios",
        category: "BGP",
      },
    },
  ];
  const events = rawRows
    .map(({ row, defaultSt }) => normalizeMgmtPlaneRow(row, defaultSt))
    .filter((e): e is NonNullable<typeof e> => Boolean(e))
    .map((event) => ({ event, indexName: "cisco_dc" }));
  const okOutcome = {
    source: "protocol_mgmt_plane",
    profile: "mgmt-dc1",
    state: "complete" as const,
  };
  const initialResult = buildMgmtPlaneAnalysis({
    events,
    thresholds: { ...DEFAULT_MGMT_PLANE_THRESHOLDS, receiptGapMinutes: 10 },
    earliest: EARLIEST,
    latest: NOW,
    outcomes: [okOutcome],
    capped: false,
    snmpConfigured: true,
    ftpConfigured: true,
    netflowConfigured: true,
    syslogConfigured: true,
    snmpOutcomes: [okOutcome],
    ftpOutcomes: [okOutcome],
    netflowOutcomes: [okOutcome],
    syslogOutcomes: [okOutcome],
  });
  return (
    <MgmtPlaneLensPage
      live={false}
      theme={theme}
      scope={scope}
      scopes={["lab:dc1"]}
      earliest={EARLIEST}
      latest={NOW}
      view={view}
      selectedItem={selectedItem}
      configuration={{
        profiles: [
          {
            id: "mgmt-dc1",
            source: "protocol_mgmt_plane",
            lens: "mgmt_plane",
            scope: "lab:dc1",
            index: "cisco_dc",
            observer: "stream-01",
            validFrom: EARLIEST - 3600,
            validUntil: NOW + 3600,
          },
        ],
        fingerprint: "mgmt-fp",
      }}
      initialResult={initialResult}
      skipConfigRecheck
      onBackToHub={() => {}}
      onRefreshConfig={() => {}}
      onChangeParams={(patch) => {
        if (patch.scope) setScope(patch.scope);
        if (patch.view) setView(patch.view);
        if ("item" in patch) setSelectedItem(patch.item);
      }}
    />
  );
}

function LbHealthShowcase() {
  const [view, setView] = useState<ProtocolViewMode>(
    params.get("view") === "matrix" ? "matrix" : "overview",
  );
  const [scope, setScope] = useState("lab:dc1");
  const [selectedItem, setSelectedItem] = useState<string | undefined>(
    undefined,
  );
  const rawRows = [
    {
      _time: EARLIEST + 60,
      host: "bigip-01",
      sourcetype: "f5:bigip:ltm:lb:failed:irule",
      f5_irule: "Splunk-iRule-LB_FAILED",
      vip: "198.51.100.10",
      pool: "pool_checkout_prod",
      src_ip: "203.0.113.20",
      bytes_in: 620,
    },
    {
      _time: EARLIEST + 140,
      host: "bigip-01",
      sourcetype: "f5:bigip:ltm:http:irule",
      f5_irule: "Splunk-iRule-HTTP",
      vip: "198.51.100.10",
      pool: "pool_checkout_prod",
      node: "10.10.30.12",
      node_port: 8443,
      src_ip: "203.0.113.21",
      http_status: 200,
      req_elapsed_time: 42,
      bytes_in: 540,
      bytes_out: 9400,
    },
    {
      _time: EARLIEST + 210,
      host: "aws-alb-01",
      sourcetype: "aws:elb:accesslogs",
      elb: "app/prod-api/01a2b3c4",
      target_group: "tg-orders-api",
      target_ip: "10.20.40.15",
      target_port: 8080,
      src_ip: "203.0.113.45",
      elb_status_code: 502,
      target_status_code: 502,
      target_processing_time: 0.72,
      request_processing_time: 0.004,
      response_processing_time: 0.002,
      bytes_in: 820,
      bytes_out: 410,
      ssl_protocol: "TLSv1.3",
    },
    {
      _time: EARLIEST + 310,
      host: "aws-nlb-01",
      sourcetype: "aws:nlb:accesslogs",
      elb: "net/prod-edge-tls/99d8e7",
      listener: "tls-443",
      target_ip: "10.20.50.22",
      target_port: 443,
      src_ip: "203.0.113.88",
      tls_alert: "handshake_failure",
      verify_status: "Failed:CertExpired",
      handshake_time_ms: 680,
      connection_time_ms: 920,
      ssl_protocol: "TLSv1.2",
      bytes_in: 310,
      bytes_out: 180,
    },
  ];
  const events = rawRows
    .map((r) => normalizeLbHealthRow(r))
    .filter((e): e is NonNullable<typeof e> => Boolean(e))
    .map((event) => ({ event, indexName: "lb_logs" }));
  const initialResult = buildLbHealthAnalysis({
    events,
    thresholds: DEFAULT_LB_HEALTH_THRESHOLDS,
    earliest: EARLIEST,
    latest: NOW,
    outcomes: [
      {
        source: "protocol_lb_health",
        profile: "lb-dc1",
        state: "complete",
      },
    ],
    capped: false,
  });
  return (
    <LbHealthLensPage
      live={false}
      theme={theme}
      scope={scope}
      scopes={["lab:dc1"]}
      earliest={EARLIEST}
      latest={NOW}
      view={view}
      selectedItem={selectedItem}
      configuration={{
        profiles: [
          {
            id: "lb-dc1",
            source: "protocol_lb_health",
            lens: "lb_health",
            scope: "lab:dc1",
            index: "lb_logs",
            observer: "bigip-01",
            validFrom: EARLIEST - 3600,
            validUntil: NOW + 3600,
          },
        ],
        fingerprint: "lb-fp",
      }}
      initialResult={initialResult}
      skipConfigRecheck
      onBackToHub={() => {}}
      onRefreshConfig={() => {}}
      onChangeParams={(patch) => {
        if (patch.scope) setScope(patch.scope);
        if (patch.view) setView(patch.view);
        if ("item" in patch) setSelectedItem(patch.item);
      }}
    />
  );
}

createRoot(document.getElementById("adm-root")!).render(
  <ThemeProvider family="enterprise" colorScheme={theme} density="comfortable">
    <Shell page="protocols" live={false}>
      {scenario === "hub" ? (
        <ProtocolsPage live={false} theme={theme} />
      ) : scenario === "tcp_tls" ? (
        <TcpTlsShowcase mode="stream_tcp" />
      ) : scenario === "tcp_tls_netflow" ? (
        <TcpTlsShowcase mode="netflow" />
      ) : scenario === "tcp_tls_race" ? (
        <TcpTlsScopeRaceShowcase />
      ) : scenario === "dns_ops" ? (
        <DnsOpsShowcase />
      ) : scenario === "routing" ? (
        <RoutingShowcase />
      ) : scenario === "l2_control" ? (
        <L2ControlShowcase />
      ) : scenario === "interface_health" ? (
        <InterfaceHealthShowcase />
      ) : scenario === "qos_icmp" ? (
        <QosIcmpShowcase />
      ) : scenario === "enterprise_l7" ? (
        <EnterpriseL7Showcase />
      ) : scenario === "drops" ? (
        <DropsShowcase />
      ) : scenario === "endpoint_mobility" ? (
        <EndpointMobilityShowcase />
      ) : scenario === "app_transactions" ? (
        <AppTransactionsShowcase />
      ) : scenario === "state_events" ? (
        <StateEventsShowcase />
      ) : scenario === "mgmt_plane" ? (
        <MgmtPlaneShowcase />
      ) : scenario === "lb_health" ? (
        <LbHealthShowcase />
      ) : (
        <SampleLensShowcase />
      )}
    </Shell>
  </ThemeProvider>,
);
