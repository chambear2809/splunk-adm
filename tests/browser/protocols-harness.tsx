import { useState } from "react";
import { createRoot } from "react-dom/client";
import ThemeProviderExport from "@splunk/themes/SplunkThemeProvider";
import { toolkitDefault } from "../../frontend/src/app/interop";
import { Shell } from "../../frontend/src/app/Shell";
import { ProtocolsPage } from "../../frontend/src/protocols/ProtocolsPage";
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

createRoot(document.getElementById("adm-root")!).render(
  <ThemeProvider family="enterprise" colorScheme={theme} density="comfortable">
    <Shell page="protocols" live={false}>
      {scenario === "hub" ? (
        <ProtocolsPage live={false} theme={theme} />
      ) : (
        <SampleLensShowcase />
      )}
    </Shell>
  </ThemeProvider>,
);
