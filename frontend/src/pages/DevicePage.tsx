import { ImpactButton } from "../impact/ImpactButton";
import { useEffect, useMemo, useState, type MouseEvent } from "react";
import { Ban, RefreshCw } from "lucide-react";
import { pageURL, type UrlState } from "../app/urlState";
import {
  demoDeviceFlows,
  demoVsphereTopology,
  prepareDemo,
} from "../data/demoClient";
import {
  DEVICE_INVENTORY_SEARCH,
  deviceFlowSummary,
  deviceFlowsSearch,
  inferLeafEgress,
  interfaceSides,
  isNxosDevice,
  loadInterfaceNames,
  MAX_DEVICE_INVENTORY_ROWS,
  nameDeviceInterfaces,
  MAX_DEVICE_FLOW_ROWS,
  rowsToDeviceFlows,
  type DeviceConversation,
  type DeviceFlows,
  type InterfaceSide,
} from "../data/deviceFlows";
import { requireNoSearchErrors, type SearchClient } from "../data/searchClient";
import { plural, prettyBytes, sourceLabel } from "../glossary";
import { TimePicker } from "../map/TimePicker";
import { loadTopology } from "../provider";
import { VirtualTable, type VirtualColumn } from "../scale/VirtualTable";
import type { Theme } from "../theme";
import {
  deviceKindLabel,
  fabricLabel,
  indexTopology,
  type Device,
  type Topology,
} from "../topology";
import { isRawIfIndex } from "../ifIndex";
import {
  conversationKey,
  epochLabel,
  findDevices,
  flowTokens,
  mergeDeviceFlows,
  portProtoLabel,
  traceTopology,
} from "../trace/traceModel";
import { DeviceLookup, deviceURL, ExploreTabs, traceURL } from "./ExploreTools";

const TOKEN = /^[A-Za-z0-9_.:/-]{1,128}$/;

type Load =
  | { status: "loading" }
  | { status: "error"; error: string }
  | {
      status: "done";
      device?: Device;
      candidates: Device[];
      flows?: DeviceFlows;
      /** Contributing collectors, e.g. "Stream NetFlow · 192.0.2.73". */
      exporters?: string[];
    };

/** Device page data: inventory lookup, then adm_device_flows per token. */
export async function loadDevicePage({
  query,
  demo,
  client,
  earliest,
  latest,
  timezone,
  signal,
}: {
  query: string;
  demo: boolean;
  client?: SearchClient;
  earliest: string;
  latest?: string;
  timezone?: string;
  signal: AbortSignal;
}): Promise<Extract<Load, { status: "done" }>> {
  let topology: Topology;
  if (!__ADM_SPLUNK_BUILD__ && demo) {
    await prepareDemo();
    topology = demoVsphereTopology();
  } else {
    if (!client) throw new Error("Live search runs inside Splunk.");
    // adm_topology can return no ACI or vSphere rows (they are not part of
    // it, or ACI topology is withheld); device identities come from
    // adm_device_inventory as well, merged by device ID.
    const [base, identities] = await Promise.all([
      loadTopology(client, earliest, signal, latest, timezone),
      client
        .search({
          search: DEVICE_INVENTORY_SEARCH,
          earliest,
          latest,
          timezone,
          maxRows: MAX_DEVICE_INVENTORY_ROWS,
          allowEmpty: true,
          signal,
        })
        .then((r) => requireNoSearchErrors(r, "Device inventory").rows)
        .catch(() => [] as unknown[]),
    ]);
    topology = traceTopology(base, identities);
  }
  const candidates = findDevices(query, topology);
  if (candidates.length > 1) return { status: "done", candidates };
  const device = candidates[0];
  const tokens = device ? flowTokens(device) : TOKEN.test(query) ? [query] : [];
  if (!tokens.length) return { status: "done", device, candidates };
  const nxos = isNxosDevice(device);
  const parts =
    !__ADM_SPLUNK_BUILD__ && demo
      ? tokens.map(demoDeviceFlows)
      : await Promise.all(
          tokens.map(async (token) => {
            const [result, names] = await Promise.all([
              client!.search({
                search: deviceFlowsSearch(token),
                earliest,
                latest,
                timezone,
                maxRows: MAX_DEVICE_FLOW_ROWS,
                allowEmpty: true,
                signal,
              }),
              loadInterfaceNames(client!, token, {
                earliest,
                latest,
                timezone,
                signal,
              }),
            ]);
            const flows = rowsToDeviceFlows(
              token,
              requireNoSearchErrors(result, "Device flows").rows,
            );
            return nameDeviceInterfaces(flows, names, nxos);
          }),
        );
  return {
    status: "done",
    device,
    candidates,
    flows: inferLeafEgress(
      mergeDeviceFlows(device?.id ?? query, parts),
      device,
      indexTopology(topology),
    ),
    exporters: deviceExporters(parts),
  };
}

/** "Stream NetFlow · 192.0.2.73" per token that returned conversations. */
export function deviceExporters(parts: readonly DeviceFlows[]): string[] {
  return [
    ...new Set(
      parts.flatMap((p) =>
        [...new Set(p.conversations.flatMap((c) => c.sources))].map(
          (s) => `${sourceLabel(s)} · ${p.device}`,
        ),
      ),
    ),
  ];
}

/** Collectors whose records carry byte and packet counters. */
const COUNTS_REPORTED = new Set(["netflow", "nd", "ftd"]);
const counter = (
  c: DeviceConversation,
  value: number | undefined,
  format: (n: number) => string,
) =>
  value !== undefined ? (
    format(value)
  ) : c.sources.some((s) => COUNTS_REPORTED.has(s)) ? (
    format(0)
  ) : (
    <span
      className="muted"
      title={`Not reported by ${c.sources.map(sourceLabel).join(", ") || "this source"}`}
    >
      —
    </span>
  );

const name = (ip: string, label?: string) => (label ? `${label}` : ip);
const COLUMNS: VirtualColumn<DeviceConversation>[] = [
  {
    key: "src",
    header: "Source",
    render: (c) => (
      <a
        href={traceURL(c.src, c.dst)}
        data-trace-link
        title={`Trace ${c.src} → ${c.dst}`}
      >
        {name(c.src, c.srcName)}
      </a>
    ),
    sortValue: (c) => c.srcName ?? c.src,
    width: 1.3,
    filterText: (c) => `${c.src} ${c.srcName ?? ""}`,
  },
  {
    key: "dst",
    header: "Destination",
    render: (c) => (
      <span title={c.dst}>
        {name(c.dst, c.dstName)}
        {c.blocked && (
          <Ban
            size={12}
            className="atlas-device-blocked"
            aria-label="Blocked"
          />
        )}
      </span>
    ),
    sortValue: (c) => c.dstName ?? c.dst,
    width: 1.3,
    filterText: (c) =>
      `${c.dst} ${c.dstName ?? ""} ${c.blocked ? "blocked" : ""}`,
  },
  {
    key: "port",
    header: "Port",
    render: (c) =>
      portProtoLabel(
        [c.protocol],
        c.destPort !== undefined ? [String(c.destPort)] : [],
      ),
    sortValue: (c) => c.destPort ?? -1,
    filterText: (c) => `${c.protocol}/${c.destPort ?? ""}`,
  },
  {
    key: "bytes",
    header: "Bytes",
    num: true,
    render: (c) => counter(c, c.bytes, prettyBytes),
    sortValue: (c) => c.bytes ?? -1,
  },
  {
    key: "packets",
    header: "Packets",
    num: true,
    render: (c) => counter(c, c.packets, (n) => n.toLocaleString()),
    sortValue: (c) => c.packets ?? -1,
  },
  {
    key: "flows",
    header: "Flows",
    num: true,
    render: (c) => c.flows.toLocaleString(),
    sortValue: (c) => c.flows,
  },
  {
    key: "in",
    header: "In",
    headerTitle: "Ingress interface reported by the exporter.",
    render: (c) => <InterfaceCell sides={interfaceSides(c.interfaces).in} />,
    sortValue: (c) =>
      interfaceSides(c.interfaces)
        .in.map((i) => i.text)
        .join(", "),
    filterText: (c) =>
      interfaceSides(c.interfaces)
        .in.map((i) => `${i.text} ${i.title}`)
        .join(" "),
    width: 1.1,
  },
  {
    key: "out",
    header: "Out",
    headerTitle:
      "Egress interface. Leaf NetFlow exports ingress only; an inferred egress comes from the ACI endpoint table.",
    render: (c) => <InterfaceCell sides={interfaceSides(c.interfaces).out} />,
    sortValue: (c) =>
      interfaceSides(c.interfaces)
        .out.map((i) => i.text)
        .join(", "),
    filterText: (c) =>
      interfaceSides(c.interfaces)
        .out.map((i) => `${i.text} ${i.title}`)
        .join(" "),
    width: 1.1,
  },
  {
    key: "first",
    header: "First seen",
    render: (c) => epochLabel(c.firstSeen) ?? "—",
    sortValue: (c) => c.firstSeen ?? 0,
  },
  {
    key: "last",
    header: "Last seen",
    render: (c) => epochLabel(c.lastSeen) ?? "—",
    sortValue: (c) => c.lastSeen ?? 0,
  },
  {
    key: "app",
    header: "App",
    render: (c) => c.app ?? "—",
    sortValue: (c) => c.app ?? "",
  },
];

/** Compact interface names; full name and provenance in the tooltip. */
function InterfaceCell({ sides }: { sides: InterfaceSide[] }) {
  if (!sides.length) return <span className="muted">—</span>;
  const raw = sides.every((s) => isRawIfIndex(s.text));
  return (
    <span
      className={`atlas-device-if${raw ? " muted" : ""}`}
      title={
        raw
          ? "Interface name not collected for this ifIndex"
          : sides.map((s) => s.title).join(", ")
      }
    >
      {sides.map((s, i) => (
        <span key={s.title}>
          {i > 0 && ", "}
          {s.inferred ? (
            <i className="atlas-device-inferred">{s.text}</i>
          ) : (
            s.text
          )}
        </span>
      ))}
    </span>
  );
}

/** Row click anywhere traces the pair; the Source link is the keyboard path. */
const traceRow = (event: MouseEvent<HTMLDivElement>) => {
  const target = event.target as HTMLElement;
  if (target.closest("a, button, input, th")) return;
  const link = target
    .closest("tr")
    ?.querySelector<HTMLAnchorElement>("a[data-trace-link]");
  if (link) location.assign(link.href);
};

export function DevicePage({
  state,
  client,
  live = false,
  timezone,
  inSplunk = false,
  theme = "light",
}: {
  state: UrlState;
  client?: SearchClient;
  live?: boolean;
  timezone?: string;
  inSplunk?: boolean;
  theme?: Theme;
}) {
  const demo = !__ADM_SPLUNK_BUILD__ && !live;
  const [earliest, setEarliest] = useState(state.earliest);
  const [latest, setLatest] = useState(state.latest);
  const [nonce, setNonce] = useState(0);
  const [load, setLoad] = useState<Load>({ status: "loading" });
  const query = state.device;
  useEffect(() => {
    if (!query) return;
    const controller = new AbortController();
    setLoad({ status: "loading" });
    loadDevicePage({
      query,
      demo,
      client,
      earliest,
      latest,
      timezone,
      signal: controller.signal,
    })
      .then((r) => !controller.signal.aborted && setLoad(r))
      .catch(
        (e: unknown) =>
          !controller.signal.aborted &&
          setLoad({
            status: "error",
            error: e instanceof Error ? e.message : "Device lookup failed",
          }),
      );
    return () => controller.abort();
  }, [query, demo, client, earliest, latest, timezone, nonce]);
  const done = load.status === "done" ? load : undefined;
  const device = done?.device;
  const flows = done?.flows;
  const summary = useMemo(() => flows && deviceFlowSummary(flows), [flows]);
  const title = device?.name ?? query ?? "Device";
  const meta = device
    ? [
        device.role
          ? device.role[0].toUpperCase() + device.role.slice(1)
          : deviceKindLabel(device.kind, device.cluster, device.sources),
        device.mgmt_ip,
        fabricLabel(device.fabric),
        device.aci_node,
        device.serial,
      ].filter(Boolean)
    : [];
  return (
    <main className="atlas-page atlas-page-wide atlas-explore atlas-device-page">
      <ExploreTabs />
      <div className="atlas-explore-tools">
        <DeviceLookup key={query} initial={query} />
        <TimePicker
          earliest={earliest}
          latest={latest}
          timezone={timezone}
          live={inSplunk}
          disabled={demo}
          onChange={(start, end) => {
            setEarliest(start);
            setLatest(end);
          }}
        />
        {demo && <span className="chip demo">Demo data</span>}
      </div>
      <div className="adm atlas-device" data-adm-theme={theme}>
        <header className="atlas-device-head">
          <h1 id="device-title">{title}</h1>
          {meta.length > 0 && <p className="muted">{meta.join(" · ")}</p>}
          {(device || query) && (
            <ImpactButton
              token={device?.mgmt_ip ?? device?.id ?? query}
              label={title}
              interfaces={flows?.conversations.flatMap((c) =>
                c.interfaces.flatMap((i) => i.split(" > ")),
              )}
            />
          )}
        </header>
        {!query && <p role="status">No device selected</p>}
        {query && load.status === "loading" && (
          <p role="status" className="muted">
            <RefreshCw size={13} className="spin" aria-hidden /> Loading…
          </p>
        )}
        {load.status === "error" && (
          <p role="alert" className="atlas-trace-error">
            {load.error}
            <button
              type="button"
              className="secondary-button"
              onClick={() => setNonce((n) => n + 1)}
            >
              Retry
            </button>
          </p>
        )}
        {done && done.candidates.length > 1 && (
          <section aria-label="Matching devices">
            <p>{plural(done.candidates.length, "match", "matches")}</p>
            <ul className="atlas-device-candidates">
              {done.candidates.map((d) => (
                <li key={d.id}>
                  <a href={deviceURL(d.id)}>{d.name}</a>{" "}
                  <span className="muted small">
                    {[deviceKindLabel(d.kind, d.cluster, d.sources), d.mgmt_ip]
                      .filter(Boolean)
                      .join(" · ")}
                  </span>
                </li>
              ))}
            </ul>
          </section>
        )}
        {done && !device && done.candidates.length === 0 && (
          <p role="status">Not in inventory</p>
        )}
        {flows && summary && (
          <>
            <div className="kpis atlas-device-kpis" aria-label="Summary">
              <span className="kpi">
                <b>{flows.totals.flows.toLocaleString()}</b>{" "}
                {flows.totals.flows === 1 ? "flow" : "flows"}
              </span>
              <span className="kpi">
                <b>{summary.peers.toLocaleString()}</b>{" "}
                {summary.peers === 1 ? "peer" : "peers"}
              </span>
              {flows.totals.bytes !== undefined && (
                <span className="kpi">
                  <b>{prettyBytes(flows.totals.bytes)}</b>
                </span>
              )}
              <span className={`kpi ${summary.blocked ? "blocked" : ""}`}>
                {summary.blocked > 0 && <Ban size={13} aria-hidden />}
                <b>{summary.blocked}</b> blocked
              </span>
              {!!done?.exporters?.length && (
                <span className="kpi" title="Contributing collectors">
                  <b>Source</b> {done.exporters.join(", ")}
                </span>
              )}
              {flows.recordsCapped && (
                <span
                  className="kpi warn"
                  title="Record cap reached; totals are lower bounds"
                >
                  Capped
                </span>
              )}
            </div>
            <div className="atlas-device-table" onClick={traceRow}>
              <VirtualTable
                caption={
                  flows.truncated
                    ? `Top ${Math.min(flows.limit ?? Infinity, flows.conversations.length).toLocaleString()} of ${flows.totals.conversations.toLocaleString()} conversations`
                    : "Conversations"
                }
                rows={flows.conversations}
                columns={COLUMNS}
                rowKey={conversationKey}
                empty="No flows in this window"
              />
            </div>
          </>
        )}
        <p className="small">
          <a href={pageURL("applications")}>Explore</a>
        </p>
      </div>
    </main>
  );
}
