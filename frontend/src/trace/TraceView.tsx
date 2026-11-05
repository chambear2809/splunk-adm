import { ImpactButton } from "../impact/ImpactButton";
import { Fragment, useMemo, useState, type ReactNode } from "react";
import {
  Ban,
  Box,
  BrickWall,
  ChevronRight,
  DoorOpen,
  Globe,
  HardDrive,
  Layers,
  Network,
  RefreshCw,
  Router,
  Server,
  Share2,
  Unplug,
  X,
} from "lucide-react";
import { hopEvidenceText, type TraceHop } from "../data/pathTrace";
import { plural, sourceLabel } from "../glossary";
import { deviceURL } from "../pages/ExploreTools";
import {
  blockedHops,
  blockedKindLabel,
  blockedLabel,
  collapseHops,
  epochLabel,
  hopIcon,
  openServices,
  portProtoLabel,
  type BlockedHop,
  type HopIcon,
  type TraceSummary,
} from "./traceModel";
import type { TraceRequest, TraceResult } from "./usePathTrace";
import "./trace.css";

const ICONS: Record<HopIcon, typeof Network> = {
  vm: HardDrive,
  pod: Box,
  host: Server,
  vswitch: Layers,
  fi: Router,
  leaf: Network,
  spine: Share2,
  switch: Network,
  firewall: BrickWall,
  external: Globe,
  handoff: DoorOpen,
  gap: Unplug,
};

const STATUS = {
  traced: "Traced",
  partial: "Partial",
  unresolved: "Not traced",
};

/** "2 spines" for ECMP choices; the hop label otherwise. */
const KIND_PLURAL: Record<string, string> = {
  Leaf: "leaves",
  FI: "FIs",
  VDS: "VDSes",
  VSS: "VSSes",
};
const hopName = (hop: TraceHop, kind: string) =>
  hop.alternatives?.length
    ? `${hop.alternatives.length} ${KIND_PLURAL[kind] ?? `${kind.toLowerCase()}s`}`
    : hop.label;
const hopLastSeen = (hop: TraceHop, summary: TraceSummary) => {
  const seen = hop.sources
    .map((s) => summary.lastSeenBySource.get(s))
    .filter((t): t is number => t !== undefined);
  return seen.length
    ? Math.max(...seen)
    : hop.kind === "endpoint"
      ? summary.lastSeen
      : undefined;
};
const ports = (hop: TraceHop) =>
  [hop.in, hop.out].filter(Boolean).join(" → ") || undefined;
/** "47110, 47111 … +6" for the detail panel. */
const portList = (list: readonly string[], max = 8) =>
  list.length
    ? list.slice(0, max).join(", ") +
      (list.length > max ? ` +${list.length - max}` : "")
    : undefined;

/**
 * Source → destination hop strip with a one-line summary and a hop detail
 * panel. Observed hops carry no badge; only inferred, gap and blocked do.
 */
export function TraceView({
  request,
  result,
  onClose,
  onCancel,
  onRetry,
  actions,
}: {
  request: TraceRequest;
  result: TraceResult;
  onClose?: () => void;
  onCancel?: () => void;
  onRetry?: () => void;
  /** Extra header controls, e.g. "Open on map". */
  actions?: ReactNode;
}) {
  const [expanded, setExpanded] = useState(false);
  const [selected, setSelected] = useState<number>();
  const done = result.status === "done" ? result : undefined;
  const blocked = useMemo(
    () =>
      done ? blockedHops(done.trace, done.topo) : new Map<number, BlockedHop>(),
    [done],
  );
  const verdicts = useMemo(() => {
    const seen = new Map<string, BlockedHop>();
    for (const b of blocked.values())
      seen.set(`${blockedLabel(b)}|${b.kind}`, b);
    return [...seen.values()];
  }, [blocked]);
  const open = useMemo(
    () => (done && blocked.size ? openServices(done.summary, blocked) : []),
    [done, blocked],
  );
  const items = useMemo(
    () =>
      done
        ? collapseHops(done.trace.hops, expanded, (_, i) => blocked.has(i))
        : [],
    [done, expanded, blocked],
  );
  const trace = done?.trace;
  const summary = done?.summary;
  const srcName = trace?.src.node?.label ?? request.src;
  const dstName = trace?.dst.node?.label ?? request.dst;
  const proto = summary && portProtoLabel(summary.protocols, summary.ports);
  const records = summary?.records ?? 0;
  const conversations = trace?.conversations.length ?? 0;
  const line = [
    proto,
    trace && trace.status !== "unresolved"
      ? records
        ? plural(records, "record")
        : conversations
          ? plural(conversations, "conversation")
          : "No records"
      : undefined,
    trace
      ? trace.status === "partial"
        ? `${STATUS.partial} · ${plural(trace.gaps.length, "gap")}`
        : STATUS[trace.status]
      : result.status === "loading"
        ? "Tracing…"
        : result.status === "waiting"
          ? "Needs Splunk"
          : result.status === "error"
            ? "Failed"
            : undefined,
  ].filter(Boolean);
  const hop = selected !== undefined ? trace?.hops[selected] : undefined;
  return (
    <section
      className="atlas-trace"
      aria-label={`Trace ${request.src} to ${request.dst}`}
      data-status={trace?.status ?? result.status}
    >
      <header className="atlas-trace-head">
        <strong
          className="atlas-trace-pair"
          title={`${request.src} → ${request.dst}`}
        >
          {srcName} → {dstName}
        </strong>
        {line.map((part) => (
          <Fragment key={part}>
            <span aria-hidden="true">·</span>
            <span>{part}</span>
          </Fragment>
        ))}
        {verdicts.map((b) => (
          <span
            key={`${blockedLabel(b)}|${b.kind}`}
            className="atlas-trace-chip blocked"
            title={[blockedKindLabel(b), ...b.reasons].join(" · ")}
          >
            <Ban size={12} aria-hidden /> {blockedLabel(b)} (
            {blockedKindLabel(b)})
          </span>
        ))}
        {open.length > 0 && (
          <span
            className="atlas-trace-chip open"
            title="Records were observed for these services and no drop was logged"
          >
            {portList(open, 3)} not blocked
          </span>
        )}
        <span className="atlas-trace-spacer" />
        {result.status === "loading" && onCancel && (
          <button type="button" className="atlas-trace-btn" onClick={onCancel}>
            Cancel
          </button>
        )}
        {actions}
        {onClose && (
          <button
            type="button"
            className="atlas-trace-icon"
            aria-label="Close trace"
            onClick={onClose}
          >
            <X size={15} />
          </button>
        )}
      </header>
      {result.status === "error" && (
        <p className="atlas-trace-error" role="alert">
          {result.error}
          {onRetry && (
            <button type="button" className="atlas-trace-btn" onClick={onRetry}>
              <RefreshCw size={13} aria-hidden /> Retry
            </button>
          )}
        </p>
      )}
      {trace?.status === "unresolved" && (
        <p className="atlas-trace-error" role="status">
          {trace.reason}
        </p>
      )}
      {result.status === "loading" && (
        <p className="atlas-trace-loading" role="status">
          <RefreshCw size={13} className="spin" aria-hidden /> Tracing…
        </p>
      )}
      {trace && trace.hops.length > 0 && (
        <div className={`atlas-trace-body ${hop ? "has-detail" : ""}`}>
          <ol className="atlas-trace-hops" aria-label="Hops">
            {items.map((item, i) => (
              <li key={item.type === "hop" ? item.index : `more-${item.from}`}>
                {i > 0 && (
                  <ChevronRight
                    size={14}
                    className="atlas-trace-link"
                    aria-hidden
                  />
                )}
                {item.type === "more" ? (
                  <button
                    type="button"
                    className="atlas-trace-more"
                    title={item.hops.map((h) => h.label).join(" → ")}
                    onClick={() => setExpanded(true)}
                  >
                    +{item.hops.length} hops
                  </button>
                ) : (
                  <HopCard
                    hop={item.hop}
                    kind={hopIcon(item.hop, done.topo)}
                    blocked={blocked.get(item.index)}
                    selected={selected === item.index}
                    onClick={() =>
                      setSelected((s) =>
                        s === item.index ? undefined : item.index,
                      )
                    }
                  />
                )}
              </li>
            ))}
          </ol>
          {expanded && trace.hops.length > 7 && (
            <button
              type="button"
              className="atlas-trace-btn"
              onClick={() => setExpanded(false)}
            >
              Collapse
            </button>
          )}
          {hop && selected !== undefined && done && (
            <HopDetail
              hop={hop}
              kind={hopIcon(hop, done.topo).kind}
              blocked={blocked.get(selected)}
              summary={done.summary}
              lastSeen={hopLastSeen(hop, done.summary)}
              deviceId={
                hop.device && done.topo.byId.has(hop.device)
                  ? hop.device
                  : undefined
              }
              onClose={() => setSelected(undefined)}
            />
          )}
        </div>
      )}
      {trace && trace.notes.length > 0 && (
        <details className="atlas-trace-notes">
          <summary>Notes ({trace.notes.length})</summary>
          <ul>
            {trace.notes.map((n) => (
              <li key={n}>{n}</li>
            ))}
          </ul>
        </details>
      )}
    </section>
  );
}

function HopCard({
  hop,
  kind,
  blocked,
  selected,
  onClick,
}: {
  hop: TraceHop;
  kind: { icon: HopIcon; kind: string };
  blocked?: BlockedHop;
  selected: boolean;
  onClick: () => void;
}) {
  const Icon = ICONS[kind.icon];
  const name = hopName(hop, kind.kind);
  const p = ports(hop);
  return (
    <button
      type="button"
      className={`atlas-hop ${hop.evidence} ${blocked ? "blocked" : ""}`}
      aria-pressed={selected}
      aria-label={`${kind.kind} ${name}${hop.evidence === "observed" ? "" : `, ${hop.evidence}`}${blocked ? `, ${blockedLabel(blocked).toLowerCase()} by ${blockedKindLabel(blocked)}` : ""}`}
      title={
        hop.alternatives?.length
          ? hop.alternatives.map((a) => a.label).join(", ")
          : (hop.detail ?? hop.label)
      }
      onClick={onClick}
    >
      <span className="atlas-hop-top">
        <Icon size={15} strokeWidth={1.8} aria-hidden />
        <span className="atlas-hop-kind">{kind.kind}</span>
        {blocked ? (
          <span
            className="atlas-hop-badge blocked"
            title={blockedKindLabel(blocked)}
          >
            {blockedLabel(blocked)}
          </span>
        ) : hop.evidence === "inferred" && hop.kind !== "endpoint" ? (
          <span className="atlas-hop-badge inferred">Inferred</span>
        ) : hop.evidence === "gap" ? (
          <span className="atlas-hop-badge gap">Gap</span>
        ) : null}
      </span>
      <strong className="atlas-hop-name">{name}</strong>
      <span className="atlas-hop-ports">{p ?? " "}</span>
    </button>
  );
}

function HopDetail({
  hop,
  kind,
  blocked,
  summary,
  lastSeen,
  deviceId,
  onClose,
}: {
  hop: TraceHop;
  kind: string;
  blocked?: BlockedHop;
  summary: TraceSummary;
  lastSeen?: number;
  deviceId?: string;
  onClose: () => void;
}) {
  const rows: [string, ReactNode][] = [
    ["Kind", kind],
    ["Detail", hop.detail],
    ["In", hop.in && <code>{hop.in}</code>],
    ["Out", hop.out && <code>{hop.out}</code>],
    [
      "Evidence",
      blocked
        ? `Drop logged (${blockedKindLabel(blocked)})${blocked.services.length ? ` for ${blocked.services.join(", ")}` : ""}`
        : hopEvidenceText(hop),
    ],
    ["Drop reason", blocked?.reasons.join(", ")],
    ["Sources", hop.sources.map(sourceLabel).join(", ")],
    ["Seen", hop.seen.join(", ")],
    ["Last seen", epochLabel(lastSeen) && `${epochLabel(lastSeen)} UTC`],
    [
      "Not seen",
      hop.notSeen?.length &&
        hop.notSeen.map((a, i) => (
          <Fragment key={a.device}>
            {i > 0 && ", "}
            <a href={deviceURL(a.device)}>{a.label}</a>
          </Fragment>
        )),
    ],
    [
      "Services",
      hop.kind === "endpoint" ? portList(summary.services) : undefined,
    ],
    [
      "Client ports",
      hop.kind === "endpoint" ? portList(summary.clientPorts) : undefined,
    ],
    [
      "One of",
      hop.alternatives?.length &&
        hop.alternatives.map((a, i) => (
          <Fragment key={a.device}>
            {i > 0 && ", "}
            <a href={deviceURL(a.device)}>{a.label}</a>
          </Fragment>
        )),
    ],
  ];
  return (
    <aside className="atlas-trace-detail" aria-label={`Hop ${hop.label}`}>
      <header>
        <h3>{hop.label}</h3>
        <button
          type="button"
          className="atlas-trace-icon"
          aria-label="Close hop details"
          onClick={onClose}
        >
          <X size={14} />
        </button>
      </header>
      <dl>
        {rows
          .filter(
            ([, v]) => v !== undefined && v !== "" && v !== 0 && v !== false,
          )
          .map(([k, v]) => (
            <Fragment key={k}>
              <dt>{k}</dt>
              <dd>{v}</dd>
            </Fragment>
          ))}
      </dl>
      {deviceId && (
        <a className="atlas-trace-btn" href={deviceURL(deviceId)}>
          Open device
        </a>
      )}
      <ImpactButton
        token={
          deviceId ??
          (hop.kind === "endpoint" ? hop.label : hop.alternatives?.[0]?.device)
        }
        label={hop.label}
        interfaces={
          deviceId ? [hop.in, hop.out].filter((i): i is string => !!i) : []
        }
      />
    </aside>
  );
}
