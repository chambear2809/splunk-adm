import { Fragment, useEffect, useId, useMemo, useState } from "react";
import { Download, Map as MapIcon, RefreshCw, X, Zap } from "lucide-react";
import type { SearchClient } from "../data/searchClient";
import { downloadBlob } from "../download";
import { plural, prettyBytes } from "../glossary";
import { TimePicker } from "../map/TimePicker";
import { ExploreTabs, deviceURL, traceURL } from "../pages/ExploreTools";
import { pageURL } from "../app/urlState";
import { loadTopology } from "../provider";
import { VirtualTable, type VirtualColumn } from "../scale/VirtualTable";
import type { Theme } from "../theme";
import { traceTopology } from "../trace/traceModel";
import { blastGraph } from "./blast";
import { BlastMap } from "./BlastMap";
import { classifier, compileFailure, type Classified } from "./classify";
import { impactCsv } from "./csv";
import { loadLiveImpact, windowHours, type ImpactData } from "./data";
import { loadDemoImpact } from "./demo";
import { isImpactToken, MAX_IMPACT_ELEMENTS } from "./elements";
import {
  dependsImpact,
  failsImpact,
  perHour,
  type Dependency,
  type DependsResult,
  type FailsResult,
  appsOf,
  type ImpactMode,
  type Split,
} from "./model";
import { impactURL, parseImpactParams } from "./url";
import "./impact.css";

type Load =
  | { status: "idle" }
  | { status: "loading" }
  | { status: "error"; error: string }
  | { status: "done"; data: ImpactData };

const SEV_LABEL = {
  outage: "Outage",
  degraded: "Degraded",
  unknown: "Unverified",
  unaffected: "Unaffected",
} as const;
const DEP_LABEL = {
  outage: "Single point",
  degraded: "Redundant",
  unknown: "Unverified",
} as const;

const rate = (bytes: number | undefined, hours?: number) => {
  if (bytes === undefined) return "—";
  const r = perHour(bytes, hours);
  return r === undefined
    ? prettyBytes(Math.round(bytes))
    : `${prettyBytes(Math.round(r))}/h`;
};
const endName = (e: Classified["conv"]["src"]) => e.name ?? e.ip ?? e.key;

function Sev({
  s,
  depends = false,
}: {
  s: keyof typeof SEV_LABEL;
  depends?: boolean;
}) {
  const text = depends && s !== "unaffected" ? DEP_LABEL[s] : SEV_LABEL[s];
  return <span className={`atlas-sev ${s}`}>{text}</span>;
}

const failsColumns = (hours?: number): VirtualColumn<Classified>[] => [
  {
    key: "sev",
    header: "Severity",
    render: (c) => <Sev s={c.severity} />,
    sortValue: (c) =>
      ({ outage: 3, unknown: 2, degraded: 1, unaffected: 0 })[c.severity],
    filterText: (c) => SEV_LABEL[c.severity],
    width: 0.8,
  },
  {
    key: "app",
    header: "App",
    render: (c) => {
      const apps = appsOf(c.conv);
      if (!apps.length) return "—";
      const hosted = apps.every((a) => a.basis === "hosted");
      const text = apps.map((a) => a.name).join(", ");
      return (
        <span
          className={hosted ? "atlas-inferred" : undefined}
          title={
            hosted
              ? `Hosted on the node (inferred): ${text}`
              : apps[0].basis === "hubble"
                ? `Hubble pod flows on this node pair: ${text}`
                : text
          }
        >
          {hosted ? `~${text}` : text}
        </span>
      );
    },
    sortValue: (c) =>
      appsOf(c.conv)
        .map((a) => a.name)
        .join(", "),
  },
  {
    key: "src",
    header: "Source",
    render: (c) =>
      c.conv.src.ip && c.conv.dst.ip ? (
        <a
          href={traceURL(c.conv.src.ip, c.conv.dst.ip)}
          title={`Trace ${c.conv.src.ip} → ${c.conv.dst.ip}`}
        >
          {endName(c.conv.src)}
        </a>
      ) : (
        endName(c.conv.src)
      ),
    sortValue: (c) => endName(c.conv.src),
    filterText: (c) => `${endName(c.conv.src)} ${c.conv.src.ip ?? ""}`,
    width: 1.3,
  },
  {
    key: "dst",
    header: "Destination",
    render: (c) => <span title={c.conv.dst.ip}>{endName(c.conv.dst)}</span>,
    sortValue: (c) => endName(c.conv.dst),
    filterText: (c) => `${endName(c.conv.dst)} ${c.conv.dst.ip ?? ""}`,
    width: 1.3,
  },
  {
    key: "port",
    header: "Port",
    render: (c) =>
      `${c.conv.protocol}${c.conv.port !== undefined ? `/${c.conv.port}` : ""}`,
    sortValue: (c) => c.conv.port ?? -1,
    width: 0.7,
  },
  {
    key: "bytes",
    header: "Traffic",
    num: true,
    render: (c) => (
      <span
        title={
          c.conv.bytesFwd !== undefined || c.conv.bytesRev !== undefined
            ? `→ ${rate(c.conv.bytesFwd, hours)} to the listener · ← ${rate(c.conv.bytesRev, hours)} back`
            : undefined
        }
      >
        {rate(c.conv.bytes, hours)}
        {c.conv.directions === "both" && (
          <span className="muted" aria-label="both directions">
            {" "}
            ⇄
          </span>
        )}
      </span>
    ),
    sortValue: (c) => c.conv.bytes ?? -1,
  },
  {
    key: "alt",
    header: "Alternate",
    headerTitle:
      "Surviving path member; observed when a collector there exported this conversation",
    render: (c) =>
      c.alternate.length ? (
        <span
          title={
            c.alternateEvidence === "observed"
              ? "Observed carrying this conversation"
              : "Inferred from topology"
          }
        >
          {c.alternate.join(", ")}
          {c.alternateEvidence === "inferred" && (
            <span className="atlas-inferred"> · inferred</span>
          )}
        </span>
      ) : (
        <span className="muted">{c.severity === "outage" ? "none" : "—"}</span>
      ),
    sortValue: (c) => c.alternate.join(", "),
    width: 1.3,
  },
  {
    key: "reason",
    header: "Why",
    render: (c) => c.reason || "—",
    sortValue: (c) => c.reason,
  },
  {
    key: "ev",
    header: "Traversal",
    headerTitle:
      "Observed: exported by a collector at the failed element. Inferred: from topology only.",
    render: (c) => (
      <span className={c.traversal === "observed" ? "" : "atlas-inferred"}>
        {c.traversal}
      </span>
    ),
    sortValue: (c) => c.traversal,
    width: 0.8,
  },
];

const dependsColumns = (hours?: number): VirtualColumn<Dependency>[] => [
  {
    key: "sev",
    header: "If it fails",
    render: (d) => <Sev s={d.severity} depends />,
    sortValue: (d) => ({ outage: 3, unknown: 2, degraded: 1 })[d.severity],
    filterText: (d) => DEP_LABEL[d.severity],
    width: 0.9,
  },
  {
    key: "dep",
    header: "Dependency",
    render: (d) => (
      <a href={impactURL([d.token])} title="If this fails">
        {d.label}
      </a>
    ),
    sortValue: (d) => d.label,
    width: 1.4,
  },
  {
    key: "tier",
    header: "Tier",
    render: (d) => d.tier,
    sortValue: (d) => d.tier,
    width: 0.7,
  },
  {
    key: "alt",
    header: "Alternate",
    render: (d) =>
      d.alternate.length ? (
        d.alternate.join(", ")
      ) : (
        <span className="muted">none</span>
      ),
    sortValue: (d) => d.alternate.join(", "),
    width: 1.4,
  },
  {
    key: "conv",
    header: "Conversations",
    num: true,
    render: (d) => d.conversations.toLocaleString(),
    sortValue: (d) => d.conversations,
  },
  {
    key: "bytes",
    header: "Traffic",
    num: true,
    render: (d) => rate(d.bytes, hours),
    sortValue: (d) => d.bytes,
  },
  {
    key: "ev",
    header: "Traversal",
    render: (d) => (
      <span className={d.evidence === "observed" ? "" : "atlas-inferred"}>
        {d.evidence}
      </span>
    ),
    sortValue: (d) => d.evidence,
    width: 0.8,
  },
];

function Kpi({
  label,
  split,
  format = (n) => n.toLocaleString(),
}: {
  label: string;
  split: Split;
  format?: (n: number) => string;
}) {
  const none = !split.outage && !split.degraded && !split.unknown;
  return (
    <span
      className={`kpi atlas-impact-kpi ${none ? "none" : ""}`}
      aria-label={`${label}: ${split.outage} outage, ${split.degraded} degraded${split.unknown ? `, ${split.unknown} unverified` : ""}`}
    >
      <span className="kpi-label">{label}</span>
      <b className="atlas-sev-n outage" title="Outage">
        {format(split.outage)}
      </b>
      <b className="atlas-sev-n degraded" title="Degraded">
        {format(split.degraded)}
      </b>
      {split.unknown > 0 && (
        <b className="atlas-sev-n unknown" title="Unverified">
          {format(split.unknown)}
        </b>
      )}
    </span>
  );
}

function ElementPicker({
  elements,
  onChange,
}: {
  elements: string[];
  onChange: (e: string[]) => void;
}) {
  const id = useId();
  const [value, setValue] = useState("");
  const v = value.trim();
  const full = elements.length >= MAX_IMPACT_ELEMENTS;
  const valid = isImpactToken(v) && !elements.includes(v) && !full;
  return (
    <form
      className="atlas-tool atlas-impact-picker"
      aria-label="Elements"
      onSubmit={(e) => {
        e.preventDefault();
        if (!valid) return;
        onChange([...elements, v]);
        setValue("");
      }}
    >
      <label htmlFor={id}>
        <Zap size={14} aria-hidden /> Impact
      </label>
      {elements.map((el, i) => (
        <span key={el} className="atlas-impact-chip">
          {i > 0 && <span aria-hidden>+ </span>}
          {el}
          <button
            type="button"
            aria-label={`Remove ${el}`}
            onClick={() => onChange(elements.filter((x) => x !== el))}
          >
            <X size={12} />
          </button>
        </span>
      ))}
      <input
        id={id}
        className="atlas-input"
        aria-label="Add element"
        placeholder={
          elements.length
            ? "+ element (what-if)"
            : "Device, IP, VM, app, interface"
        }
        autoComplete="off"
        spellCheck={false}
        disabled={full}
        value={value}
        onChange={(e) => setValue(e.target.value)}
      />
      <button className="atlas-button" type="submit" disabled={!valid}>
        {elements.length ? "Add" : "Go"}
      </button>
    </form>
  );
}

export function ImpactPage({
  client,
  live = false,
  timezone,
  inSplunk = false,
  theme = "light",
}: {
  client?: SearchClient;
  live?: boolean;
  timezone?: string;
  inSplunk?: boolean;
  theme?: Theme;
}) {
  const demo = !__ADM_SPLUNK_BUILD__ && !live;
  const initial = useMemo(
    () =>
      parseImpactParams(
        new URLSearchParams(
          typeof location === "undefined" ? "" : location.search,
        ),
      ),
    [],
  );
  const [elements, setElements] = useState(initial.elements);
  const [mode, setMode] = useState<ImpactMode>(initial.mode);
  const [earliest, setEarliest] = useState(initial.earliest);
  const [latest, setLatest] = useState(initial.latest);
  const [nonce, setNonce] = useState(0);
  const [load, setLoad] = useState<Load>({ status: "idle" });

  // The URL is the shareable state.
  useEffect(() => {
    if (typeof window === "undefined") return;
    const href = impactURL(
      elements,
      { mode, earliest, latest },
      new URLSearchParams(),
    );
    const query = href.slice(href.indexOf("?"));
    if (location.search !== query)
      history.replaceState(
        null,
        "",
        `${location.pathname}${query}${location.hash}`,
      );
  }, [elements, mode, earliest, latest]);

  useEffect(() => {
    if (!elements.length) {
      setLoad({ status: "idle" });
      return;
    }
    const controller = new AbortController();
    setLoad({ status: "loading" });
    const task: Promise<ImpactData> = demo
      ? loadDemoImpact(elements)
      : client
        ? loadLiveImpact({
            tokens: elements,
            client,
            earliest,
            latest,
            timezone,
            signal: controller.signal,
            loadBaseTopology: () =>
              // Inventory changes slowly: read at least a day of it.
              loadTopology(
                client,
                /^-\d+[smh]$/.test(earliest) ? "-24h" : earliest,
                controller.signal,
                latest,
                timezone,
              ),
            merge: traceTopology,
          }).then((d) => ({ ...d, hours: windowHours(earliest, latest) }))
        : Promise.reject(new Error("Live search runs inside Splunk."));
    task
      .then(
        (data) =>
          !controller.signal.aborted && setLoad({ status: "done", data }),
      )
      .catch(
        (e: unknown) =>
          !controller.signal.aborted &&
          setLoad({
            status: "error",
            error: e instanceof Error ? e.message : "Impact failed",
          }),
      );
    return () => controller.abort();
  }, [elements, demo, client, earliest, latest, timezone, nonce]);

  const data = load.status === "done" ? load.data : undefined;
  const cls = useMemo(() => data && classifier(data.ctx), [data]);
  const resolved = useMemo(
    () => data?.elements.filter((e) => e.resolved) ?? [],
    [data],
  );
  const result: FailsResult | DependsResult | undefined = useMemo(() => {
    if (!data || !cls || !resolved.length) return undefined;
    return mode === "fails"
      ? failsImpact(resolved, data.conversations, data.ctx, {
          hours: data.hours,
          total: data.total,
          cls,
        })
      : dependsImpact(resolved, data.conversations, data.ctx, { cls });
  }, [data, cls, resolved, mode]);
  const blast = useMemo(
    () =>
      result?.mode === "fails" && cls
        ? blastGraph(result, cls, compileFailure(resolved))
        : undefined,
    [result, cls, resolved],
  );
  const unresolved = data?.elements.filter((e) => !e.resolved) ?? [];
  const exportCsv = () => {
    if (!result || !data) return;
    downloadBlob(
      `atlas-impact-${elements
        .join("+")
        .replace(/[^A-Za-z0-9.+_-]+/g, "_")
        .slice(0, 80)}.csv`,
      "text/csv;charset=utf-8",
      impactCsv(result, {
        window: `${earliest} to ${latest}`,
        source: data.source,
        generated: new Date().toISOString(),
      }),
    );
  };
  const mapLink =
    demo && result?.mode === "fails"
      ? pageURL(
          "map",
          new URLSearchParams([
            ...elements.map((e) => ["impact", e] as [string, string]),
          ]),
        )
      : undefined;
  return (
    <main className="atlas-page atlas-page-wide atlas-explore atlas-impact-page">
      <ExploreTabs />
      <div className="atlas-explore-tools">
        <ElementPicker elements={elements} onChange={setElements} />
        <div
          className="atlas-impact-mode"
          role="radiogroup"
          aria-label="Impact mode"
        >
          {(
            [
              ["fails", "If this fails"],
              ["depends", "Depends on"],
            ] as const
          ).map(([m, text]) => (
            <button
              key={m}
              type="button"
              role="radio"
              aria-checked={mode === m}
              className={mode === m ? "active" : ""}
              onClick={() => setMode(m)}
            >
              {text}
            </button>
          ))}
        </div>
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
      <div className="adm atlas-impact" data-adm-theme={theme}>
        {!elements.length && (
          <p role="status" className="muted">
            Pick an element: a leaf, spine, FI, ESXi host, VM, app or interface
            (<code>leaf101|eth1/21</code>, <code>if:vpc-1-22</code>). Add up to{" "}
            {MAX_IMPACT_ELEMENTS} to fail together.
          </p>
        )}
        {load.status === "loading" && (
          <p role="status" className="muted">
            <RefreshCw size={13} className="spin" aria-hidden /> Computing
            impact…
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
        {unresolved.map((e) => (
          <p key={e.token} className="callout warn" role="status">
            {e.candidates?.length ? (
              <>
                {e.token}: {plural(e.candidates.length, "match", "matches")} —{" "}
                {e.candidates.slice(0, 6).map((d, i) => (
                  <span key={d.id}>
                    {i > 0 && ", "}
                    <a
                      href={impactURL(
                        [...elements.filter((x) => x !== e.token), d.id],
                        { mode, earliest, latest },
                      )}
                    >
                      {d.name}
                    </a>
                  </span>
                ))}
              </>
            ) : (
              <>{e.token}: not in inventory</>
            )}
          </p>
        ))}
        {resolved
          .filter((e) => e.membershipAfter !== undefined)
          .map((e) => (
            <p key={`m:${e.token}`} className="callout" role="status">
              {e.label}: members from the APIC snapshot of{" "}
              {new Date(e.membershipAfter! * 1000)
                .toISOString()
                .slice(0, 16)
                .replace("T", " ")}{" "}
              UTC (none in this window)
            </p>
          ))}
        {result && (
          <>
            <h1 className="atlas-impact-headline" aria-live="polite">
              {result.headline.split(" · ").map((part, i) => (
                <Fragment key={part}>
                  {i > 0 && " · "}
                  {/possibly affected$/.test(part) ? (
                    <span
                      className="atlas-impact-possible"
                      title="Apps with pods on affected nodes; traffic not attributed"
                    >
                      {part}
                    </span>
                  ) : (
                    part
                  )}
                </Fragment>
              ))}
            </h1>
            {result.mode === "fails" ? (
              <>
                <div
                  className="kpis atlas-impact-kpis"
                  aria-label="Impact by severity"
                >
                  <Kpi label="Apps" split={result.kpis.apps} />
                  <Kpi label="Services" split={result.kpis.services} />
                  <Kpi label="Workloads" split={result.kpis.workloads} />
                  <Kpi
                    label="Conversations"
                    split={result.kpis.conversations}
                  />
                  <Kpi
                    label={data?.hours ? "Traffic/h" : "Traffic"}
                    split={result.kpis.bytes}
                    format={(n) =>
                      n
                        ? prettyBytes(Math.round(perHour(n, data?.hours) ?? n))
                        : "0"
                    }
                  />
                  <Kpi label="External" split={result.kpis.external} />
                  <span className="atlas-impact-legend muted small">
                    <i className="atlas-sev-n outage" /> outage{" "}
                    <i className="atlas-sev-n degraded" /> degraded
                  </span>
                </div>
                <div className="atlas-impact-grid">
                  <section
                    aria-label="Top impacted apps"
                    className="atlas-impact-apps"
                  >
                    <h2>Apps</h2>
                    {result.apps.length ? (
                      <ol>
                        {result.apps.slice(0, 10).map((a) => (
                          <li key={a.app}>
                            <Sev s={a.severity} />
                            <span
                              className="name"
                              title={
                                a.basis === "hubble"
                                  ? "Hubble pod flows on the node pair"
                                  : undefined
                              }
                            >
                              {a.app}
                            </span>
                            <span className="muted small">
                              {plural(a.conversations, "conv")}
                              {a.alternate ? ` · via ${a.alternate}` : ""}
                            </span>
                          </li>
                        ))}
                      </ol>
                    ) : (
                      <p className="muted">None confirmed</p>
                    )}
                    {result.possibleApps.length > 0 && (
                      <details className="atlas-impact-possible-apps">
                        <summary title="Apps with pods on affected nodes; traffic not attributed">
                          Possibly affected ({result.possibleApps.length})
                        </summary>
                        <ul>
                          {result.possibleApps.map((a) => (
                            <li key={a.app}>{a.app}</li>
                          ))}
                        </ul>
                      </details>
                    )}
                  </section>
                  {blast && <BlastMap graph={blast} />}
                </div>
                <div className="atlas-impact-table">
                  <VirtualTable
                    caption={
                      data && data.total > data.conversations.length
                        ? `${result.rows.length.toLocaleString()} affected · top ${data.conversations.length.toLocaleString()} of ${data.total.toLocaleString()} conversations`
                        : `${result.rows.length.toLocaleString()} affected of ${result.total.toLocaleString()} conversations`
                    }
                    rows={result.rows}
                    columns={failsColumns(data?.hours)}
                    rowKey={(c) => c.conv.id}
                    empty="No observed conversation traverses this element"
                  />
                </div>
              </>
            ) : (
              <div className="atlas-impact-table">
                <VirtualTable
                  caption={`${result.rows.length} dependencies across ${plural(result.conversations, "conversation")}`}
                  rows={result.rows}
                  columns={dependsColumns(data?.hours)}
                  rowKey={(d) => d.id}
                  empty="No dependency observed (not evidence that none exist)"
                />
              </div>
            )}
            <p className="atlas-impact-foot muted small">
              <button
                type="button"
                className="secondary-button"
                onClick={exportCsv}
              >
                <Download size={13} aria-hidden /> CSV
              </button>
              {mapLink && (
                <a className="secondary-button" href={mapLink}>
                  <MapIcon size={13} aria-hidden /> Map
                </a>
              )}
              {resolved
                .filter((e) => e.kind === "device")
                .slice(0, 1)
                .map((e) => (
                  <a
                    key={e.token}
                    className="secondary-button"
                    href={deviceURL(e.token)}
                  >
                    Device
                  </a>
                ))}
              <span>
                Observed = exported at the element · inferred = topology only
                {data?.capped
                  ? " · record cap reached, totals are lower bounds"
                  : ""}
                {data ? ` · ${data.source}` : ""}
              </span>
            </p>
            {data?.notes?.map((note) => (
              <p
                key={note}
                className="atlas-impact-foot muted small"
                role="note"
              >
                {note}
              </p>
            ))}
          </>
        )}
      </div>
    </main>
  );
}
