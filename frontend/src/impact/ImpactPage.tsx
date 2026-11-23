import { Fragment, useEffect, useId, useMemo, useRef, useState } from "react";
import { Download, Map as MapIcon, RefreshCw, X, Zap } from "lucide-react";
import {
  SearchAccessDeniedError,
  type SearchClient,
} from "../data/searchClient";
import { downloadBlob } from "../download";
import { plural, prettyBytes } from "../glossary";
import { TimePicker } from "../map/TimePicker";
import { ExploreTabs, deviceURL, traceURL } from "../pages/ExploreTools";
import { pageURL } from "../app/urlState";
import { VirtualTable, type VirtualColumn } from "../scale/VirtualTable";
import type { Theme } from "../theme";
import { blastGraph } from "./blast";
import { BlastMap } from "./BlastMap";
import { classifier, compileFailure, type Classified } from "./classify";
import { impactCsv } from "./csv";
import { loadLiveImpact, type ImpactData } from "./data";
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
import { impactURL, isImpactScope, parseImpactParams } from "./url";
import { ObservedJourneyImpact } from "./ObservedJourneyImpact";
import {
  observedImpactClassifier,
  observedImpactData,
  observedJourneyImpact,
} from "./observedImpact";
import "./impact.css";
import { JourneyLazyEvidence } from "../JourneyLazyEvidence";

type Load =
  | { status: "idle" }
  | { status: "loading" }
  | { status: "error"; error: string; denied?: boolean }
  | { status: "done"; data: ImpactData };

const SEV_LABEL = {
  outage: "Outage",
  degraded: "Degraded",
  unknown: "Outcome not tested",
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
      "Observed: direct evidence for this connection. Linked leg: observed on another TCP connection in this journey. Inferred: topology only.",
    render: (c) => (
      <span className={c.traversal === "observed" ? "" : "atlas-inferred"}>
        {c.linkedTraversal ? "Linked leg" : c.traversal}
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
      aria-label={`${label}: ${split.outage} outage, ${split.degraded} degraded${split.unknown ? `, ${split.unknown} outcome not tested` : ""}`}
    >
      <span className="kpi-label">{label}</span>
      <b className="atlas-sev-n outage" title="Outage">
        {format(split.outage)}
      </b>
      <b className="atlas-sev-n degraded" title="Degraded">
        {format(split.degraded)}
      </b>
      {split.unknown > 0 && (
        <b className="atlas-sev-n unknown" title="Outcome not tested">
          {format(split.unknown)}
        </b>
      )}
    </span>
  );
}

function ElementPicker({
  elements,
  onChange,
  devices,
}: {
  elements: string[];
  onChange: (e: string[]) => void;
  devices?: NonNullable<ImpactData["observed"]>["devices"];
}) {
  const id = useId();
  const choices = devices?.filter((device) => !elements.includes(device.id));
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
        list={choices?.length ? `${id}-choices` : undefined}
        spellCheck={false}
        disabled={full}
        value={value}
        onChange={(e) => setValue(e.target.value)}
      />
      {!!choices?.length && (
        <datalist id={`${id}-choices`}>
          {choices.map((device) => (
            <option key={device.id} value={device.id}>
              {device.name}
            </option>
          ))}
        </datalist>
      )}
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
  const [scope, setScope] = useState(initial.scope ?? "");
  const [nonce, setNonce] = useState(0);
  const [load, setLoad] = useState<Load>({ status: "idle" });
  const qualified = useRef<{
    key: string;
    client: SearchClient;
    cohort: NonNullable<ImpactData["observed"]>;
  }>();

  // The URL is the shareable state.
  useEffect(() => {
    if (typeof window === "undefined") return;
    const href = impactURL(
      elements,
      { mode, earliest, latest, scope },
      new URLSearchParams(),
    );
    const query = href.slice(href.indexOf("?"));
    if (location.search !== query)
      history.replaceState(
        null,
        "",
        `${location.pathname}${query}${location.hash}`,
      );
  }, [elements, mode, earliest, latest, scope]);

  useEffect(() => {
    if (!elements.length) {
      setLoad({ status: "idle" });
      return;
    }
    if (!demo && !isImpactScope(scope)) {
      setLoad({ status: "idle" });
      return;
    }
    const controller = new AbortController();
    const key = JSON.stringify([scope, earliest, latest, timezone, nonce]);
    const cached = qualified.current;
    const task: Promise<ImpactData> = demo
      ? loadDemoImpact(elements)
      : cached?.key === key && cached.client === client
        ? Promise.resolve().then(() =>
            observedImpactData(cached.cohort, elements),
          )
        : client
          ? loadLiveImpact({
              tokens: elements,
              client,
              earliest,
              latest,
              scope,
              timezone,
              signal: controller.signal,
            })
          : Promise.reject(new Error("Live search runs inside Splunk."));
    setLoad({ status: "loading" });
    task
      .then((data) => {
        if (controller.signal.aborted) return;
        if (client && data.observed)
          qualified.current = { key, client, cohort: data.observed };
        setLoad({ status: "done", data });
      })
      .catch(
        (e: unknown) =>
          !controller.signal.aborted &&
          setLoad({
            status: "error",
            denied: e instanceof SearchAccessDeniedError,
            error: e instanceof Error ? e.message : "Impact failed",
          }),
      );
    return () => controller.abort();
  }, [elements, demo, client, earliest, latest, timezone, scope, nonce]);

  const data = load.status === "done" ? load.data : undefined;
  const cls = useMemo(
    () =>
      data &&
      (data.observed
        ? observedImpactClassifier(data.ctx, data.observed)
        : classifier(data.ctx)),
    [data],
  );
  const resolved = useMemo(
    () => data?.elements.filter((e) => e.resolved) ?? [],
    [data],
  );
  const result: FailsResult | DependsResult | undefined = useMemo(() => {
    if (
      !data ||
      !cls ||
      !resolved.length ||
      (data.observed && mode === "depends")
    )
      return undefined;
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
  const observed = data?.observed;
  const journeys = useMemo(
    () =>
      observed ? observedJourneyImpact(observed, compileFailure(resolved)) : [],
    [observed, resolved],
  );
  const exposed = journeys.filter((journey) => journey.exposed.length > 0);
  const browserJourneys = exposed.filter(
    (journey) => journey.actor === "browser",
  ).length;
  const observedHead =
    result?.mode === "fails" && observed
      ? `${result.label} what-if · ${plural(new Set(exposed.map((j) => j.app)).size, "app")} with observed exposure · ${plural(browserJourneys, "browser journey exposed", "browser journeys exposed")}`
      : undefined;
  const unresolved = data?.elements.filter((e) => !e.resolved) ?? [];
  const deviceChoices = observed?.devices.map((device) => device.name);
  const failedDeviceIds = resolved.flatMap((element) => [...element.devices]);
  const exportCsv = () => {
    if (!result || !data) return;
    downloadBlob(
      `atlas-impact-${elements
        .join("+")
        .replace(/[^A-Za-z0-9.+_-]+/g, "_")
        .slice(0, 80)}.csv`,
      "text/csv;charset=utf-8",
      impactCsv(observedHead ? { ...result, headline: observedHead } : result, {
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
        <ElementPicker
          elements={elements}
          onChange={setElements}
          devices={observed?.devices}
        />
        {!demo && (
          <label>
            Routing scope
            <input
              value={scope}
              onChange={(event) => setScope(event.target.value)}
              autoComplete="off"
            />
          </label>
        )}
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
              disabled={!demo && m === "depends"}
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
        <button
          type="button"
          className="secondary-button"
          disabled={
            load.status === "loading" ||
            !elements.length ||
            (!demo && !isImpactScope(scope))
          }
          onClick={() => setNonce((value) => value + 1)}
        >
          Refresh impact
        </button>
      </div>
      <div className="adm atlas-impact" data-adm-theme={theme}>
        {!demo && elements.length > 0 && !isImpactScope(scope) && (
          <p role="status">
            Enter a mapped routing scope to assess live impact.
          </p>
        )}
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
                        { mode, earliest, latest, scope },
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
        {deviceChoices?.length && (
          <p className="muted small">
            Fixed-window evidence · Devices in this sample{" "}
            {deviceChoices.join(", ")}
          </p>
        )}
        {observed && mode === "depends" && (
          <p role="status">
            Select If this fails to compare the fixed-window device
            observations.
          </p>
        )}
        {result && (
          <>
            <h1 className="atlas-impact-headline" aria-live="polite">
              {(observedHead ?? result.headline).split(" · ").map((part, i) => (
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
                {observed && (
                  <ObservedJourneyImpact
                    cohort={observed}
                    journeys={journeys}
                    selectedDevices={failedDeviceIds}
                  />
                )}
                {!observed && (
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
                          ? prettyBytes(
                              Math.round(perHour(n, data?.hours) ?? n),
                            )
                          : "0"
                      }
                    />
                    <Kpi label="External" split={result.kpis.external} />
                    <span className="atlas-impact-legend muted small">
                      <i className="atlas-sev-n outage" /> outage{" "}
                      <i className="atlas-sev-n degraded" /> degraded
                    </span>
                  </div>
                )}
                <div className="atlas-impact-grid">
                  <section
                    aria-label="Top impacted apps"
                    className="atlas-impact-apps"
                  >
                    <h2>{observed ? "Apps with observed exposure" : "Apps"}</h2>
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
                      observed
                        ? `${result.rows.length} of ${result.total} recorded samples with evidence on the selection`
                        : data && data.total > data.conversations.length
                          ? `${result.rows.length.toLocaleString()} affected · top ${data.conversations.length.toLocaleString()} of ${data.total.toLocaleString()} conversations`
                          : `${result.rows.length.toLocaleString()} affected of ${result.total.toLocaleString()} conversations`
                    }
                    rows={result.rows}
                    columns={failsColumns(data?.hours)}
                    rowKey={(c) => c.conv.id}
                    empty={
                      observed
                        ? "No traversal of the selection in these recorded samples"
                        : "No observed conversation traverses this element"
                    }
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
                {observed
                  ? "Observed evidence for selected devices · fixed-window sample"
                  : "Observed = exported at the element · inferred = topology only"}
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
        {elements.length > 0 && (
          <JourneyLazyEvidence
            kind="ownership"
            graph={data?.graph}
            unavailableReason={
              load.status === "loading"
                ? "Impact evidence is loading."
                : load.status === "error"
                  ? "Impact source evidence is unavailable."
                  : !data?.graph
                    ? "Impact endpoints do not carry qualified service identities. Names and addresses cannot establish ownership."
                    : undefined
            }
          />
        )}
        {elements.length > 0 && (
          <JourneyLazyEvidence
            kind="maintenance"
            data={data}
            result={result?.mode === "fails" ? result : undefined}
            selection={{ elements, earliest, latest, scope, demo }}
            loading={load.status === "loading"}
            denied={load.status === "error" && load.denied}
          />
        )}
      </div>
    </main>
  );
}
