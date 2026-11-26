import { useEffect, useMemo, useRef, useState } from "react";
import type { Graph } from "../graph";
import { downloadBlob } from "../download";
import { plural } from "../glossary";
import { traceURL } from "../pages/ExploreTools";
import {
  aciContractDraft,
  ciliumPolicyDraft,
  firewallCsvDraft,
  networkPolicyDraft,
  type Draft,
} from "./drafts";
import {
  coverageSummary,
  describeSelector,
  parseRuleSetText,
  portText,
  replay,
  replayWindowError,
  seedRuleSet,
  serializeRuleSet,
  type Completeness,
  type RuleSet,
  type SeedResult,
  type Tally,
} from "./model";
import "./segmentation.css";

export interface PolicyWorkbenchProps {
  graph: Graph;
  /** Live only: reads another absolute window through the same bounded graph search. */
  loadWindow?: (
    start: string,
    end: string,
    signal: AbortSignal,
  ) => Promise<Graph>;
  /** Selects a conversation of the current map; only offered for the map's own window. */
  onShowEdge?: (edgeId: string) => void;
  onClose: () => void;
}

const count = (t: Tally) =>
  `${plural(t.conversations, "conversation")} · ${plural(t.connections, "connection")}`;
const epoch = (iso: string, round: (n: number) => number) =>
  String(round(Date.parse(iso) / 1000));

function CompletenessNote({ completeness }: { completeness: Completeness }) {
  return (
    <div
      className={`atlas-seg-completeness ${completeness.complete ? "" : "warn"}`}
      role={completeness.complete ? undefined : "status"}
    >
      <b>
        {completeness.complete
          ? "Read complete for the loaded map."
          : "Incomplete read: counts are lower bounds."}
      </b>
      {completeness.notes.length > 0 && (
        <ul>
          {completeness.notes.map((note) => (
            <li key={note}>{note}</li>
          ))}
        </ul>
      )}
    </div>
  );
}

export function PolicyWorkbench({
  graph,
  loadWindow,
  onShowEdge,
  onClose,
}: PolicyWorkbenchProps) {
  const [historical, setHistorical] = useState<Graph>();
  const evidence = historical ?? graph;
  const [seed, setSeed] = useState<SeedResult>(() => seedRuleSet(graph));
  const [ruleSet, setRuleSet] = useState<RuleSet>(seed.ruleSet);
  const [ruleText, setRuleText] = useState(() =>
    serializeRuleSet(seed.ruleSet),
  );
  const [ruleErrors, setRuleErrors] = useState<string[]>([]);
  const [start, setStart] = useState(graph.window.start);
  const [end, setEnd] = useState(graph.window.end);
  const [loading, setLoading] = useState(false);
  const [loadError, setLoadError] = useState("");
  const controller = useRef<AbortController>();
  const heading = useRef<HTMLHeadingElement>(null);
  useEffect(() => heading.current?.focus(), []);
  useEffect(() => () => controller.current?.abort(), []);

  const coverage = useMemo(() => coverageSummary(evidence), [evidence]);
  const result = useMemo(() => replay(evidence, ruleSet), [evidence, ruleSet]);
  const onMapWindow = historical === undefined;
  const draftContext = useMemo(
    () => ({
      window: evidence.window,
      scope: [
        evidence.boundary.environment,
        evidence.boundary.vmScope
          ? `VM scope ${evidence.boundary.vmScope}`
          : `${evidence.boundary.cluster} · ${evidence.boundary.namespace}`,
        evidence.boundary.service,
      ].join(" · "),
    }),
    [evidence],
  );
  const stem = `adm-${evidence.boundary.id.replace(/[^a-zA-Z0-9_-]/g, "_")}-segmentation-draft`;
  const linkParams = useMemo(() => {
    const params = new URLSearchParams(
      typeof location === "undefined" ? "" : location.search,
    );
    params.set("earliest", epoch(evidence.window.start, Math.floor));
    params.set("latest", epoch(evidence.window.end, Math.ceil));
    return params;
  }, [evidence]);

  const applyRules = (next: RuleSet) => {
    setRuleSet(next);
    setRuleText(serializeRuleSet(next));
    setRuleErrors([]);
  };
  const reseed = (source: Graph) => {
    const next = seedRuleSet(source);
    setSeed(next);
    applyRules(next.ruleSet);
  };
  const applyText = () => {
    const parsed = parseRuleSetText(ruleText);
    if (parsed.ok) applyRules(parsed.ruleSet);
    else setRuleErrors(parsed.errors);
  };
  const loadOther = async () => {
    const error = replayWindowError(start, end);
    if (error) {
      setLoadError(error);
      return;
    }
    if (!loadWindow) return;
    controller.current?.abort();
    const current = new AbortController();
    controller.current = current;
    setLoading(true);
    setLoadError("");
    try {
      const next = await loadWindow(
        new Date(start).toISOString(),
        new Date(end).toISOString(),
        current.signal,
      );
      if (!current.signal.aborted) setHistorical(next);
    } catch (reason) {
      if (!current.signal.aborted)
        setLoadError(
          reason instanceof Error
            ? reason.message
            : "The historical window could not be read.",
        );
    } finally {
      if (controller.current === current) setLoading(false);
    }
  };
  const download = (kind: string, type: string, draft: Draft) =>
    downloadBlob(`${stem}-${kind}`, type, draft.text);
  const drafts = useMemo(
    () => ({
      networkPolicy: networkPolicyDraft(ruleSet, draftContext),
      cilium: ciliumPolicyDraft(ruleSet, draftContext),
      aci: aciContractDraft(ruleSet, draftContext),
      firewall: firewallCsvDraft(ruleSet, evidence),
    }),
    [ruleSet, draftContext, evidence],
  );
  const noRules = ruleSet.rules.length === 0;

  return (
    <section className="atlas-seg" aria-labelledby="atlas-seg-title">
      <header className="atlas-seg-header">
        <div>
          <h2 id="atlas-seg-title" ref={heading} tabIndex={-1}>
            Segmentation policy workbench{" "}
            <span className="chip warn">Draft only</span>
          </h2>
          <p className="muted small">
            Tests rules against observed conversations in{" "}
            <b>{draftContext.scope}</b>. Exports are files for review; Atlas
            never pushes policy or calls cluster, controller or firewall APIs.
          </p>
        </div>
        <button type="button" className="secondary-button" onClick={onClose}>
          Close workbench
        </button>
      </header>

      <section className="atlas-seg-section" aria-label="Evidence window">
        <h3>Evidence window</h3>
        <p className="small">
          {evidence.window.start} → {evidence.window.end}
          {onMapWindow ? " (current map)" : " (historical read)"}
        </p>
        {loadWindow ? (
          <div className="atlas-seg-window">
            <label>
              Start (UTC, ISO 8601)
              <input value={start} onChange={(e) => setStart(e.target.value)} />
            </label>
            <label>
              End (UTC, ISO 8601)
              <input value={end} onChange={(e) => setEnd(e.target.value)} />
            </label>
            <button
              type="button"
              className="secondary-button"
              disabled={loading}
              onClick={() => void loadOther()}
            >
              {loading ? "Reading window…" : "Read window"}
            </button>
            {!onMapWindow && (
              <button
                type="button"
                className="link"
                onClick={() => {
                  controller.current?.abort();
                  setLoading(false);
                  setHistorical(undefined);
                }}
              >
                Back to map window
              </button>
            )}
          </div>
        ) : (
          <p className="muted small">
            Other windows can be read only from Splunk data; demo data has one
            captured window.
          </p>
        )}
        {loadError && <p role="alert">{loadError}</p>}
        <p className="muted small">
          Uses the same bounded map search (five-minute summaries up to 7 days,
          ranked top-N when large). Searches run with your Splunk permissions.
        </p>
        <CompletenessNote completeness={coverage.completeness} />
      </section>

      <section
        className="atlas-seg-section"
        aria-label="Existing policy coverage"
      >
        <h3>Existing policy coverage</h3>
        <div className="atlas-seg-tallies">
          <div className="atlas-seg-tally ok">
            <b>Covered</b>
            <span>{count(coverage.covered)}</span>
            <small>A collected ACI contract (or intra-EPG) permits it.</small>
          </div>
          <div className="atlas-seg-tally blocked">
            <b>Not covered</b>
            <span>{count(coverage.notCovered)}</span>
            <small>Collected ACI policy has no permit.</small>
          </div>
          <div className="atlas-seg-tally">
            <b>Unknown</b>
            <span>{count(coverage.unknown)}</span>
            <small>No policy data, or policy not evaluated.</small>
          </div>
        </div>
        <ul className="small atlas-seg-notes">
          <li>
            Covered means configured ACI intent, not proof of enforcement.
            Traffic is never counted as allowed without collected policy.
          </li>
          {coverage.ciliumNotCollected > 0 && (
            <li>
              {plural(coverage.ciliumNotCollected, "pod conversation")}: Atlas
              does not collect Cilium or Kubernetes policy rules, so the cluster
              side stays unknown.
            </li>
          )}
          {coverage.aclDrops > 0 && (
            <li>
              {plural(coverage.aclDrops, "conversation")} with logged ACL drops.
            </li>
          )}
          {coverage.conflicts > 0 && (
            <li className="warn">
              {plural(coverage.conflicts, "conversation")} permitted by a
              collected contract also logged drops.
            </li>
          )}
        </ul>
      </section>

      <section className="atlas-seg-section" aria-label="Proposed rules">
        <h3>Proposed rules</h3>
        <p className="small">
          {plural(ruleSet.rules.length, "rule")}. Seeded rules are exact allow
          rules for observed conversations; nothing is widened. Unmatched
          traffic is blocked by default, and deny rules take precedence.
        </p>
        <div className="atlas-seg-actions">
          <button
            type="button"
            className="secondary-button"
            onClick={() => reseed(evidence)}
          >
            Seed from observed traffic
          </button>
          <button
            type="button"
            className="secondary-button"
            onClick={() => applyRules({ ...ruleSet, rules: [] })}
          >
            Clear rules
          </button>
        </div>
        {(seed.skipped.length > 0 || seed.truncated) && (
          <details className="small">
            <summary>
              Not seeded:{" "}
              {plural(
                seed.skipped.reduce((n, s) => n + s.conversations, 0),
                "conversation",
              )}
            </summary>
            <ul>
              {seed.skipped.map((s) => (
                <li key={s.reason}>
                  {s.reason} ({s.conversations})
                </li>
              ))}
            </ul>
          </details>
        )}
        {!noRules && (
          <div className="atlas-table-scroll">
            <table className="atlas-table" aria-label="Proposed rules">
              <thead>
                <tr>
                  <th>Rule</th>
                  <th>Action</th>
                  <th>Source</th>
                  <th>Destination</th>
                  <th>Port</th>
                  <th>Matched</th>
                  <th>
                    <span className="sr-only">Remove</span>
                  </th>
                </tr>
              </thead>
              <tbody>
                {ruleSet.rules.map((rule) => {
                  const hits = result.ruleHits.find((h) => h.rule === rule.id);
                  return (
                    <tr key={rule.id}>
                      <td>{rule.id}</td>
                      <td>
                        <select
                          aria-label={`Action for ${rule.id}`}
                          value={rule.action}
                          onChange={(e) =>
                            applyRules({
                              ...ruleSet,
                              rules: ruleSet.rules.map((r) =>
                                r.id === rule.id
                                  ? {
                                      ...r,
                                      action: e.target.value as
                                        "allow" | "deny",
                                    }
                                  : r,
                              ),
                            })
                          }
                        >
                          <option value="allow">allow</option>
                          <option value="deny">deny</option>
                        </select>
                      </td>
                      <td>{describeSelector(rule.source)}</td>
                      <td>{describeSelector(rule.destination)}</td>
                      <td>
                        {portText(rule.ports)}/{rule.protocol}
                      </td>
                      <td>{hits ? hits.conversations : 0}</td>
                      <td>
                        <button
                          type="button"
                          className="link"
                          aria-label={`Remove ${rule.id}`}
                          onClick={() =>
                            applyRules({
                              ...ruleSet,
                              rules: ruleSet.rules.filter(
                                (r) => r.id !== rule.id,
                              ),
                            })
                          }
                        >
                          Remove
                        </button>
                      </td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
          </div>
        )}
        <details>
          <summary>Edit rules as JSON</summary>
          <p className="muted small">
            Selectors: application (service, environment), endpoint (nodeId),
            epg (tenant, appProfile, epg), esg (tenant, esg; never resolved),
            k8s (cluster, namespace, optional workload controller), cidr (IPv4).
            Pod labels are not collected, so label selectors are rejected.
          </p>
          <textarea
            aria-label="Rule set JSON"
            className="atlas-seg-json"
            spellCheck={false}
            value={ruleText}
            onChange={(e) => setRuleText(e.target.value)}
          />
          <button
            type="button"
            className="secondary-button"
            onClick={applyText}
          >
            Apply JSON
          </button>
          {ruleErrors.length > 0 && (
            <div role="alert">
              <b>Rules not applied:</b>
              <ul>
                {ruleErrors.slice(0, 20).map((error) => (
                  <li key={error}>{error}</li>
                ))}
              </ul>
            </div>
          )}
        </details>
      </section>

      <section className="atlas-seg-section" aria-label="Replay">
        <h3>Replay against the evidence window</h3>
        <div className="atlas-seg-tallies">
          <div className="atlas-seg-tally ok">
            <b>Would be allowed</b>
            <span>{count(result.allowed)}</span>
          </div>
          <div className="atlas-seg-tally blocked">
            <b>Would be blocked</b>
            <span>{count(result.blocked)}</span>
          </div>
          <div className="atlas-seg-tally">
            <b>Unknown</b>
            <span>{count(result.unknown)}</span>
          </div>
        </div>
        {!result.completeness.complete && (
          <p className="small warn" role="status">
            Incomplete read: more traffic may be blocked than shown.
          </p>
        )}
        {result.unknownReasons.length > 0 && (
          <details className="small">
            <summary>Why some conversations are unknown</summary>
            <ul>
              {result.unknownReasons.map((r) => (
                <li key={r.reason}>
                  {r.reason} ({r.conversations})
                </li>
              ))}
            </ul>
          </details>
        )}
        {result.unusedRules.length > 0 && (
          <p className="small muted">
            No observed conversation matched: {result.unusedRules.join(", ")}.
          </p>
        )}
        {result.topBlocked.length > 0 && (
          <div className="atlas-table-scroll">
            <table
              className="atlas-table"
              aria-label="Top would-be-blocked conversations"
            >
              <caption className="small">
                Top {result.topBlocked.length} would-be-blocked conversations by
                connections
                {result.blockedTruncated &&
                  ` (of ${result.blocked.conversations.toLocaleString("en-US")})`}
              </caption>
              <thead>
                <tr>
                  <th>Source</th>
                  <th>Destination</th>
                  <th>Port</th>
                  <th>Connections</th>
                  <th>Reason</th>
                  <th>Evidence</th>
                </tr>
              </thead>
              <tbody>
                {result.topBlocked.map((b) => (
                  <tr key={b.edgeId}>
                    <td>{b.source.label}</td>
                    <td>{b.target.label}</td>
                    <td>
                      {b.port}/{b.protocol}
                    </td>
                    <td>{b.connections.toLocaleString("en-US")}</td>
                    <td>
                      {b.basis === "deny_rule"
                        ? `Deny rule ${b.rule}`
                        : "No allow rule (default deny)"}
                    </td>
                    <td>
                      <span className="small">{b.evidence.join(", ")}</span>{" "}
                      {onMapWindow && onShowEdge && (
                        <button
                          type="button"
                          className="link"
                          onClick={() => onShowEdge(b.edgeId)}
                        >
                          Show on map
                        </button>
                      )}{" "}
                      {b.source.address && b.target.address && (
                        <a
                          href={traceURL(
                            b.source.address,
                            b.target.address,
                            linkParams,
                            b.source.scope ?? b.target.scope,
                          )}
                        >
                          Trace
                        </a>
                      )}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </section>

      <section className="atlas-seg-section" aria-label="Draft exports">
        <h3>Draft exports</h3>
        <p className="small muted">
          Every file is marked DRAFT and lists the rules it could not represent.
          Review selectors, labels and ports before any manual use.
        </p>
        <div className="atlas-seg-exports">
          {(
            [
              [
                "networkpolicy.yaml",
                "text/yaml;charset=utf-8",
                drafts.networkPolicy,
                "Kubernetes NetworkPolicy (YAML)",
              ],
              [
                "ciliumnetworkpolicy.yaml",
                "text/yaml;charset=utf-8",
                drafts.cilium,
                "CiliumNetworkPolicy (YAML)",
              ],
              [
                "aci-contracts.json",
                "application/json",
                drafts.aci,
                "ACI contract/subject/filter (APIC JSON)",
              ],
              [
                "firewall-rules.csv",
                "text/csv;charset=utf-8",
                drafts.firewall,
                "Firewall rules (CSV)",
              ],
            ] as const
          ).map(([file, type, draft, label]) => (
            <button
              key={file}
              type="button"
              className="menu-item"
              disabled={noRules}
              onClick={() => download(file, type, draft)}
            >
              <span>
                <b>{label}</b>
                <small>
                  {plural(draft.included, "rule")} included
                  {draft.skipped.length > 0 &&
                    ` · ${draft.skipped.length} not representable`}
                </small>
              </span>
            </button>
          ))}
        </div>
      </section>
    </section>
  );
}
