import { useEffect, useMemo, useRef, useState } from "react";
import { normalizeIp } from "../data/evidence";
import {
  evidenceConfigClient,
  type EvidenceConfigClient,
} from "../data/evidenceConfig";
import type { SearchClient } from "../data/searchClient";
import { downloadBlob } from "../download";
import {
  DEFAULT_RULES,
  PLANNER_LIMITS,
  SHARED_PORT_CATALOG,
  UNASSIGNED,
  parseCustomPorts,
  parseSeedLines,
  planMoveGroups,
  type DependencyEdge,
  type MovePlan,
  type PlannerOverrides,
  type PlannerRules,
  type SeedGroupInput,
} from "../ops/moveGroup";
import {
  PLANNER_WINDOW_PRESETS,
  loadPlannerDataset,
  presetSelection,
  type PlannerDataset,
} from "./data";
import { blockersCsv, describeReason, groupsCsv, planJson } from "./export";
import {
  VMWARE_LABEL_LIMITS,
  loadVmwareInventoryLabels,
  type VmwareInventoryResult,
} from "./vmwareInventory";
import "./migration.css";

const DISPLAY_ROWS = 200;
const iso = (seconds: number) => new Date(seconds * 1000).toISOString();
const EXPANSION: Record<string, string> = {
  expanded: "Expanded",
  depth_limit: "Stopped: depth limit",
  connection_limit: "Stopped: connection limit",
  group_size_limit: "Stopped: group size limit",
  not_expanded: "Not expanded",
};
const BASIS: Record<string, string> = {
  seed: "Seed (you chose it)",
  traversal: "Inferred from observed conversations",
  manual: "Moved by you",
};
const EMPTY_OVERRIDES: PlannerOverrides = {
  pinnedShared: [],
  notShared: [],
  assignments: {},
};

type PlanState =
  | { plan: MovePlan; seeds: SeedGroupInput[]; rules: PlannerRules }
  | { error: string };

function NumberRule({
  label,
  value,
  min,
  max,
  onChange,
}: {
  label: string;
  value: number;
  min: number;
  max: number;
  onChange: (value: number) => void;
}) {
  return (
    <label>
      {label}
      <input
        type="number"
        aria-label={label}
        min={min}
        max={max}
        step={1}
        value={Number.isFinite(value) ? value : ""}
        onChange={(e) => onChange(Number(e.target.value))}
      />
    </label>
  );
}

function EdgeTable({
  caption,
  edges,
  total,
  groupLabel,
}: {
  caption: string;
  edges: DependencyEdge[];
  total: number;
  groupLabel: (id: string) => string;
}) {
  if (!edges.length) return null;
  return (
    <>
      {total > Math.min(edges.length, DISPLAY_ROWS) && (
        <p role="status">
          Showing {Math.min(edges.length, DISPLAY_ROWS)} of{" "}
          {total.toLocaleString()} conversations. Exports include up to{" "}
          {PLANNER_LIMITS.edgeList.toLocaleString()}.
        </p>
      )}
      <div
        className="endpoint-table-scroll migration-table-scroll"
        role="region"
        aria-label={`${caption} table`}
        tabIndex={0}
      >
        <table>
          <caption>{caption}</caption>
          <thead>
            <tr>
              <th>Client group → server group</th>
              <th>Observed client → server</th>
              <th>Port / transport</th>
              <th>Direction</th>
              <th>Flow records</th>
              <th>Bytes</th>
              <th>Observers</th>
              <th>First seen</th>
              <th>Last seen</th>
            </tr>
          </thead>
          <tbody>
            {edges.slice(0, DISPLAY_ROWS).map((e, i) => (
              <tr key={`${e.client}:${e.server}:${e.port}:${e.transport}:${i}`}>
                <td>
                  {groupLabel(e.clientGroup)} → {groupLabel(e.serverGroup)}
                </td>
                <td>
                  {e.client} → {e.server}
                </td>
                <td>
                  {e.port ?? "—"} / {e.transport}
                </td>
                <td>{e.directed ? "Observed" : "Unknown"}</td>
                <td>{e.records.toLocaleString()}</td>
                <td>
                  {e.bytes === undefined ? "Unknown" : e.bytes.toLocaleString()}
                </td>
                <td>
                  {e.observers.join(", ") || "Unknown"}
                  {e.observersCapped ? " (more not shown)" : ""}
                </td>
                <td>{iso(e.first)}</td>
                <td>{iso(e.last)}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </>
  );
}

export function MigrationPlannerPage({
  client,
  live,
  configurationClient,
  initialDataset,
  initialSeeds = "",
}: {
  client?: SearchClient;
  live: boolean;
  configurationClient?: EvidenceConfigClient;
  /** Test and replay entry point; live use loads through the search client. */
  initialDataset?: PlannerDataset;
  initialSeeds?: string;
}) {
  const [scope, setScope] = useState(initialDataset?.selection.scope ?? "");
  const [preset, setPreset] = useState<string>("7d");
  const [seedText, setSeedText] = useState(initialSeeds);
  const [rules, setRules] = useState<PlannerRules>(DEFAULT_RULES);
  const [customPorts, setCustomPorts] = useState("");
  const [overrides, setOverrides] = useState<PlannerOverrides>(EMPTY_OVERRIDES);
  const [dataset, setDataset] = useState<PlannerDataset | undefined>(
    initialDataset,
  );
  const [error, setError] = useState("");
  const [loading, setLoading] = useState(false);
  const [vmware, setVmware] = useState<VmwareInventoryResult>();
  const [vmwareError, setVmwareError] = useState("");
  const [vmwareLoading, setVmwareLoading] = useState(false);
  const controllerRef = useRef<AbortController>();
  useEffect(() => () => controllerRef.current?.abort(), []);

  const state: PlanState | undefined = useMemo(() => {
    if (!dataset || !seedText.trim()) return undefined;
    try {
      const seeds = parseSeedLines(seedText, normalizeIp);
      const custom = parseCustomPorts(customPorts);
      const merged: PlannerRules = {
        ...rules,
        sharedPorts: [
          ...rules.sharedPorts,
          ...custom.filter(
            (p) =>
              !rules.sharedPorts.some(
                (q) => q.port === p.port && q.transport === p.transport,
              ),
          ),
        ],
      };
      return {
        plan: planMoveGroups({
          conversations: dataset.conversations,
          complete: !dataset.capped && dataset.unprotectedRows === 0,
          seeds,
          rules: merged,
          overrides,
        }),
        seeds,
        rules: merged,
      };
    } catch (reason) {
      return {
        error: reason instanceof Error ? reason.message : "Invalid plan input.",
      };
    }
  }, [dataset, seedText, rules, customPorts, overrides]);
  const plan = state && "plan" in state ? state.plan : undefined;
  const groupLabel = (id: string) =>
    plan?.groups.find((g) => g.id === id)?.label ??
    (id === "shared" ? "Shared services" : "Not in a group");
  const vmName = (address: string) => {
    const label = vmware?.labels.find((l) => l.address === address);
    if (!label) return undefined;
    return `${label.vmName}${label.claims > 1 ? " (ambiguous: several VMs report this IP)" : ""}`;
  };

  const load = async () => {
    if (!client) {
      setError("Conversation search is unavailable.");
      return;
    }
    let selection;
    try {
      const seconds =
        PLANNER_WINDOW_PRESETS.find((p) => p.id === preset)?.seconds ?? 0;
      selection = presetSelection(scope, seconds);
    } catch (reason) {
      setError(reason instanceof Error ? reason.message : "Invalid window.");
      return;
    }
    controllerRef.current?.abort();
    const controller = new AbortController();
    controllerRef.current = controller;
    setLoading(true);
    setError("");
    setDataset(undefined);
    setVmware(undefined);
    setVmwareError("");
    try {
      const next = await loadPlannerDataset(
        client,
        configurationClient ?? evidenceConfigClient,
        selection,
        controller.signal,
      );
      if (!controller.signal.aborted) setDataset(next);
    } catch (reason) {
      if (!controller.signal.aborted)
        setError(
          reason instanceof Error
            ? reason.message
            : "Conversation search failed.",
        );
    } finally {
      if (controllerRef.current === controller) setLoading(false);
    }
  };

  const loadVmware = async () => {
    if (!client || !plan || !dataset) return;
    const addresses = [
      ...plan.groups.flatMap((g) => g.members.map((m) => m.address)),
      ...plan.shared.map((s) => s.address),
    ].slice(0, VMWARE_LABEL_LIMITS.addresses);
    if (!addresses.length) return;
    const controller = new AbortController();
    controllerRef.current = controller;
    setVmwareLoading(true);
    setVmwareError("");
    try {
      const result = await loadVmwareInventoryLabels(
        client,
        addresses,
        dataset.selection.end,
        controller.signal,
      );
      if (!controller.signal.aborted) setVmware(result);
    } catch (reason) {
      if (!controller.signal.aborted)
        setVmwareError(
          reason instanceof Error ? reason.message : "VMware lookup failed.",
        );
    } finally {
      setVmwareLoading(false);
    }
  };

  const assign = (address: string, target: string, traversalGroup?: string) =>
    setOverrides((o) => {
      const assignments = { ...o.assignments };
      if (target === traversalGroup) delete assignments[address];
      else assignments[address] = target;
      return {
        ...o,
        pinnedShared: o.pinnedShared.filter((a) => a !== address),
        assignments,
      };
    });
  const pin = (address: string) =>
    setOverrides((o) => {
      const assignments = { ...o.assignments };
      delete assignments[address];
      return {
        pinnedShared: [...new Set([...o.pinnedShared, address])],
        notShared: o.notShared.filter((a) => a !== address),
        assignments,
      };
    });
  const unshare = (address: string) =>
    setOverrides((o) => ({
      ...o,
      pinnedShared: o.pinnedShared.filter((a) => a !== address),
      notShared: o.pinnedShared.includes(address)
        ? o.notShared
        : [...new Set([...o.notShared, address])],
    }));
  // A manual assignment remembers where traversal put the host so "Move to"
  // that group again clears the override.
  const traversalGroups = useMemo(() => {
    if (!dataset || !state || !("plan" in state))
      return new Map<string, string>();
    try {
      const base = planMoveGroups({
        conversations: dataset.conversations,
        complete: true,
        seeds: state.seeds,
        rules: state.rules,
        overrides: { ...overrides, assignments: {} },
      });
      return new Map(
        base.groups.flatMap((g) =>
          g.members.map((m) => [m.address, g.id] as const),
        ),
      );
    } catch {
      return new Map<string, string>();
    }
  }, [dataset, state, overrides]);

  const download = (kind: "groups" | "blockers" | "json") => {
    if (!dataset || !state || !("plan" in state)) return;
    const labels = vmware?.labels ?? [];
    if (kind === "json")
      downloadBlob(
        "move-group-plan.json",
        "application/json",
        planJson(
          dataset,
          state.plan,
          state.seeds,
          state.rules,
          overrides,
          labels,
        ),
      );
    else
      downloadBlob(
        `move-group-${kind}.csv`,
        "text/csv",
        kind === "groups"
          ? groupsCsv(dataset, state.plan, labels)
          : blockersCsv(dataset, state.plan),
      );
  };

  const portEnabled = (port: number) =>
    rules.sharedPorts.some((p) => p.port === port);
  const togglePort = (port: number, enabled: boolean) => {
    const rule = SHARED_PORT_CATALOG.find((r) => r.port === port)!;
    setRules((r) => ({
      ...r,
      sharedPorts: enabled
        ? [
            ...r.sharedPorts.filter((p) => p.port !== port),
            ...rule.transports.map((transport) => ({ port, transport })),
          ]
        : r.sharedPorts.filter((p) => p.port !== port),
    }));
  };
  const moveOptions = plan
    ? [
        ...plan.groups.map((g) => [g.id, g.label] as const),
        [UNASSIGNED, "Not in a group"] as const,
      ]
    : [];
  const coverage = dataset?.coverage;
  const gapDays = coverage?.days.filter((d) => d.buckets < d.expected) ?? [];

  return (
    <section
      className="page endpoints-page migration-page"
      aria-labelledby="migration-title"
    >
      <h2 id="migration-title">Migration move groups</h2>
      <p>
        Group servers by who they were observed talking to, stop at shared
        services, and see which cross-group conversations block a wave. Groups
        and shared services are planning inferences; conversations are observed
        summaries. Nothing here changes devices or other systems.
      </p>
      {!live && <p role="status">Requires live data</p>}
      <form
        aria-label="Load conversations"
        onSubmit={(event) => {
          event.preventDefault();
          void load();
        }}
      >
        <label>
          Verified routing scope
          <input
            aria-label="Verified routing scope"
            value={scope}
            onChange={(e) => setScope(e.target.value)}
            required
          />
        </label>
        <label>
          Window
          <select
            aria-label="Window"
            value={preset}
            onChange={(e) => setPreset(e.target.value)}
          >
            {PLANNER_WINDOW_PRESETS.map((p) => (
              <option key={p.id} value={p.id}>
                {p.label}
              </option>
            ))}
          </select>
        </label>
        <button type="submit" disabled={!live || loading}>
          {loading ? "Loading…" : "Load conversations"}
        </button>
        {loading && (
          <button type="button" onClick={() => controllerRef.current?.abort()}>
            Cancel search
          </button>
        )}
      </form>
      {error && <p role="alert">{error}</p>}
      <div className="migration-setup">
        <label className="migration-seeds">
          Seeds: one application or group per line
          <textarea
            aria-label="Seeds"
            rows={4}
            placeholder={"Orders = 10.0.0.1, 10.0.0.2\nBilling = 10.1.0.1"}
            value={seedText}
            onChange={(e) => setSeedText(e.target.value)}
            spellCheck={false}
          />
          <span className="migration-hint">
            Up to {PLANNER_LIMITS.seedGroups} lines and{" "}
            {PLANNER_LIMITS.seedAddresses} addresses. The text before = is a
            label.
          </span>
        </label>
        <fieldset>
          <legend>Traversal rules</legend>
          <NumberRule
            label="Traversal depth"
            value={rules.maxDepth}
            min={0}
            max={PLANNER_LIMITS.depth}
            onChange={(maxDepth) => setRules((r) => ({ ...r, maxDepth }))}
          />
          <NumberRule
            label="Maximum group size"
            value={rules.maxGroupSize}
            min={1}
            max={PLANNER_LIMITS.groupSize}
            onChange={(maxGroupSize) =>
              setRules((r) => ({ ...r, maxGroupSize }))
            }
          />
          <NumberRule
            label="Stop expanding hosts with more peers than"
            value={rules.maxConnections}
            min={1}
            max={PLANNER_LIMITS.connections}
            onChange={(maxConnections) =>
              setRules((r) => ({ ...r, maxConnections }))
            }
          />
          <label className="migration-check">
            <input
              type="checkbox"
              checked={rules.mergeConnectedSeeds}
              onChange={(e) =>
                setRules((r) => ({
                  ...r,
                  mergeConnectedSeeds: e.target.checked,
                }))
              }
            />
            Merge seed groups that talk directly
          </label>
        </fieldset>
        <fieldset>
          <legend>Shared-service rules</legend>
          <label>
            Highly connected hosts
            <select
              aria-label="Fan-in percentile"
              value={rules.fanInPercentile ?? "off"}
              onChange={(e) =>
                setRules((r) => ({
                  ...r,
                  fanInPercentile:
                    e.target.value === "off" ? null : Number(e.target.value),
                }))
              }
            >
              <option value="off">Off</option>
              <option value="90">Top 10% by distinct peers</option>
              <option value="95">Top 5% by distinct peers</option>
              <option value="99">Top 1% by distinct peers</option>
            </select>
          </label>
          <NumberRule
            label="And at least this many peers"
            value={rules.minFanIn}
            min={1}
            max={PLANNER_LIMITS.connections}
            onChange={(minFanIn) => setRules((r) => ({ ...r, minFanIn }))}
          />
          <NumberRule
            label="Port rule: minimum distinct clients"
            value={rules.minPortClients}
            min={1}
            max={1000}
            onChange={(minPortClients) =>
              setRules((r) => ({ ...r, minPortClients }))
            }
          />
          <div
            className="migration-ports"
            role="group"
            aria-label="Shared ports"
          >
            {SHARED_PORT_CATALOG.map((rule) => (
              <label
                key={rule.id}
                className="migration-check"
                title={rule.note}
              >
                <input
                  type="checkbox"
                  checked={portEnabled(rule.port)}
                  onChange={(e) => togglePort(rule.port, e.target.checked)}
                />
                {rule.service} ({rule.transports.join("/")} {rule.port})
              </label>
            ))}
          </div>
          <label>
            Other shared ports
            <input
              aria-label="Other shared ports"
              placeholder="tcp/10102, udp/514"
              value={customPorts}
              onChange={(e) => setCustomPorts(e.target.value)}
            />
          </label>
        </fieldset>
      </div>
      {dataset && (
        <section
          aria-label="Conversation coverage"
          className="migration-summary"
        >
          <p>
            <strong>{dataset.conversations.length.toLocaleString()}</strong>{" "}
            observed conversations in <strong>{dataset.selection.scope}</strong>{" "}
            from {iso(dataset.selection.start)} to {iso(dataset.selection.end)}.
            Captured {iso(dataset.capturedAt)}.
          </p>
          {coverage && (
            <p>
              Summary coverage: {coverage.coveredBuckets.toLocaleString()} of{" "}
              {coverage.expectedBuckets.toLocaleString()} five-minute buckets
              have conversation rows in this scope
              {gapDays.length
                ? `; ${gapDays.length} days are partly or wholly missing.`
                : "."}
            </p>
          )}
          {dataset.warnings.map((warning, i) => (
            <p role="note" key={i}>
              {warning}
            </p>
          ))}
        </section>
      )}
      {dataset && !seedText.trim() && (
        <p role="status">Enter seed addresses to build move groups.</p>
      )}
      {state && "error" in state && <p role="alert">{state.error}</p>}
      {plan && state && "plan" in state && (
        <section aria-label="Move-group plan">
          <div aria-label="Plan downloads" className="migration-actions">
            <button type="button" onClick={() => download("groups")}>
              Download groups CSV
            </button>
            <button type="button" onClick={() => download("blockers")}>
              Download dependencies CSV
            </button>
            <button type="button" onClick={() => download("json")}>
              Download plan JSON
            </button>
            <button
              type="button"
              disabled={vmwareLoading}
              onClick={() => void loadVmware()}
            >
              {vmwareLoading ? "Looking up…" : "Add VMware names"}
            </button>
          </div>
          {vmwareError && <p role="alert">{vmwareError}</p>}
          {vmware && (
            <p role="note">
              VMware names are inferred context: the primary guest IP vCenter
              last reported for each VM in the 30 days before the window end,
              matched by address without a routing scope. {vmware.labels.length}{" "}
              matched
              {vmware.capped ? "; the lookup reached its row cap" : ""}. A
              missing name does not mean the host is not a VM.
            </p>
          )}
          {plan.notes.map((note, i) => (
            <p role="note" key={i}>
              {note}
            </p>
          ))}
          <p>
            {plan.groups.length} move groups, {plan.totals.shared} shared
            services, <strong>{plan.totals.blockers}</strong> wave-blocking
            conversations, {plan.totals.outsidePlan} conversations to hosts
            outside every group.
            {plan.fanInThreshold !== undefined &&
              ` Highly connected threshold: ${plan.fanInThreshold} distinct peers.`}
          </p>
          <h3>Wave blockers</h3>
          {plan.blockerPairs.length ? (
            <ul className="migration-pairs">
              {plan.blockerPairs.map((pair) => (
                <li key={pair.groups.join(":")}>
                  <strong>
                    {groupLabel(pair.groups[0])} ↔ {groupLabel(pair.groups[1])}
                  </strong>
                  : {pair.conversations} conversations,{" "}
                  {pair.records.toLocaleString()} flow records on{" "}
                  {pair.services.join(", ")}
                  {pair.servicesCapped ? " and more" : ""}. Move these groups in
                  the same wave or keep the path open between waves.
                </li>
              ))}
            </ul>
          ) : (
            <p>
              No cross-group conversations were observed in this window. This is
              not proof that the groups are independent.
            </p>
          )}
          <EdgeTable
            caption="Wave-blocking conversations"
            edges={plan.blockers}
            total={plan.totals.blockers}
            groupLabel={groupLabel}
          />
          {plan.groups.map((group) => (
            <section
              key={group.id}
              aria-label={`Group ${group.label}`}
              className="migration-group"
            >
              <h3>
                {group.label}{" "}
                <span className="migration-muted">
                  ({group.members.length} hosts
                  {group.sizeCapped ? ", size limit reached" : ""})
                </span>
              </h3>
              {!group.members.length ? (
                <p>No hosts. Its seeds were dropped or moved.</p>
              ) : (
                <div
                  className="endpoint-table-scroll"
                  role="region"
                  aria-label={`${group.label} members table`}
                  tabIndex={0}
                >
                  <table>
                    <thead>
                      <tr>
                        <th>Host</th>
                        <th>Membership</th>
                        <th>Depth / via</th>
                        <th>Distinct peers</th>
                        <th>Expansion</th>
                        <th>Shared-rule match</th>
                        <th>Actions</th>
                      </tr>
                    </thead>
                    <tbody>
                      {group.members.map((m) => (
                        <tr key={m.address}>
                          <td>
                            {m.address}
                            {vmName(m.address) && (
                              <span className="migration-muted">
                                {" "}
                                {vmName(m.address)}
                              </span>
                            )}
                          </td>
                          <td>{BASIS[m.basis]}</td>
                          <td>
                            {m.depth ?? "—"}
                            {m.via ? ` via ${m.via}` : ""}
                          </td>
                          <td>{m.peers}</td>
                          <td>{EXPANSION[m.expansion]}</td>
                          <td>
                            {m.sharedMatch.map(describeReason).join("; ") ||
                              "—"}
                          </td>
                          <td>
                            <select
                              aria-label={`Move ${m.address}`}
                              value={group.id}
                              onChange={(e) =>
                                assign(
                                  m.address,
                                  e.target.value,
                                  traversalGroups.get(m.address),
                                )
                              }
                            >
                              {moveOptions.map(([id, label]) => (
                                <option key={id} value={id}>
                                  {label}
                                </option>
                              ))}
                            </select>{" "}
                            <button
                              type="button"
                              onClick={() => pin(m.address)}
                            >
                              Mark shared
                            </button>
                          </td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
              )}
            </section>
          ))}
          <h3>Shared services</h3>
          {plan.truncated.shared && (
            <p role="status">
              Showing {plan.shared.length} of {plan.totals.shared} shared
              services.
            </p>
          )}
          {plan.shared.length ? (
            <div
              className="endpoint-table-scroll"
              role="region"
              aria-label="Shared services table"
              tabIndex={0}
            >
              <table>
                <thead>
                  <tr>
                    <th>Host</th>
                    <th>Why shared</th>
                    <th>Basis</th>
                    <th>Distinct peers</th>
                    <th>Used by groups</th>
                    <th>Actions</th>
                  </tr>
                </thead>
                <tbody>
                  {plan.shared.map((s) => (
                    <tr key={s.address}>
                      <td>
                        {s.address}
                        {vmName(s.address) && (
                          <span className="migration-muted">
                            {" "}
                            {vmName(s.address)}
                          </span>
                        )}
                      </td>
                      <td>{s.reasons.map(describeReason).join("; ")}</td>
                      <td>
                        {s.basis === "user"
                          ? "Pinned by you"
                          : "Inferred from observed conversations"}
                      </td>
                      <td>{s.peers}</td>
                      <td>
                        {s.dependentGroups.map(groupLabel).join(", ") || "—"}
                      </td>
                      <td>
                        <button
                          type="button"
                          onClick={() => unshare(s.address)}
                        >
                          {s.basis === "user" ? "Unpin" : "Not shared"}
                        </button>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          ) : (
            <p>No shared services matched the current rules.</p>
          )}
          {overrides.notShared.length > 0 && (
            <p>
              Treated as not shared: {overrides.notShared.join(", ")}.{" "}
              <button
                type="button"
                onClick={() => setOverrides((o) => ({ ...o, notShared: [] }))}
              >
                Restore detection
              </button>
            </p>
          )}
          <EdgeTable
            caption="Conversations with shared services"
            edges={plan.sharedDependencies}
            total={plan.totals.sharedDependencies}
            groupLabel={groupLabel}
          />
          <h3>Hosts outside every group</h3>
          {plan.unplanned.length ? (
            <>
              {plan.truncated.unplanned && (
                <p role="status">
                  Showing {plan.unplanned.length} of {plan.totals.unplanned}{" "}
                  hosts.
                </p>
              )}
              <ul className="migration-unplanned">
                {plan.unplanned.slice(0, DISPLAY_ROWS).map((u) => (
                  <li key={u.address}>
                    {u.address} ({u.peers} peers; talks to{" "}
                    {u.adjacentGroups.map(groupLabel).join(", ")}){" "}
                    <select
                      aria-label={`Add ${u.address} to a group`}
                      value=""
                      onChange={(e) =>
                        e.target.value && assign(u.address, e.target.value)
                      }
                    >
                      <option value="">Add to group…</option>
                      {plan.groups.map((g) => (
                        <option key={g.id} value={g.id}>
                          {g.label}
                        </option>
                      ))}
                    </select>{" "}
                    <button type="button" onClick={() => pin(u.address)}>
                      Mark shared
                    </button>
                  </li>
                ))}
              </ul>
            </>
          ) : (
            <p>Every observed peer of the groups is in a group or shared.</p>
          )}
          <details>
            <summary>
              Conversations to hosts outside every group (
              {plan.totals.outsidePlan})
            </summary>
            <EdgeTable
              caption="Conversations outside the plan"
              edges={plan.outsidePlan}
              total={plan.totals.outsidePlan}
              groupLabel={groupLabel}
            />
          </details>
          {(overrides.pinnedShared.length > 0 ||
            Object.keys(overrides.assignments).length > 0) && (
            <button type="button" onClick={() => setOverrides(EMPTY_OVERRIDES)}>
              Clear all manual changes
            </button>
          )}
        </section>
      )}
    </section>
  );
}
