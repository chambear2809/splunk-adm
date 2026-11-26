import type { Graph, GraphEdge, GraphNode } from "../graph";

/**
 * Segmentation rule model, coverage and replay over observed conversations.
 * Every selector match is three-valued: an endpoint that Atlas cannot place
 * from collected evidence is "unknown", never silently inside or outside.
 * Nothing here applies, enforces or transmits policy.
 */
export const RULESET_SCHEMA = "atlas.segmentation.ruleset/v1" as const;
export const MAX_RULES = 200;
export const TOP_BLOCKED_LIMIT = 25;
export const MAX_REPLAY_WINDOW_SECONDS = 7 * 24 * 3600;
export const MIN_REPLAY_WINDOW_SECONDS = 60;
export const PROTOCOLS = ["tcp", "udp", "sctp"] as const;
export type Protocol = (typeof PROTOCOLS)[number];
export type RuleAction = "allow" | "deny";

export type Selector =
  | { kind: "application"; service: string; environment: string }
  | { kind: "endpoint"; nodeId: string }
  | { kind: "epg"; tenant: string; appProfile: string; epg: string }
  | { kind: "esg"; tenant: string; esg: string }
  | { kind: "k8s"; cluster: string; namespace: string; workload?: string }
  | { kind: "cidr"; cidr: string };
export type SelectorKind = Selector["kind"];
export interface PortRange {
  from: number;
  to: number;
}
export interface Rule {
  id: string;
  action: RuleAction;
  source: Selector;
  destination: Selector;
  protocol: Protocol;
  ports: PortRange;
}
export interface RuleSet {
  schema: typeof RULESET_SCHEMA;
  rules: Rule[];
}
export type ParseResult =
  { ok: true; ruleSet: RuleSet } | { ok: false; errors: string[] };

const K8S_LABEL = /^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$/;
const K8S_NAME =
  /^(?=.{1,253}$)[a-z0-9](?:[a-z0-9-]*[a-z0-9])?(?:\.[a-z0-9](?:[a-z0-9-]*[a-z0-9])?)*$/;
/** APIC object names: letters, digits, `_ . : -`, at most 64 characters. */
const ACI_NAME = /^[A-Za-z0-9_.:-]{1,64}$/;
const RULE_ID = /^[A-Za-z0-9_.-]{1,64}$/;
// eslint-disable-next-line no-control-regex
const CONTROL = /[\u0000-\u001f\u007f]/;

const object = (v: unknown): v is Record<string, unknown> =>
  !!v && typeof v === "object" && !Array.isArray(v);
const text = (v: unknown, max = 256): v is string =>
  typeof v === "string" &&
  v.length > 0 &&
  v.length <= max &&
  v.trim() === v &&
  !CONTROL.test(v);

function ipv4(value: string): number | undefined {
  const m = /^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/.exec(value);
  if (!m) return undefined;
  let n = 0;
  for (const part of m.slice(1)) {
    if (part.length > 1 && part.startsWith("0")) return undefined;
    const octet = Number(part);
    if (octet > 255) return undefined;
    n = n * 256 + octet;
  }
  return n;
}

export interface Cidr {
  network: number;
  prefix: number;
}
/** Strict IPv4 CIDR; host bits must be zero so the intended range is unambiguous. */
export function parseCidr(value: string): Cidr | string {
  const [address, length, extra] = value.split("/");
  if (extra !== undefined || length === undefined || !/^\d{1,2}$/.test(length))
    return value.includes(":")
      ? "IPv6 CIDR selectors are not supported."
      : "CIDR must be an IPv4 network such as 10.20.0.0/16.";
  if (address?.includes(":")) return "IPv6 CIDR selectors are not supported.";
  const network = ipv4(address ?? "");
  const prefix = Number(length);
  if (network === undefined || prefix > 32)
    return "CIDR must be an IPv4 network such as 10.20.0.0/16.";
  const size = 2 ** (32 - prefix);
  if (network % size !== 0)
    return `CIDR ${value} has host bits set; use the network address.`;
  return { network, prefix };
}
const inCidr = (address: number, cidr: Cidr) => {
  const size = 2 ** (32 - cidr.prefix);
  return address >= cidr.network && address < cidr.network + size;
};

function parseSelector(value: unknown, where: string): Selector | string {
  if (!object(value)) return `${where} must be an object.`;
  const allowed: Record<SelectorKind, string[]> = {
    application: ["kind", "service", "environment"],
    endpoint: ["kind", "nodeId"],
    epg: ["kind", "tenant", "appProfile", "epg"],
    esg: ["kind", "tenant", "esg"],
    k8s: ["kind", "cluster", "namespace", "workload"],
    cidr: ["kind", "cidr"],
  };
  const kind = value.kind as SelectorKind;
  if (typeof value.kind !== "string" || !(kind in allowed))
    return `${where}.kind must be one of ${Object.keys(allowed).join(", ")}.`;
  const unknownKey = Object.keys(value).find(
    (key) => !allowed[kind].includes(key),
  );
  if (unknownKey)
    return kind === "k8s" && unknownKey === "labels"
      ? `${where}: Kubernetes pod labels are not collected by Atlas, so label selectors cannot be resolved. Use namespace and workload (controller name).`
      : `${where} has unsupported field ${JSON.stringify(unknownKey)}.`;
  switch (kind) {
    case "application":
      if (!text(value.service) || !text(value.environment))
        return `${where} needs an application service and environment.`;
      return {
        kind,
        service: value.service,
        environment: value.environment,
      };
    case "endpoint":
      if (!text(value.nodeId, 4096))
        return `${where}.nodeId must be an Atlas endpoint identifier.`;
      return { kind, nodeId: value.nodeId };
    case "epg":
      if (
        typeof value.tenant !== "string" ||
        typeof value.appProfile !== "string" ||
        typeof value.epg !== "string" ||
        ![value.tenant, value.appProfile, value.epg].every((v) =>
          ACI_NAME.test(v),
        )
      )
        return `${where} needs tenant, appProfile and epg as APIC names.`;
      return {
        kind,
        tenant: value.tenant,
        appProfile: value.appProfile,
        epg: value.epg,
      };
    case "esg":
      if (
        typeof value.tenant !== "string" ||
        typeof value.esg !== "string" ||
        !ACI_NAME.test(value.tenant) ||
        !ACI_NAME.test(value.esg)
      )
        return `${where} needs tenant and esg as APIC names.`;
      return { kind, tenant: value.tenant, esg: value.esg };
    case "k8s": {
      if (!text(value.cluster))
        return `${where}.cluster must name the Kubernetes cluster.`;
      if (
        typeof value.namespace !== "string" ||
        !K8S_LABEL.test(value.namespace)
      )
        return `${where}.namespace must be a valid Kubernetes namespace.`;
      if (
        value.workload !== undefined &&
        (typeof value.workload !== "string" || !K8S_NAME.test(value.workload))
      )
        return `${where}.workload must be a Kubernetes controller name.`;
      return {
        kind,
        cluster: value.cluster,
        namespace: value.namespace,
        ...(value.workload !== undefined
          ? { workload: value.workload as string }
          : {}),
      };
    }
    case "cidr": {
      if (typeof value.cidr !== "string") return `${where}.cidr is required.`;
      const parsed = parseCidr(value.cidr);
      if (typeof parsed === "string") return `${where}: ${parsed}`;
      return { kind, cidr: value.cidr };
    }
  }
}

const RULE_KEYS = [
  "id",
  "action",
  "source",
  "destination",
  "protocol",
  "ports",
];
/** Strict rule-set parser: any unknown, missing or malformed field rejects the set. */
export function parseRuleSet(value: unknown): ParseResult {
  const errors: string[] = [];
  if (!object(value))
    return { ok: false, errors: ["Rule set must be an object."] };
  if (value.schema !== RULESET_SCHEMA)
    errors.push(`schema must be ${JSON.stringify(RULESET_SCHEMA)}.`);
  const extra = Object.keys(value).find((k) => k !== "schema" && k !== "rules");
  if (extra)
    errors.push(`Unsupported rule-set field ${JSON.stringify(extra)}.`);
  if (!Array.isArray(value.rules)) {
    errors.push("rules must be an array.");
    return { ok: false, errors };
  }
  if (value.rules.length > MAX_RULES)
    errors.push(`At most ${MAX_RULES} rules are supported.`);
  const rules: Rule[] = [];
  const ids = new Set<string>();
  value.rules.slice(0, MAX_RULES).forEach((raw, index) => {
    const where = `Rule ${index + 1}`;
    if (!object(raw)) {
      errors.push(`${where} must be an object.`);
      return;
    }
    const unknownKey = Object.keys(raw).find((k) => !RULE_KEYS.includes(k));
    if (unknownKey) {
      errors.push(
        `${where} has unsupported field ${JSON.stringify(unknownKey)}.`,
      );
      return;
    }
    const before = errors.length;
    if (typeof raw.id !== "string" || !RULE_ID.test(raw.id))
      errors.push(`${where}.id must use letters, digits, ".", "_" or "-".`);
    else if (ids.has(raw.id))
      errors.push(`${where}.id ${raw.id} is duplicated.`);
    if (raw.action !== "allow" && raw.action !== "deny")
      errors.push(`${where}.action must be "allow" or "deny".`);
    if (!PROTOCOLS.includes(raw.protocol as Protocol))
      errors.push(`${where}.protocol must be tcp, udp or sctp.`);
    const ports = raw.ports;
    const port = (v: unknown) =>
      Number.isInteger(v) && (v as number) >= 1 && (v as number) <= 65535;
    if (
      !object(ports) ||
      Object.keys(ports).some((k) => k !== "from" && k !== "to") ||
      !port(ports.from) ||
      !port(ports.to) ||
      (ports.from as number) > (ports.to as number)
    )
      errors.push(
        `${where}.ports needs integer from/to between 1 and 65535 with from ≤ to.`,
      );
    const source = parseSelector(raw.source, `${where}.source`);
    const destination = parseSelector(raw.destination, `${where}.destination`);
    if (typeof source === "string") errors.push(source);
    if (typeof destination === "string") errors.push(destination);
    if (errors.length > before) return;
    ids.add(raw.id as string);
    rules.push({
      id: raw.id as string,
      action: raw.action as RuleAction,
      source: source as Selector,
      destination: destination as Selector,
      protocol: raw.protocol as Protocol,
      ports: {
        from: (ports as Record<string, number>).from,
        to: (ports as Record<string, number>).to,
      },
    });
  });
  return errors.length
    ? { ok: false, errors }
    : { ok: true, ruleSet: { schema: RULESET_SCHEMA, rules } };
}

export function parseRuleSetText(source: string): ParseResult {
  if (source.length > 512 * 1024)
    return { ok: false, errors: ["Rule set text exceeds 512 KiB."] };
  let value: unknown;
  try {
    value = JSON.parse(source);
  } catch {
    return { ok: false, errors: ["Rule set is not valid JSON."] };
  }
  return parseRuleSet(value);
}

export const serializeRuleSet = (ruleSet: RuleSet) =>
  JSON.stringify(ruleSet, null, 2);

export function describeSelector(selector: Selector): string {
  switch (selector.kind) {
    case "application":
      return `Application ${selector.service} (${selector.environment})`;
    case "endpoint":
      return `Endpoint ${selector.nodeId}`;
    case "epg":
      return `EPG ${selector.tenant}/${selector.appProfile}/${selector.epg}`;
    case "esg":
      return `ESG ${selector.tenant}/${selector.esg}`;
    case "k8s":
      return `Kubernetes ${selector.namespace}/${selector.workload ?? "*"} (${selector.cluster})`;
    case "cidr":
      return `CIDR ${selector.cidr}`;
  }
}
export const portText = (ports: PortRange) =>
  ports.from === ports.to ? String(ports.from) : `${ports.from}-${ports.to}`;

export type Match =
  | { state: "match" }
  | { state: "no_match" }
  | { state: "unknown"; reason: string };
const MATCH: Match = { state: "match" };
const NO_MATCH: Match = { state: "no_match" };
const unknown = (reason: string): Match => ({ state: "unknown", reason });

export interface EvaluationContext {
  nodes: Map<string, GraphNode>;
  /** Workload id → OpenTelemetry service nodes linked by runs_on. */
  applications: Map<string, GraphNode[]>;
  cidrs: Map<string, Cidr | string>;
}
export function evaluationContext(
  graph: Pick<Graph, "nodes" | "edges">,
): EvaluationContext {
  const nodes = new Map(graph.nodes.map((node) => [node.id, node]));
  const applications = new Map<string, GraphNode[]>();
  for (const edge of graph.edges) {
    if (edge.relationship !== "runs_on") continue;
    const service = nodes.get(edge.source);
    if (!service) continue;
    const list = applications.get(edge.target) ?? [];
    list.push(service);
    applications.set(edge.target, list);
  }
  return { nodes, applications, cidrs: new Map() };
}

const identityUnresolved = (node: GraphNode) =>
  node.endpoint_kind === "unresolved" || node.endpoint_kind === "ambiguous";

export function matchSelector(
  selector: Selector,
  node: GraphNode | undefined,
  context: EvaluationContext,
): Match {
  if (!node) return unknown("The endpoint is missing from the map.");
  switch (selector.kind) {
    case "endpoint":
      return node.id === selector.nodeId ? MATCH : NO_MATCH;
    case "esg":
      return unknown(
        "Atlas does not evaluate ACI ESG membership (fvESg is collected at most as configuration, not membership).",
      );
    case "application": {
      if (node.kind !== "workload")
        return node.kind === "client" ||
          ["external", "k8s_node", "k8s_node_proxy"].includes(
            node.endpoint_kind ?? "",
          )
          ? NO_MATCH
          : unknown("Application membership of this endpoint is not resolved.");
      const services = context.applications.get(node.id);
      if (!services?.length)
        return unknown(
          "No application (OpenTelemetry service) is linked to this workload in the window.",
        );
      return services.some(
        (service) =>
          service.label === selector.service &&
          service.attributes?.environment === selector.environment,
      )
        ? MATCH
        : NO_MATCH;
    }
    case "k8s": {
      if (node.kind === "workload") {
        if (
          node.cluster !== selector.cluster ||
          node.namespace !== selector.namespace
        )
          return NO_MATCH;
        if (!selector.workload) return MATCH;
        const owner = node.attributes?.owner;
        if (!owner)
          return unknown("The pod's workload controller is not recorded.");
        return owner === selector.workload ? MATCH : NO_MATCH;
      }
      if (node.endpoint_kind === "k8s_service")
        return node.cluster === selector.cluster &&
          node.namespace === selector.namespace
          ? unknown(
              "Kubernetes Service frontend: pod policy applies to the backend pods after translation.",
            )
          : NO_MATCH;
      return identityUnresolved(node)
        ? unknown("Endpoint identity is unresolved.")
        : NO_MATCH;
    }
    case "epg": {
      const a = node.attributes ?? {};
      if (a.tenant && a.app_profile && a.epg)
        return a.tenant === selector.tenant &&
          a.app_profile === selector.appProfile &&
          a.epg === selector.epg
          ? MATCH
          : NO_MATCH;
      return unknown(
        a.tenant || a.app_profile || a.epg
          ? "The endpoint's EPG classification is incomplete."
          : "No collected ACI endpoint (fvCEp) EPG classification for this endpoint.",
      );
    }
    case "cidr": {
      let cidr = context.cidrs.get(selector.cidr);
      if (cidr === undefined) {
        cidr = parseCidr(selector.cidr);
        context.cidrs.set(selector.cidr, cidr);
      }
      if (typeof cidr === "string") return unknown(cidr);
      const addresses = node.addresses ?? [];
      if (!addresses.length)
        return unknown("No address is recorded for this endpoint.");
      let inside = 0;
      for (const address of addresses) {
        const n = ipv4(address);
        if (n === undefined && !address.includes(":"))
          return unknown(`Address ${address} could not be parsed.`);
        if (n !== undefined && inCidr(n, cidr)) inside++;
      }
      if (inside === addresses.length) return MATCH;
      if (inside === 0) return NO_MATCH;
      return unknown(
        "The endpoint has addresses both inside and outside the CIDR.",
      );
    }
  }
}

export interface L4 {
  protocol: Protocol;
  port: number;
}
export function conversationL4(edge: GraphEdge): L4 | undefined {
  const port = edge.server_port;
  const protocol = edge.transport?.trim().toLowerCase() as Protocol;
  if (
    typeof port !== "number" ||
    !Number.isInteger(port) ||
    port < 1 ||
    port > 65535 ||
    !PROTOCOLS.includes(protocol)
  )
    return undefined;
  return { protocol, port };
}

export function conversations(graph: Pick<Graph, "edges">): GraphEdge[] {
  return graph.edges.filter(
    (edge) => edge.relationship === "communicates_with",
  );
}

export function matchRule(
  rule: Rule,
  edge: GraphEdge,
  context: EvaluationContext,
): Match {
  const l4 = conversationL4(edge);
  if (!l4) return unknown("No valid server port and TCP/UDP/SCTP transport.");
  if (
    rule.protocol !== l4.protocol ||
    l4.port < rule.ports.from ||
    l4.port > rule.ports.to
  )
    return NO_MATCH;
  const source = matchSelector(
    rule.source,
    context.nodes.get(edge.source),
    context,
  );
  if (source.state === "no_match") return NO_MATCH;
  const destination = matchSelector(
    rule.destination,
    context.nodes.get(edge.target),
    context,
  );
  if (destination.state === "no_match") return NO_MATCH;
  if (edge.direction_basis === "unknown")
    return unknown("Client and server direction is not established.");
  if (source.state === "unknown") return unknown(`Source: ${source.reason}`);
  if (destination.state === "unknown")
    return unknown(`Destination: ${destination.reason}`);
  return MATCH;
}

export type Verdict =
  | { outcome: "allowed"; rule: string }
  | { outcome: "blocked"; basis: "deny_rule"; rule: string }
  | { outcome: "blocked"; basis: "default_deny" }
  | { outcome: "unknown"; reason: string; rule?: string };

/**
 * Deny takes precedence over allow, and anything no allow rule matches is
 * blocked by default deny. A rule that might match keeps the verdict unknown.
 */
export function evaluateConversation(
  ruleSet: RuleSet,
  edge: GraphEdge,
  context: EvaluationContext,
): Verdict {
  if (!conversationL4(edge))
    return {
      outcome: "unknown",
      reason: "No valid server port and TCP/UDP/SCTP transport.",
    };
  const results = ruleSet.rules.map((rule) => ({
    rule,
    match: matchRule(rule, edge, context),
  }));
  const first = (action: RuleAction, state: Match["state"]) =>
    results.find((r) => r.rule.action === action && r.match.state === state);
  const deny = first("deny", "match");
  if (deny)
    return { outcome: "blocked", basis: "deny_rule", rule: deny.rule.id };
  const maybeDeny = first("deny", "unknown");
  if (maybeDeny)
    return {
      outcome: "unknown",
      rule: maybeDeny.rule.id,
      reason: `Deny rule ${maybeDeny.rule.id} may apply. ${(maybeDeny.match as { reason: string }).reason}`,
    };
  const allow = first("allow", "match");
  if (allow) return { outcome: "allowed", rule: allow.rule.id };
  const maybeAllow = first("allow", "unknown");
  if (maybeAllow)
    return {
      outcome: "unknown",
      rule: maybeAllow.rule.id,
      reason: `Allow rule ${maybeAllow.rule.id} may apply. ${(maybeAllow.match as { reason: string }).reason}`,
    };
  return { outcome: "blocked", basis: "default_deny" };
}

export interface Completeness {
  complete: boolean;
  notes: string[];
}
const CAP_WARNING = /capped|listed only the first|limit|truncat|exceed/i;
/** Any truncation, partial read or cap makes counts lower bounds, never complete. */
export function graphCompleteness(graph: Graph): Completeness {
  const notes: string[] = [];
  let complete = true;
  if (graph.demo) notes.push("Synthetic demo data, not observed traffic.");
  if (graph.truncation) {
    complete = false;
    notes.push(
      `The map read is truncated: ${graph.truncation.shown.edges.toLocaleString("en-US")} of ${graph.truncation.total.edges.toLocaleString("en-US")} relationships are included (ranked by ${graph.truncation.ranking}).`,
    );
  }
  if (graph.read) {
    if (graph.read.pendingSeconds) {
      complete = false;
      notes.push("The newest minutes of the window are still loading.");
    }
    if (graph.read.coverage < 100) {
      complete = false;
      notes.push(
        `Only ${graph.read.coverage}% of the window was read; counts describe the slices read.`,
      );
    }
  }
  const capped = graph.coverage.warnings.filter((w) => CAP_WARNING.test(w));
  if (capped.length) {
    complete = false;
    notes.push(...capped.map((w) => `Search reported: ${w}`));
  }
  if (
    graph.coverage.unresolved_conversations ||
    graph.coverage.ambiguous_conversations
  )
    notes.push(
      `${graph.coverage.unresolved_conversations} unresolved and ${graph.coverage.ambiguous_conversations} ambiguous conversation identities limit selector matching.`,
    );
  return { complete, notes };
}

export type CoverageState = "covered" | "not_covered" | "unknown";
export interface ConversationCoverage {
  edge: GraphEdge;
  state: CoverageState;
  basis: string;
  aclDrop: boolean;
  /** Atlas does not collect Cilium policy rules; pod conversations stay unknown on that side. */
  ciliumPolicy: "not_collected" | "not_applicable";
  conflict?: string;
}
export interface Tally {
  conversations: number;
  connections: number;
}
const tally = (): Tally => ({ conversations: 0, connections: 0 });
const add = (t: Tally, edge: GraphEdge) => {
  t.conversations++;
  t.connections += edge.count;
};

export function conversationCoverage(
  edge: GraphEdge,
  context: EvaluationContext,
): ConversationCoverage {
  const aclDrop = edge.acl_action === "drop";
  const touchesPod = [edge.source, edge.target].some(
    (id) => context.nodes.get(id)?.kind === "workload",
  );
  const ciliumPolicy = touchesPod ? "not_collected" : "not_applicable";
  const entry = edge.contract_entry ? ` (${edge.contract_entry})` : "";
  switch (edge.contract_basis) {
    case "intent":
      return {
        edge,
        state: "covered",
        basis: `Collected ACI contract ${edge.contract ?? "?"}${entry} permits it (configured intent).`,
        aclDrop,
        ciliumPolicy,
        ...(aclDrop
          ? {
              conflict:
                "An ACL drop was logged although the collected contract permits this conversation.",
            }
          : {}),
      };
    case "intra_epg":
      return {
        edge,
        state: "covered",
        basis:
          "Both sides are in one EPG without collected intra-EPG isolation.",
        aclDrop,
        ciliumPolicy,
      };
    case "none":
      return {
        edge,
        state: "not_covered",
        basis:
          "Collected ACI policy has no permit for it (complete policy or logged drop).",
        aclDrop,
        ciliumPolicy,
      };
    case "not_evaluated":
      return {
        edge,
        state: "unknown",
        basis: `ACI policy not evaluated${edge.contract_reason ? `: ${edge.contract_reason}` : "."}`,
        aclDrop,
        ciliumPolicy,
      };
    default:
      return {
        edge,
        state: "unknown",
        basis: touchesPod
          ? "No collected policy evidence: no ACI contract annotation, and Atlas does not collect Cilium policy rules."
          : "No collected ACI policy evidence for this conversation.",
        aclDrop,
        ciliumPolicy,
      };
  }
}

export interface CoverageSummary {
  covered: Tally;
  notCovered: Tally;
  unknown: Tally;
  aclDrops: number;
  conflicts: number;
  ciliumNotCollected: number;
  items: ConversationCoverage[];
  completeness: Completeness;
}
export function coverageSummary(graph: Graph): CoverageSummary {
  const context = evaluationContext(graph);
  const summary: CoverageSummary = {
    covered: tally(),
    notCovered: tally(),
    unknown: tally(),
    aclDrops: 0,
    conflicts: 0,
    ciliumNotCollected: 0,
    items: [],
    completeness: graphCompleteness(graph),
  };
  for (const edge of conversations(graph)) {
    const item = conversationCoverage(edge, context);
    summary.items.push(item);
    add(
      item.state === "covered"
        ? summary.covered
        : item.state === "not_covered"
          ? summary.notCovered
          : summary.unknown,
      edge,
    );
    if (item.aclDrop) summary.aclDrops++;
    if (item.conflict) summary.conflicts++;
    if (item.ciliumPolicy === "not_collected") summary.ciliumNotCollected++;
  }
  return summary;
}

export interface EndpointRef {
  id: string;
  label: string;
  address?: string;
  scope?: string;
}
export interface BlockedConversation {
  edgeId: string;
  source: EndpointRef;
  target: EndpointRef;
  protocol: Protocol;
  port: number;
  connections: number;
  bytes?: number;
  basis: "deny_rule" | "default_deny";
  rule?: string;
  evidence: string[];
  observers: string[];
}
export interface ReplayResult {
  window: { start: string; end: string };
  allowed: Tally;
  blocked: Tally;
  unknown: Tally;
  topBlocked: BlockedConversation[];
  blockedTruncated: boolean;
  unknownReasons: { reason: string; conversations: number }[];
  ruleHits: { rule: string; conversations: number; connections: number }[];
  unusedRules: string[];
  completeness: Completeness;
}

function endpointRef(node: GraphNode | undefined, id: string): EndpointRef {
  const address =
    node?.addresses?.find((a) => ipv4(a) !== undefined) ?? node?.addresses?.[0];
  return {
    id,
    label: node?.label ?? id,
    ...(address ? { address } : {}),
    ...(node?.attributes?.scope ? { scope: node.attributes.scope } : {}),
  };
}

export function replay(graph: Graph, ruleSet: RuleSet): ReplayResult {
  const context = evaluationContext(graph);
  const allowed = tally(),
    blocked = tally(),
    unknownTally = tally();
  const blockedItems: BlockedConversation[] = [];
  const reasons = new Map<string, number>();
  const hits = new Map<string, Tally>(
    ruleSet.rules.map((rule) => [rule.id, tally()]),
  );
  for (const edge of conversations(graph)) {
    const verdict = evaluateConversation(ruleSet, edge, context);
    if (verdict.outcome === "allowed") {
      add(allowed, edge);
      add(hits.get(verdict.rule)!, edge);
    } else if (verdict.outcome === "unknown") {
      add(unknownTally, edge);
      const reason = verdict.reason.replace(
        /^(Allow|Deny) rule \S+ may apply\. /,
        "",
      );
      reasons.set(reason, (reasons.get(reason) ?? 0) + 1);
    } else {
      add(blocked, edge);
      if (verdict.basis === "deny_rule") add(hits.get(verdict.rule)!, edge);
      const l4 = conversationL4(edge)!;
      blockedItems.push({
        edgeId: edge.id,
        source: endpointRef(context.nodes.get(edge.source), edge.source),
        target: endpointRef(context.nodes.get(edge.target), edge.target),
        protocol: l4.protocol,
        port: l4.port,
        connections: edge.count,
        ...(edge.bytes !== undefined ? { bytes: edge.bytes } : {}),
        basis: verdict.basis,
        ...(verdict.basis === "deny_rule" ? { rule: verdict.rule } : {}),
        evidence: edge.evidence,
        observers: edge.observers ?? [],
      });
    }
  }
  blockedItems.sort(
    (a, b) =>
      b.connections - a.connections ||
      (b.bytes ?? 0) - (a.bytes ?? 0) ||
      a.edgeId.localeCompare(b.edgeId),
  );
  const ruleHits = ruleSet.rules.map((rule) => ({
    rule: rule.id,
    ...hits.get(rule.id)!,
  }));
  return {
    window: graph.window,
    allowed,
    blocked,
    unknown: unknownTally,
    topBlocked: blockedItems.slice(0, TOP_BLOCKED_LIMIT),
    blockedTruncated: blockedItems.length > TOP_BLOCKED_LIMIT,
    unknownReasons: [...reasons.entries()]
      .map(([reason, count]) => ({ reason, conversations: count }))
      .sort(
        (a, b) =>
          b.conversations - a.conversations || a.reason.localeCompare(b.reason),
      )
      .slice(0, 8),
    ruleHits,
    unusedRules: ruleHits
      .filter((h) => h.conversations === 0)
      .map((h) => h.rule),
    completeness: graphCompleteness(graph),
  };
}

export interface SeedResult {
  ruleSet: RuleSet;
  skipped: { reason: string; conversations: number }[];
  truncated: boolean;
}

/** Most specific selector Atlas can resolve for an observed endpoint, if any. */
export function observedSelector(
  node: GraphNode | undefined,
): Selector | string {
  if (!node) return "Endpoint missing from the map.";
  if (identityUnresolved(node))
    return "Endpoint identity is unresolved or ambiguous.";
  if (node.kind === "workload") {
    if (
      !node.cluster ||
      !text(node.cluster) ||
      !node.namespace ||
      !K8S_LABEL.test(node.namespace)
    )
      return "Pod without a valid cluster and namespace.";
    const owner = node.attributes?.owner;
    return {
      kind: "k8s",
      cluster: node.cluster,
      namespace: node.namespace,
      ...(owner && K8S_NAME.test(owner) ? { workload: owner } : {}),
    };
  }
  const a = node.attributes ?? {};
  if (
    a.tenant &&
    a.app_profile &&
    a.epg &&
    [a.tenant, a.app_profile, a.epg].every((v) => ACI_NAME.test(v))
  )
    return {
      kind: "epg",
      tenant: a.tenant,
      appProfile: a.app_profile,
      epg: a.epg,
    };
  const v4 = (node.addresses ?? []).filter((x) => ipv4(x) !== undefined);
  if (v4.length === 1 && (node.addresses ?? []).length === 1)
    return { kind: "cidr", cidr: `${v4[0]}/32` };
  return "No single IPv4 address or collected EPG for this endpoint.";
}

/** Exact allow rules for each observed L4 conversation; never widens ports or peers. */
export function seedRuleSet(graph: Pick<Graph, "nodes" | "edges">): SeedResult {
  const context = evaluationContext(graph);
  const skipped = new Map<string, number>();
  const skip = (reason: string) =>
    skipped.set(reason, (skipped.get(reason) ?? 0) + 1);
  const rules = new Map<string, Rule>();
  let truncated = false;
  const ordered = [...conversations(graph)].sort(
    (a, b) => b.count - a.count || a.id.localeCompare(b.id),
  );
  for (const edge of ordered) {
    const l4 = conversationL4(edge);
    if (!l4) {
      skip("No valid server port and TCP/UDP/SCTP transport.");
      continue;
    }
    if (edge.acl_action === "drop") {
      skip("ACL drop observed; not seeded as an allow rule.");
      continue;
    }
    if (edge.direction_basis === "unknown") {
      skip("Client and server direction is not established.");
      continue;
    }
    const source = observedSelector(context.nodes.get(edge.source));
    const destination = observedSelector(context.nodes.get(edge.target));
    if (typeof source === "string") {
      skip(`Source: ${source}`);
      continue;
    }
    if (typeof destination === "string") {
      skip(`Destination: ${destination}`);
      continue;
    }
    const key = JSON.stringify([source, destination, l4.protocol, l4.port]);
    if (rules.has(key)) continue;
    if (rules.size >= MAX_RULES) {
      truncated = true;
      skip(`Rule limit of ${MAX_RULES} reached.`);
      continue;
    }
    rules.set(key, {
      id: `observed-${String(rules.size + 1).padStart(3, "0")}`,
      action: "allow",
      source,
      destination,
      protocol: l4.protocol,
      ports: { from: l4.port, to: l4.port },
    });
  }
  return {
    ruleSet: { schema: RULESET_SCHEMA, rules: [...rules.values()] },
    skipped: [...skipped.entries()]
      .map(([reason, count]) => ({ reason, conversations: count }))
      .sort((a, b) => b.conversations - a.conversations),
    truncated,
  };
}

/** Validates an absolute replay window; returns an error message or undefined. */
export function replayWindowError(
  start: string,
  end: string,
): string | undefined {
  const s = Date.parse(start);
  const e = Date.parse(end);
  if (!Number.isFinite(s) || !Number.isFinite(e))
    return "Enter absolute start and end times.";
  if (e <= s) return "The end must be after the start.";
  const seconds = (e - s) / 1000;
  if (seconds < MIN_REPLAY_WINDOW_SECONDS)
    return "Choose a window of at least one minute.";
  if (seconds > MAX_REPLAY_WINDOW_SECONDS)
    return "Choose a window of at most 7 days.";
  if (e > Date.now() + 60_000) return "The window cannot end in the future.";
  return undefined;
}
