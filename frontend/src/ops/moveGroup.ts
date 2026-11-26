/**
 * Migration move-group (wave) planner. Pure and deterministic: the same
 * conversations, seeds, rules and overrides always produce the same plan.
 * Conversations are observed; groups, shared services and blockers are
 * planning inferences over them and are labelled as such.
 */

export const MOVE_GROUP_SCHEMA_VERSION = 1 as const;
export const PLANNER_LIMITS = {
  seedGroups: 16,
  seedAddresses: 64,
  depth: 6,
  groupSize: 1000,
  connections: 10000,
  conversations: 5000,
  edgeList: 2000,
  shared: 500,
  unplanned: 500,
  overrides: 1000,
  customPorts: 32,
  observers: 8,
} as const;

export type Transport = "tcp" | "udp";
export interface SharedPortRule {
  id: string;
  port: number;
  transports: Transport[];
  service: string;
  defaultEnabled: boolean;
  reference: string;
  note: string;
}

/**
 * A port is a service-port hint, not protocol proof. Defaults cover identity,
 * name and time services that almost never move with one application. File
 * and backup ports are opt-in because applications often own those servers,
 * and NetBackup clients also listen on PBX.
 */
export const SHARED_PORT_CATALOG: readonly SharedPortRule[] = [
  {
    id: "dns",
    port: 53,
    transports: ["tcp", "udp"],
    service: "DNS",
    defaultEnabled: true,
    reference: "https://www.rfc-editor.org/rfc/rfc1035",
    note: "Name resolution used by every tier.",
  },
  {
    id: "kerberos",
    port: 88,
    transports: ["tcp", "udp"],
    service: "Kerberos KDC",
    defaultEnabled: true,
    reference: "https://www.rfc-editor.org/rfc/rfc4120",
    note: "Domain authentication; domain controllers serve it.",
  },
  {
    id: "ntp",
    port: 123,
    transports: ["udp"],
    service: "NTP",
    defaultEnabled: true,
    reference: "https://www.rfc-editor.org/rfc/rfc5905",
    note: "Time source shared by the estate.",
  },
  {
    id: "ldap",
    port: 389,
    transports: ["tcp", "udp"],
    service: "LDAP / DC locator",
    defaultEnabled: true,
    reference: "https://www.rfc-editor.org/rfc/rfc4511",
    note: "Directory lookups; domain controllers serve it.",
  },
  {
    id: "kpasswd",
    port: 464,
    transports: ["tcp", "udp"],
    service: "Kerberos password change",
    defaultEnabled: true,
    reference:
      "https://learn.microsoft.com/en-us/troubleshoot/windows-server/networking/service-overview-and-network-port-requirements",
    note: "Served by domain controllers.",
  },
  {
    id: "ldaps",
    port: 636,
    transports: ["tcp"],
    service: "LDAP over TLS",
    defaultEnabled: true,
    reference:
      "https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-adts/1010e59a-cf64-410c-a05c-a3a6c715261a",
    note: "Directory lookups over TLS.",
  },
  {
    id: "gc",
    port: 3268,
    transports: ["tcp"],
    service: "AD Global Catalog",
    defaultEnabled: true,
    reference:
      "https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-adts/1010e59a-cf64-410c-a05c-a3a6c715261a",
    note: "Forest-wide directory lookups.",
  },
  {
    id: "gcs",
    port: 3269,
    transports: ["tcp"],
    service: "AD Global Catalog over TLS",
    defaultEnabled: true,
    reference:
      "https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-adts/1010e59a-cf64-410c-a05c-a3a6c715261a",
    note: "Forest-wide directory lookups over TLS.",
  },
  {
    id: "smb",
    port: 445,
    transports: ["tcp"],
    service: "SMB",
    defaultEnabled: false,
    reference:
      "https://learn.microsoft.com/en-us/troubleshoot/windows-server/networking/service-overview-and-network-port-requirements",
    note: "Domain controllers (SYSVOL) and file servers; application file shares also use it.",
  },
  {
    id: "nfs",
    port: 2049,
    transports: ["tcp", "udp"],
    service: "NFS",
    defaultEnabled: false,
    reference: "https://www.rfc-editor.org/rfc/rfc7530",
    note: "Shared filers; an application may own its NFS server.",
  },
  {
    id: "netbackup-pbx",
    port: 1556,
    transports: ["tcp"],
    service: "NetBackup PBX",
    defaultEnabled: false,
    reference: "https://www.veritas.com/support/en_US/article.100002391",
    note: "Backup primary and media servers; clients also listen on it, so raise the minimum client count.",
  },
];

export interface PlannerConversation {
  client: string;
  server: string;
  port?: number;
  transport: string;
  /** False when the summary ordered endpoints by address (direction unknown). */
  directed: boolean;
  records: number;
  /** Largest single-observer byte total; never summed across observers. */
  bytes?: number;
  first: number;
  last: number;
  observers: string[];
  observersCapped: boolean;
  sources: string[];
  sampled: boolean;
}
export interface SeedGroupInput {
  label: string;
  addresses: string[];
}
export interface SharedPortSelection {
  port: number;
  transport: Transport;
}
export interface PlannerRules {
  maxDepth: number;
  maxGroupSize: number;
  /** Hosts with more distinct peers are members but are not expanded. */
  maxConnections: number;
  sharedPorts: SharedPortSelection[];
  /** Distinct clients a host must serve on a shared port. */
  minPortClients: number;
  /** Nearest-rank percentile of distinct peers; null disables the rule. */
  fanInPercentile: number | null;
  minFanIn: number;
  mergeConnectedSeeds: boolean;
}
export const UNASSIGNED = "unassigned";
export interface PlannerOverrides {
  pinnedShared: string[];
  notShared: string[];
  /** Host → group ID or UNASSIGNED. */
  assignments: Record<string, string>;
}
export interface PlannerInput {
  conversations: PlannerConversation[];
  /** False when the conversation read was capped or otherwise incomplete. */
  complete: boolean;
  seeds: SeedGroupInput[];
  rules: PlannerRules;
  overrides: PlannerOverrides;
}

export type MemberBasis = "seed" | "traversal" | "manual";
export type ExpansionState =
  | "expanded"
  | "depth_limit"
  | "connection_limit"
  | "group_size_limit"
  | "not_expanded";
export interface GroupMember {
  address: string;
  basis: MemberBasis;
  depth?: number;
  via?: string;
  peers: number;
  expansion: ExpansionState;
  /** Shared-service rules this member matched but which did not apply. */
  sharedMatch: SharedReason[];
}
export interface MoveGroup {
  id: string;
  label: string;
  seeds: string[];
  members: GroupMember[];
  sizeCapped: boolean;
}
export type SharedReason =
  | {
      kind: "port";
      port: number;
      transport: Transport;
      service: string;
      clients: number;
    }
  | { kind: "fan_in"; peers: number; threshold: number; percentile: number }
  | { kind: "pinned" };
export interface SharedService {
  address: string;
  reasons: SharedReason[];
  basis: "inferred" | "user";
  peers: number;
  dependentGroups: string[];
}
export type EdgeKind = "wave_blocker" | "shared_service" | "outside_plan";
export const SHARED_GROUP = "shared";
export const UNPLANNED_GROUP = "unplanned";
export interface DependencyEdge extends PlannerConversation {
  kind: EdgeKind;
  clientGroup: string;
  serverGroup: string;
}
export interface GroupPairSummary {
  groups: [string, string];
  conversations: number;
  records: number;
  bytes?: number;
  services: string[];
  servicesCapped: boolean;
}
export interface UnplannedPeer {
  address: string;
  peers: number;
  adjacentGroups: string[];
}
export interface MovePlan {
  schemaVersion: typeof MOVE_GROUP_SCHEMA_VERSION;
  complete: boolean;
  hosts: number;
  conversations: number;
  fanInThreshold?: number;
  groups: MoveGroup[];
  shared: SharedService[];
  blockers: DependencyEdge[];
  blockerPairs: GroupPairSummary[];
  sharedDependencies: DependencyEdge[];
  outsidePlan: DependencyEdge[];
  unplanned: UnplannedPeer[];
  totals: {
    blockers: number;
    sharedDependencies: number;
    outsidePlan: number;
    internal: number;
    unplanned: number;
    shared: number;
  };
  truncated: {
    blockers: boolean;
    sharedDependencies: boolean;
    outsidePlan: boolean;
    unplanned: boolean;
    shared: boolean;
  };
  notes: string[];
}

export const DEFAULT_RULES: PlannerRules = {
  maxDepth: 2,
  maxGroupSize: 200,
  maxConnections: 50,
  sharedPorts: SHARED_PORT_CATALOG.filter(
    (rule) => rule.defaultEnabled,
  ).flatMap((rule) =>
    rule.transports.map((transport) => ({ port: rule.port, transport })),
  ),
  minPortClients: 2,
  fanInPercentile: 95,
  minFanIn: 10,
  mergeConnectedSeeds: false,
};

const integerIn = (value: number, min: number, max: number) =>
  Number.isInteger(value) && value >= min && value <= max;

const ADDRESS = /^[0-9A-Fa-f.:]{2,45}$/;
function validAddress(value: unknown): value is string {
  return typeof value === "string" && ADDRESS.test(value);
}

/** IPv4 sorts numerically and before IPv6; IPv6 sorts by canonical text. */
export function compareAddress(a: string, b: string): number {
  const v4 = (value: string) =>
    /^\d{1,3}(?:\.\d{1,3}){3}$/.test(value)
      ? value.split(".").reduce((sum, octet) => sum * 256 + Number(octet), 0)
      : undefined;
  const left = v4(a),
    right = v4(b);
  if (left !== undefined && right !== undefined) return left - right;
  if (left !== undefined) return -1;
  if (right !== undefined) return 1;
  return a < b ? -1 : a > b ? 1 : 0;
}

export function validateRules(rules: PlannerRules): PlannerRules {
  if (
    !integerIn(rules.maxDepth, 0, PLANNER_LIMITS.depth) ||
    !integerIn(rules.maxGroupSize, 1, PLANNER_LIMITS.groupSize) ||
    !integerIn(rules.maxConnections, 1, PLANNER_LIMITS.connections) ||
    !integerIn(rules.minPortClients, 1, 1000) ||
    !integerIn(rules.minFanIn, 1, PLANNER_LIMITS.connections) ||
    (rules.fanInPercentile !== null &&
      !(
        Number.isFinite(rules.fanInPercentile) &&
        rules.fanInPercentile >= 50 &&
        rules.fanInPercentile < 100
      )) ||
    typeof rules.mergeConnectedSeeds !== "boolean" ||
    !Array.isArray(rules.sharedPorts) ||
    rules.sharedPorts.length >
      SHARED_PORT_CATALOG.length * 2 + PLANNER_LIMITS.customPorts ||
    rules.sharedPorts.some(
      (p) =>
        !integerIn(p.port, 0, 65535) || !["tcp", "udp"].includes(p.transport),
    )
  )
    throw new Error("Invalid move-group rules.");
  return rules;
}

/** Parse "tcp/1556, udp/514" custom shared-port entries. */
export function parseCustomPorts(text: string): SharedPortSelection[] {
  const items = text
    .split(/[\s,]+/)
    .map((item) => item.trim().toLowerCase())
    .filter(Boolean);
  if (items.length > PLANNER_LIMITS.customPorts)
    throw new Error(
      `Enter at most ${PLANNER_LIMITS.customPorts} custom shared ports.`,
    );
  return items.map((item) => {
    const match = /^(tcp|udp)\/(\d{1,5})$/.exec(item);
    const port = match ? Number(match[2]) : NaN;
    if (!match || !integerIn(port, 1, 65535))
      throw new Error(`Use transport/port such as tcp/1556 (got "${item}").`);
    return { transport: match[1] as Transport, port };
  });
}

/**
 * Parse seed lines: "label = 10.0.0.1, 10.0.0.2" or bare addresses. Each line
 * becomes one candidate group. "=" never occurs in an IPv4 or IPv6 literal.
 * Addresses are validated by the caller's normalizer.
 */
export function parseSeedLines(
  text: string,
  normalize: (value: string) => string,
): SeedGroupInput[] {
  const lines = text
    .split(/\r?\n/)
    .map((line) => line.trim())
    .filter(Boolean);
  if (!lines.length) throw new Error("Enter at least one seed address.");
  if (lines.length > PLANNER_LIMITS.seedGroups)
    throw new Error(`Enter at most ${PLANNER_LIMITS.seedGroups} seed lines.`);
  let total = 0;
  return lines.map((line, index) => {
    const labelled = /^([^=]*)=(.*)$/.exec(line);
    const label = (labelled?.[1] ?? "").trim();
    if (
      label.length > 64 ||
      [...label].some(
        (char) => char.charCodeAt(0) < 32 || char.charCodeAt(0) === 127,
      )
    )
      throw new Error("Seed labels must be at most 64 printable characters.");
    const addresses = (labelled?.[2] ?? line)
      .split(/[\s,]+/)
      .filter(Boolean)
      .map((value) => normalize(value));
    total += addresses.length;
    if (!addresses.length || total > PLANNER_LIMITS.seedAddresses)
      throw new Error(
        `Each line needs an address; at most ${PLANNER_LIMITS.seedAddresses} seed addresses in total.`,
      );
    return { label: label || `Group ${index + 1}`, addresses };
  });
}

function validateInput(input: PlannerInput): void {
  validateRules(input.rules);
  if (
    !Array.isArray(input.conversations) ||
    input.conversations.length > PLANNER_LIMITS.conversations ||
    typeof input.complete !== "boolean" ||
    !Array.isArray(input.seeds) ||
    !input.seeds.length ||
    input.seeds.length > PLANNER_LIMITS.seedGroups ||
    input.seeds.reduce((n, s) => n + s.addresses.length, 0) >
      PLANNER_LIMITS.seedAddresses ||
    input.seeds.some(
      (s) =>
        typeof s.label !== "string" ||
        !s.label ||
        s.label.length > 64 ||
        !s.addresses.length ||
        !s.addresses.every(validAddress),
    )
  )
    throw new Error("Invalid move-group input.");
  const o = input.overrides;
  const assignments = Object.entries(o.assignments);
  if (
    o.pinnedShared.length + o.notShared.length + assignments.length >
      PLANNER_LIMITS.overrides ||
    !o.pinnedShared.every(validAddress) ||
    !o.notShared.every(validAddress) ||
    !assignments.every(
      ([host, group]) =>
        validAddress(host) && typeof group === "string" && group.length <= 64,
    )
  )
    throw new Error("Invalid move-group overrides.");
  for (const c of input.conversations)
    if (
      !validAddress(c.client) ||
      !validAddress(c.server) ||
      (c.port !== undefined && !integerIn(c.port, 0, 65535)) ||
      typeof c.transport !== "string" ||
      typeof c.directed !== "boolean" ||
      !Number.isFinite(c.records) ||
      c.records < 0 ||
      (c.bytes !== undefined && (!Number.isFinite(c.bytes) || c.bytes < 0)) ||
      !Number.isFinite(c.first) ||
      !Number.isFinite(c.last) ||
      c.last < c.first ||
      c.observers.length > PLANNER_LIMITS.observers ||
      c.sources.length > PLANNER_LIMITS.observers
    )
      throw new Error("Invalid move-group conversation.");
}

const sortedUnique = (values: Iterable<string>) =>
  [...new Set(values)].sort(compareAddress);

const serviceLabel = (c: Pick<PlannerConversation, "port" | "transport">) =>
  `${c.transport}/${c.port ?? "-"}`;

function edgeOrder(a: DependencyEdge, b: DependencyEdge): number {
  return (
    a.clientGroup.localeCompare(b.clientGroup) ||
    a.serverGroup.localeCompare(b.serverGroup) ||
    b.records - a.records ||
    compareAddress(a.client, b.client) ||
    compareAddress(a.server, b.server) ||
    (a.port ?? -1) - (b.port ?? -1) ||
    a.transport.localeCompare(b.transport)
  );
}

/** Nearest-rank percentile of a non-empty ascending list. */
export function nearestRank(sortedAscending: number[], percentile: number) {
  const rank = Math.max(
    1,
    Math.ceil((percentile / 100) * sortedAscending.length),
  );
  return sortedAscending[Math.min(rank, sortedAscending.length) - 1];
}

export function planMoveGroups(input: PlannerInput): MovePlan {
  validateInput(input);
  const { rules, overrides } = input;
  const notes: string[] = [];
  const conversations = input.conversations.filter(
    (c) => c.client !== c.server,
  );
  const adjacency = new Map<string, Set<string>>();
  const link = (a: string, b: string) => {
    if (!adjacency.has(a)) adjacency.set(a, new Set());
    adjacency.get(a)!.add(b);
  };
  for (const c of conversations) {
    link(c.client, c.server);
    link(c.server, c.client);
  }
  const peers = (host: string) => adjacency.get(host)?.size ?? 0;
  const neighbours = (host: string) => sortedUnique(adjacency.get(host) ?? []);

  // Shared-service detection over observed conversations.
  const detected = new Map<string, SharedReason[]>();
  const addReason = (host: string, reason: SharedReason) => {
    if (!detected.has(host)) detected.set(host, []);
    detected.get(host)!.push(reason);
  };
  const enabled = new Map(
    rules.sharedPorts.map((p) => [`${p.transport}/${p.port}`, p]),
  );
  const servedClients = new Map<string, Set<string>>();
  let undirectedSharedPortRows = 0;
  for (const c of conversations) {
    const key = `${c.transport.toLowerCase()}/${c.port}`;
    if (c.port === undefined || !enabled.has(key)) continue;
    if (!c.directed) {
      undirectedSharedPortRows += 1;
      continue;
    }
    const id = `${c.server}\u0000${key}`;
    if (!servedClients.has(id)) servedClients.set(id, new Set());
    servedClients.get(id)!.add(c.client);
  }
  for (const id of [...servedClients.keys()].sort()) {
    const [host, key] = id.split("\u0000");
    const clients = servedClients.get(id)!.size;
    if (clients < rules.minPortClients) continue;
    const selection = enabled.get(key)!;
    const catalog = SHARED_PORT_CATALOG.find(
      (rule) =>
        rule.port === selection.port &&
        rule.transports.includes(selection.transport),
    );
    addReason(host, {
      kind: "port",
      port: selection.port,
      transport: selection.transport,
      service: catalog?.service ?? "Custom shared port",
      clients,
    });
  }
  if (undirectedSharedPortRows)
    notes.push(
      `${undirectedSharedPortRows} conversations on shared-service ports have no observed direction, so the server side is unknown and they were not used by the port rule.`,
    );
  let fanInThreshold: number | undefined;
  if (rules.fanInPercentile !== null && adjacency.size) {
    const degrees = [...adjacency.values()]
      .map((set) => set.size)
      .sort((a, b) => a - b);
    const threshold = nearestRank(degrees, rules.fanInPercentile);
    fanInThreshold = Math.max(threshold, rules.minFanIn);
    for (const host of sortedUnique(adjacency.keys()))
      if (peers(host) >= fanInThreshold)
        addReason(host, {
          kind: "fan_in",
          peers: peers(host),
          threshold: fanInThreshold,
          percentile: rules.fanInPercentile,
        });
  }
  const pinned = new Set(overrides.pinnedShared);
  const notShared = new Set(overrides.notShared);
  const assigned = new Map(Object.entries(overrides.assignments));
  const manualMember = (host: string) =>
    assigned.has(host) && assigned.get(host) !== UNASSIGNED;
  const isShared = (host: string) =>
    !manualMember(host) &&
    (pinned.has(host) || (detected.has(host) && !notShared.has(host)));

  // Seed groups. A pinned shared seed is dropped; detection never drops a seed.
  const seen = new Set<string>();
  const groups: (MoveGroup & { index: number })[] = [];
  input.seeds.forEach((seed, index) => {
    const addresses: string[] = [];
    for (const address of seed.addresses) {
      if (seen.has(address)) {
        notes.push(
          `Seed ${address} is listed more than once; the first line keeps it.`,
        );
        continue;
      }
      if (pinned.has(address) && !manualMember(address)) {
        notes.push(
          `Seed ${address} is pinned as a shared service and was not used as a seed.`,
        );
        continue;
      }
      seen.add(address);
      addresses.push(address);
    }
    groups.push({
      index,
      id: `g${index + 1}`,
      label: seed.label,
      seeds: addresses,
      members: [],
      sizeCapped: false,
    });
  });

  interface Owner {
    group: number;
    depth: number;
    via?: string;
    expansion: ExpansionState;
  }
  const owner = new Map<string, Owner>();
  const parent = groups.map((g) => g.index);
  const find = (i: number): number =>
    parent[i] === i ? i : (parent[i] = find(parent[i]));
  const union = (a: number, b: number) => {
    const ra = find(a),
      rb = find(b);
    if (ra !== rb) parent[Math.max(ra, rb)] = Math.min(ra, rb);
  };
  const sizes = groups.map(() => 0);
  let frontier: string[] = [];
  for (const group of groups)
    for (const address of group.seeds) {
      owner.set(address, {
        group: group.index,
        depth: 0,
        expansion: "not_expanded",
      });
      sizes[group.index] += 1;
      frontier.push(address);
    }
  for (let depth = 0; depth <= rules.maxDepth && frontier.length; depth++) {
    const next: string[] = [];
    frontier.sort(
      (a, b) =>
        owner.get(a)!.group - owner.get(b)!.group || compareAddress(a, b),
    );
    for (const host of frontier) {
      const state = owner.get(host)!;
      const isSeed = depth === 0;
      if (!isSeed && isShared(host)) continue;
      const candidates = neighbours(host).filter((n) => !isShared(n));
      if (rules.mergeConnectedSeeds)
        for (const n of candidates) {
          const existing = owner.get(n);
          if (existing) union(existing.group, state.group);
        }
      const unowned = candidates.filter((n) => !owner.has(n));
      state.expansion = !unowned.length
        ? "expanded"
        : depth === rules.maxDepth
          ? "depth_limit"
          : peers(host) > rules.maxConnections
            ? "connection_limit"
            : "expanded";
      if (state.expansion !== "expanded") continue;
      for (const n of unowned) {
        const root = rules.mergeConnectedSeeds ? find(state.group) : -1;
        const used = rules.mergeConnectedSeeds
          ? sizes.reduce((n2, s, i) => (find(i) === root ? n2 + s : n2), 0)
          : sizes[state.group];
        if (used >= rules.maxGroupSize) {
          state.expansion = "group_size_limit";
          groups[rules.mergeConnectedSeeds ? root : state.group].sizeCapped =
            true;
          break;
        }
        owner.set(n, {
          group: state.group,
          depth: depth + 1,
          via: host,
          expansion: "not_expanded",
        });
        sizes[state.group] += 1;
        next.push(n);
      }
    }
    frontier = next;
  }

  // Merge connected seed groups into the lowest-numbered group.
  const finalGroups: MoveGroup[] = [];
  const groupOf = new Map<number, MoveGroup>();
  for (const group of groups) {
    const root = find(group.index);
    let target = groupOf.get(root);
    if (!target) {
      target = {
        id: groups[root].id,
        label: groups[root].label,
        seeds: [],
        members: [],
        sizeCapped: false,
      };
      groupOf.set(root, target);
      finalGroups.push(target);
    } else target.label = `${target.label} + ${group.label}`;
    target.seeds.push(...group.seeds);
    target.sizeCapped ||= group.sizeCapped;
  }
  const membership = new Map<string, string>();
  const memberDetail = new Map<string, GroupMember>();
  for (const [address, state] of owner) {
    const group = groupOf.get(find(state.group))!;
    membership.set(address, group.id);
    memberDetail.set(address, {
      address,
      basis: state.depth === 0 ? "seed" : "traversal",
      depth: state.depth,
      ...(state.via ? { via: state.via } : {}),
      peers: peers(address),
      expansion: state.expansion,
      sharedMatch: [],
    });
  }
  const groupIds = new Set(finalGroups.map((g) => g.id));
  for (const [host, target] of [...assigned].sort(([a], [b]) =>
    compareAddress(a, b),
  )) {
    if (target === UNASSIGNED) {
      membership.delete(host);
      memberDetail.delete(host);
      continue;
    }
    if (!groupIds.has(target)) {
      notes.push(
        `Manual move of ${host} to ${target} was ignored; that group is not in the current plan.`,
      );
      continue;
    }
    membership.set(host, target);
    memberDetail.set(host, {
      address: host,
      basis: "manual",
      peers: peers(host),
      expansion: "not_expanded",
      sharedMatch: [],
    });
  }
  for (const [address, detail] of memberDetail) {
    const reasons = [
      ...(pinned.has(address) ? [{ kind: "pinned" } as const] : []),
      ...(detected.get(address) ?? []),
    ];
    if (reasons.length && !notShared.has(address)) detail.sharedMatch = reasons;
  }
  const byId = new Map(finalGroups.map((g) => [g.id, g]));
  for (const [address, id] of membership)
    byId.get(id)!.members.push(memberDetail.get(address)!);
  for (const group of finalGroups)
    group.members.sort(
      (a, b) =>
        (a.depth ?? PLANNER_LIMITS.depth + 1) -
          (b.depth ?? PLANNER_LIMITS.depth + 1) ||
        compareAddress(a.address, b.address),
    );
  for (const group of finalGroups)
    if (group.members.some((m) => m.basis === "seed" && m.sharedMatch.length))
      notes.push(
        `${group.label} has a seed that matches a shared-service rule; it stays in the group because it was chosen as a seed.`,
      );

  // Classify every observed conversation relative to the plan.
  const sharedHosts = new Set(
    sortedUnique([...adjacency.keys(), ...pinned]).filter(
      (h) => isShared(h) && !membership.has(h),
    ),
  );
  const side = (host: string) =>
    membership.get(host) ??
    (sharedHosts.has(host) ? SHARED_GROUP : UNPLANNED_GROUP);
  const blockers: DependencyEdge[] = [];
  const sharedDependencies: DependencyEdge[] = [];
  const outsidePlan: DependencyEdge[] = [];
  const dependents = new Map<string, Set<string>>();
  const unplannedAdjacent = new Map<string, Set<string>>();
  let internal = 0;
  for (const c of conversations) {
    const clientGroup = side(c.client),
      serverGroup = side(c.server);
    const inPlan = (g: string) => g !== SHARED_GROUP && g !== UNPLANNED_GROUP;
    if (!inPlan(clientGroup) && !inPlan(serverGroup)) continue;
    if (clientGroup === serverGroup) {
      internal += 1;
      continue;
    }
    const edge: DependencyEdge = {
      ...c,
      kind: "wave_blocker",
      clientGroup,
      serverGroup,
    };
    if (inPlan(clientGroup) && inPlan(serverGroup)) blockers.push(edge);
    else if (clientGroup === SHARED_GROUP || serverGroup === SHARED_GROUP) {
      edge.kind = "shared_service";
      sharedDependencies.push(edge);
      const [host, group] =
        clientGroup === SHARED_GROUP
          ? [c.client, serverGroup]
          : [c.server, clientGroup];
      if (!dependents.has(host)) dependents.set(host, new Set());
      dependents.get(host)!.add(group);
    } else {
      edge.kind = "outside_plan";
      outsidePlan.push(edge);
      const [host, group] =
        clientGroup === UNPLANNED_GROUP
          ? [c.client, serverGroup]
          : [c.server, clientGroup];
      if (!unplannedAdjacent.has(host)) unplannedAdjacent.set(host, new Set());
      unplannedAdjacent.get(host)!.add(group);
    }
  }
  for (const list of [blockers, sharedDependencies, outsidePlan])
    list.sort(edgeOrder);

  const pairs = new Map<string, GroupPairSummary & { all: Set<string> }>();
  for (const edge of blockers) {
    const key = [edge.clientGroup, edge.serverGroup].sort() as [string, string];
    const id = key.join("\u0000");
    let pair = pairs.get(id);
    if (!pair) {
      pair = {
        groups: key,
        conversations: 0,
        records: 0,
        services: [],
        servicesCapped: false,
        all: new Set(),
      };
      pairs.set(id, pair);
    }
    pair.conversations += 1;
    pair.records += edge.records;
    if (edge.bytes !== undefined) pair.bytes = (pair.bytes ?? 0) + edge.bytes;
    pair.all.add(serviceLabel(edge));
  }
  const blockerPairs = [...pairs.values()]
    .map(({ all, ...pair }) => {
      const services = [...all].sort();
      return {
        ...pair,
        services: services.slice(0, 16),
        servicesCapped: services.length > 16,
      };
    })
    .sort(
      (a, b) =>
        b.conversations - a.conversations ||
        a.groups[0].localeCompare(b.groups[0]) ||
        a.groups[1].localeCompare(b.groups[1]),
    );

  const shared: SharedService[] = [...sharedHosts].map((address) => ({
    address,
    reasons: [
      ...(pinned.has(address) ? [{ kind: "pinned" } as const] : []),
      ...(notShared.has(address) ? [] : (detected.get(address) ?? [])),
    ],
    basis: pinned.has(address) ? "user" : "inferred",
    peers: peers(address),
    dependentGroups: [...(dependents.get(address) ?? [])].sort(),
  }));
  shared.sort(
    (a, b) =>
      b.dependentGroups.length - a.dependentGroups.length ||
      b.peers - a.peers ||
      compareAddress(a.address, b.address),
  );
  const unplanned = [...unplannedAdjacent]
    .map(([address, adjacent]) => ({
      address,
      peers: peers(address),
      adjacentGroups: [...adjacent].sort(),
    }))
    .sort(
      (a, b) =>
        b.adjacentGroups.length - a.adjacentGroups.length ||
        b.peers - a.peers ||
        compareAddress(a.address, b.address),
    );

  if (!input.complete)
    notes.unshift(
      "The conversation read was capped or incomplete. Groups, fan-in percentiles and blockers cover only the loaded conversations; a missing blocker does not mean there is no dependency.",
    );
  if (finalGroups.some((g) => g.sizeCapped))
    notes.push(
      "At least one group reached its size limit; more observed peers were not added.",
    );
  if (conversations.some((c) => c.sampled))
    notes.push(
      "Some conversations come from sampled flow records; low-volume dependencies may be missing.",
    );
  const cap = PLANNER_LIMITS.edgeList;
  return {
    schemaVersion: MOVE_GROUP_SCHEMA_VERSION,
    complete: input.complete,
    hosts: adjacency.size,
    conversations: conversations.length,
    ...(fanInThreshold === undefined ? {} : { fanInThreshold }),
    groups: finalGroups,
    shared: shared.slice(0, PLANNER_LIMITS.shared),
    blockers: blockers.slice(0, cap),
    blockerPairs,
    sharedDependencies: sharedDependencies.slice(0, cap),
    outsidePlan: outsidePlan.slice(0, cap),
    unplanned: unplanned.slice(0, PLANNER_LIMITS.unplanned),
    totals: {
      blockers: blockers.length,
      sharedDependencies: sharedDependencies.length,
      outsidePlan: outsidePlan.length,
      internal,
      unplanned: unplanned.length,
      shared: shared.length,
    },
    truncated: {
      blockers: blockers.length > cap,
      sharedDependencies: sharedDependencies.length > cap,
      outsidePlan: outsidePlan.length > cap,
      unplanned: unplanned.length > PLANNER_LIMITS.unplanned,
      shared: shared.length > PLANNER_LIMITS.shared,
    },
    notes,
  };
}
