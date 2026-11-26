import { csvRow } from "../csv";

/**
 * ITSI service/entity import rows built from Atlas observations.
 *
 * Column names follow the ITSI import settings documented for ITSI 4.19
 * `inputs.conf` (`service_title_field`, `service_description_column`,
 * `service_dependents`, `entity_title_field`, `entity_description_column`,
 * `entity_identifier_fields`, `entity_informational_fields`). The export is a
 * file only; Atlas never calls `itsiimportobjects` or writes to ITSI.
 */

export interface AtlasServiceKey {
  service: string;
  environment: string;
  cluster: string;
  namespace: string;
}

export interface ObservedServiceDependency {
  from: AtlasServiceKey;
  to: AtlasServiceKey;
  firstSeen: number;
  lastSeen: number;
  conversations: number;
}

/** Only exact, conflict-free bindings resolved against qualified identities. */
export interface BusinessServiceParent {
  serviceName: string;
  serviceId: string;
  authority: string;
  members: AtlasServiceKey[];
}

export interface ObservedEntity {
  scope: string;
  ip: string;
  kind: "vm" | "k8s_node" | "endpoint";
  name?: string;
  firstSeen: number;
  lastSeen: number;
}

export interface ItsiExportInput {
  services: AtlasServiceKey[];
  dependencies: ObservedServiceDependency[];
  businessServices?: BusinessServiceParent[];
  entities?: ObservedEntity[];
  window: { start: number; end: number };
  batchSize?: number;
}

export interface ItsiServiceRow {
  service_title: string;
  service_description: string;
  services_depends_on: string;
}

export interface ItsiEntityRow {
  entity_title: string;
  entity_description: string;
  ip: string;
  atlas_scope: string;
  atlas_identity_kind: string;
}

export interface BrokenEdge {
  from: string;
  to: string;
  /** Titles from the dependency target back to the edge source, then the target. */
  cycle: string[];
}

export interface ExcludedItem {
  item: string;
  reason: string;
}

export interface ItsiBatch {
  index: number;
  rows: ItsiServiceRow[];
}

export interface ItsiExport {
  batches: ItsiBatch[];
  entities: ItsiEntityRow[];
  brokenEdges: BrokenEdge[];
  excluded: ExcludedItem[];
  serviceCount: number;
  dependencyCount: number;
  batchSize: number;
  window: { start: number; end: number };
}

export const ITSI_BATCH_MIN = 200;
export const ITSI_BATCH_MAX = 300;
export const ITSI_BATCH_DEFAULT = 250;
export const ITSI_MAX_ENTITIES = 5000;
const MAX_TITLE = 255;

export const ITSI_SERVICE_COLUMNS = [
  "service_title",
  "service_description",
  "services_depends_on",
] as const;
export const ITSI_ENTITY_COLUMNS = [
  "entity_title",
  "entity_description",
  "ip",
  "atlas_scope",
  "atlas_identity_kind",
] as const;

/**
 * ITSI splits dependent services on commas and accepts `;`, `|`, tab and `^`
 * as CSV separators. A leading formula character would be rewritten by the
 * CSV writer and no longer match its dependency references.
 */
export function itsiTitleError(title: string): string | undefined {
  if (!title || title.length > MAX_TITLE)
    return `Title must contain 1 to ${MAX_TITLE} characters.`;
  if (title !== title.trim()) return "Title has leading or trailing spaces.";
  if (/[,;|^\t"]/.test(title))
    return 'Title contains an ITSI separator or quote (, ; | ^ tab ").';
  if ([...title].some((c) => c.charCodeAt(0) < 32 || c.charCodeAt(0) === 127))
    return "Title contains a control character.";
  if (/^[=+\-@]/.test(title))
    return "Title starts with a spreadsheet formula character.";
  return undefined;
}

export const serviceKeyId = (key: AtlasServiceKey) =>
  JSON.stringify([key.service, key.environment, key.cluster, key.namespace]);

export const itsiServiceTitle = (key: AtlasServiceKey) =>
  `${key.service} (${key.environment}/${key.cluster}/${key.namespace})`;

const utc = (epoch: number) =>
  new Date(epoch * 1000).toISOString().replace(".000Z", "Z");
const compare = (a: string, b: string) => (a < b ? -1 : a > b ? 1 : 0);

interface Node {
  title: string;
  description: string;
}

/**
 * Remove every DFS back edge, visiting nodes and targets in title order, so
 * the same input always breaks the same edges. Returns the kept adjacency.
 */
export function breakCycles(
  titles: readonly string[],
  edges: ReadonlyMap<string, ReadonlySet<string>>,
): { kept: Map<string, string[]>; broken: BrokenEdge[] } {
  const ordered = [...titles].sort(compare);
  const kept = new Map<string, string[]>(ordered.map((t) => [t, []]));
  const broken: BrokenEdge[] = [];
  const state = new Map<string, 1 | 2>();
  for (const root of ordered) {
    if (state.has(root)) continue;
    const stack: { node: string; targets: string[]; next: number }[] = [];
    const push = (node: string) => {
      state.set(node, 1);
      stack.push({
        node,
        targets: [...(edges.get(node) ?? [])]
          .filter((t) => kept.has(t))
          .sort(compare),
        next: 0,
      });
    };
    push(root);
    while (stack.length) {
      const frame = stack[stack.length - 1];
      if (frame.next >= frame.targets.length) {
        state.set(frame.node, 2);
        stack.pop();
        continue;
      }
      const target = frame.targets[frame.next++];
      const seen = state.get(target);
      if (seen === 1) {
        const start = stack.findIndex((entry) => entry.node === target);
        broken.push({
          from: frame.node,
          to: target,
          cycle: [...stack.slice(start).map((entry) => entry.node), target],
        });
        continue;
      }
      kept.get(frame.node)!.push(target);
      if (seen === undefined) push(target);
    }
  }
  return { kept, broken };
}

/** Dependencies before dependents, title-ordered among peers. */
function dependencyOrder(kept: ReadonlyMap<string, string[]>): string[] {
  const order: string[] = [];
  const done = new Set<string>();
  for (const root of [...kept.keys()].sort(compare)) {
    if (done.has(root)) continue;
    const stack: { node: string; next: number }[] = [{ node: root, next: 0 }];
    done.add(root);
    while (stack.length) {
      const frame = stack[stack.length - 1];
      const targets = kept.get(frame.node) ?? [];
      if (frame.next >= targets.length) {
        order.push(frame.node);
        stack.pop();
        continue;
      }
      const target = targets[frame.next++];
      if (!done.has(target)) {
        done.add(target);
        stack.push({ node: target, next: 0 });
      }
    }
  }
  return order;
}

export function clampBatchSize(value: number | undefined): number {
  if (value === undefined || !Number.isFinite(value)) return ITSI_BATCH_DEFAULT;
  return Math.min(ITSI_BATCH_MAX, Math.max(ITSI_BATCH_MIN, Math.floor(value)));
}

export function buildItsiExport(input: ItsiExportInput): ItsiExport {
  const { start, end } = input.window;
  if (!Number.isFinite(start) || !Number.isFinite(end) || end <= start)
    throw new Error("ITSI export needs an absolute observation window.");
  const batchSize = clampBatchSize(input.batchSize);
  const excluded: ExcludedItem[] = [];
  const nodes = new Map<string, Node>();
  const titleByKey = new Map<string, string>();
  const collisions = new Set<string>();

  const keys = new Map<string, AtlasServiceKey>();
  for (const key of [
    ...input.services,
    ...input.dependencies.flatMap((d) => [d.from, d.to]),
  ])
    keys.set(serviceKeyId(key), key);
  for (const [id, key] of [...keys].sort((a, b) => compare(a[0], b[0]))) {
    if (
      [key.service, key.environment, key.cluster, key.namespace].some(
        (part) => typeof part !== "string" || !part,
      )
    ) {
      excluded.push({
        item: id,
        reason: "Service scope is incomplete; no title was generated.",
      });
      continue;
    }
    const title = itsiServiceTitle(key);
    const error = itsiTitleError(title);
    if (error) {
      excluded.push({ item: title, reason: error });
      continue;
    }
    if (nodes.has(title)) {
      collisions.add(title);
      continue;
    }
    nodes.set(title, {
      title,
      description: `Application Atlas observed service ${key.service}; environment ${key.environment}, cluster ${key.cluster}, namespace ${key.namespace}. Dependencies are network conversations observed ${utc(start)} to ${utc(end)}; they are not CMDB records.`,
    });
    titleByKey.set(id, title);
  }

  const businessMembers = new Map<string, Set<string>>();
  for (const parent of [...(input.businessServices ?? [])].sort(
    (a, b) =>
      compare(a.serviceName, b.serviceName) ||
      compare(a.authority, b.authority) ||
      compare(a.serviceId, b.serviceId),
  )) {
    const title = parent.serviceName;
    const error = itsiTitleError(title);
    if (error) {
      excluded.push({ item: `Business service ${title}`, reason: error });
      continue;
    }
    if (nodes.has(title)) {
      collisions.add(title);
      continue;
    }
    const members = new Set<string>();
    for (const member of parent.members) {
      const memberTitle = titleByKey.get(serviceKeyId(member));
      if (memberTitle) members.add(memberTitle);
      else
        excluded.push({
          item: `${title} → ${itsiServiceTitle(member)}`,
          reason: "Business-service member is not an exported Atlas service.",
        });
    }
    nodes.set(title, {
      title,
      description: `Imported business-service assertion ${parent.serviceId} from ${parent.authority}. Members come from exact bindings to qualified Atlas service identities; the assertion itself is not verified.`,
    });
    businessMembers.set(title, members);
  }
  for (const title of [...collisions].sort(compare)) {
    nodes.delete(title);
    businessMembers.delete(title);
    for (const [id, value] of titleByKey)
      if (value === title) titleByKey.delete(id);
    excluded.push({
      item: title,
      reason: "Two exported services produce the same ITSI title.",
    });
  }

  const edges = new Map<string, Set<string>>();
  const addEdge = (from: string, to: string) => {
    if (from === to) return;
    if (!edges.has(from)) edges.set(from, new Set());
    edges.get(from)!.add(to);
  };
  for (const dependency of input.dependencies) {
    const from = titleByKey.get(serviceKeyId(dependency.from));
    const to = titleByKey.get(serviceKeyId(dependency.to));
    if (from && to) addEdge(from, to);
  }
  for (const [title, members] of businessMembers)
    for (const member of members) if (nodes.has(member)) addEdge(title, member);

  const { kept, broken } = breakCycles([...nodes.keys()], edges);
  const order = dependencyOrder(kept);
  const rows = order.map((title) => ({
    service_title: title,
    service_description: nodes.get(title)!.description,
    services_depends_on: [...kept.get(title)!].sort(compare).join(","),
  }));
  const batches: ItsiBatch[] = [];
  for (let offset = 0; offset < rows.length; offset += batchSize)
    batches.push({
      index: batches.length + 1,
      rows: rows.slice(offset, offset + batchSize),
    });

  const entities = buildEntities(input.entities ?? [], excluded);
  return {
    batches,
    entities,
    brokenEdges: broken,
    excluded,
    serviceCount: rows.length,
    dependencyCount: [...kept.values()].reduce((n, t) => n + t.length, 0),
    batchSize,
    window: { start, end },
  };
}

function buildEntities(
  observed: readonly ObservedEntity[],
  excluded: ExcludedItem[],
): ItsiEntityRow[] {
  const byTitle = new Map<string, ItsiEntityRow>();
  const collisions = new Set<string>();
  const sorted = [...observed].sort(
    (a, b) => compare(a.scope, b.scope) || compare(a.ip, b.ip),
  );
  const seen = new Set<string>();
  for (const entity of sorted) {
    const identity = `${entity.scope}\u0000${entity.ip}`;
    if (seen.has(identity)) continue;
    seen.add(identity);
    const title = `${entity.name ?? entity.ip} (${entity.scope})`;
    const error = itsiTitleError(title);
    if (error) {
      excluded.push({ item: `Entity ${title}`, reason: error });
      continue;
    }
    if (byTitle.has(title)) {
      collisions.add(title);
      continue;
    }
    byTitle.set(title, {
      entity_title: title,
      entity_description: `Application Atlas ${entity.kind} endpoint observed in network conversations ${utc(entity.firstSeen)} to ${utc(entity.lastSeen)}. Not a CMDB record.`,
      ip: entity.ip,
      atlas_scope: entity.scope,
      atlas_identity_kind: entity.kind,
    });
  }
  for (const title of collisions) {
    byTitle.delete(title);
    excluded.push({
      item: `Entity ${title}`,
      reason: "Two observed endpoints produce the same ITSI entity title.",
    });
  }
  const rows = [...byTitle.values()].sort((a, b) =>
    compare(a.entity_title, b.entity_title),
  );
  if (rows.length > ITSI_MAX_ENTITIES) {
    excluded.push({
      item: `${rows.length - ITSI_MAX_ENTITIES} entities`,
      reason: `Entity export is capped at ${ITSI_MAX_ENTITIES} rows.`,
    });
    return rows.slice(0, ITSI_MAX_ENTITIES);
  }
  return rows;
}

export function itsiServicesCsv(batch: ItsiBatch): string {
  return [
    csvRow([...ITSI_SERVICE_COLUMNS]),
    ...batch.rows.map((row) =>
      csvRow(ITSI_SERVICE_COLUMNS.map((column) => row[column])),
    ),
  ].join("\r\n");
}

export function itsiEntitiesCsv(rows: readonly ItsiEntityRow[]): string {
  return [
    csvRow([...ITSI_ENTITY_COLUMNS]),
    ...rows.map((row) =>
      csvRow(ITSI_ENTITY_COLUMNS.map((column) => row[column])),
    ),
  ].join("\r\n");
}

export function itsiBrokenEdgesCsv(edges: readonly BrokenEdge[]): string {
  return [
    csvRow(["dependent_service", "removed_dependency", "cycle"]),
    ...edges.map((edge) =>
      csvRow([edge.from, edge.to, edge.cycle.join(" > ")]),
    ),
  ].join("\r\n");
}
