import type { CatalogRow } from "../data/catalog";
import {
  resolveBusinessOwnership,
  type NativeServiceIdentity,
} from "../businessServices/bindings";
import type { ImportPreview } from "../businessServices/import";
import {
  serviceKeyId,
  type AtlasServiceKey,
  type BusinessServiceParent,
  type ExcludedItem,
  type ObservedEntity,
  type ObservedServiceDependency,
} from "./itsiExport";
import type { ObservedRelationship } from "./reconciliation";

const ENTITY_KINDS = new Set(["vm", "endpoint", "k8s_node"]);

/** Service edges only where both sides have exactly one retained binding. */
export function observedServiceDependencies(
  relationships: readonly ObservedRelationship[],
): ObservedServiceDependency[] {
  const byPair = new Map<string, ObservedServiceDependency>();
  for (const rel of relationships) {
    const from = rel.client.service;
    const to = rel.server.service;
    if (
      rel.client.serviceState !== "bound" ||
      rel.server.serviceState !== "bound" ||
      !from ||
      !to
    )
      continue;
    const fromId = serviceKeyId(from);
    const toId = serviceKeyId(to);
    if (fromId === toId) continue;
    const key = `${fromId}\u0000${toId}`;
    const current = byPair.get(key);
    if (current) {
      current.firstSeen = Math.min(current.firstSeen, rel.firstSeen);
      current.lastSeen = Math.max(current.lastSeen, rel.lastSeen);
      current.conversations += 1;
    } else
      byPair.set(key, {
        from,
        to,
        firstSeen: rel.firstSeen,
        lastSeen: rel.lastSeen,
        conversations: 1,
      });
  }
  return [...byPair.values()];
}

/** Non-workload endpoints with one resolved Atlas identity; pods churn and are not exported. */
export function observedEntities(
  relationships: readonly ObservedRelationship[],
): ObservedEntity[] {
  const byIp = new Map<string, ObservedEntity>();
  const conflicts = new Set<string>();
  for (const rel of relationships)
    for (const [ip, side] of [
      [rel.clientIp, rel.client],
      [rel.serverIp, rel.server],
    ] as const) {
      if (
        side.identityState !== "resolved" ||
        !side.kind ||
        !ENTITY_KINDS.has(side.kind)
      )
        continue;
      const key = `${rel.scope}\u0000${ip}`;
      const current = byIp.get(key);
      if (!current) {
        byIp.set(key, {
          scope: rel.scope,
          ip,
          kind: side.kind as ObservedEntity["kind"],
          ...(side.name ? { name: side.name } : {}),
          firstSeen: rel.firstSeen,
          lastSeen: rel.lastSeen,
        });
        continue;
      }
      if (current.kind !== side.kind || current.name !== side.name)
        conflicts.add(key);
      current.firstSeen = Math.min(current.firstSeen, rel.firstSeen);
      current.lastSeen = Math.max(current.lastSeen, rel.lastSeen);
    }
  return [...byIp].filter(([key]) => !conflicts.has(key)).map(([, e]) => e);
}

export function catalogServiceKeys(
  catalog: readonly CatalogRow[],
): AtlasServiceKey[] {
  return catalog
    .filter((row) => !row.scopeError && !row._key.startsWith("scope:"))
    .map(({ service, environment, cluster, namespace }) => ({
      service,
      environment,
      cluster,
      namespace,
    }));
}

/**
 * Business parents come only from imported claims whose exact v2 binding
 * resolves against a catalog row carrying qualified identity provenance.
 */
export function businessServiceParents(
  catalog: readonly CatalogRow[],
  preview: ImportPreview | undefined,
  window: { start: number; end: number },
): { parents: BusinessServiceParent[]; excluded: ExcludedItem[] } {
  if (!preview || !preview.bindings.length)
    return { parents: [], excluded: [] };
  const natives: NativeServiceIdentity[] = catalog.flatMap((row) =>
    row.identityContext && !row.scopeError
      ? [
          {
            kind: "service" as const,
            contract: "qualified_v2" as const,
            authority: row.identityContext.authority,
            scope: row.identityContext.scope,
            configRevision: row.identityContext.configRevision,
            observedWindow: row.identityContext.observedWindow,
            key: {
              service: row.service,
              environment: row.environment,
              cluster: row.cluster,
              namespace: row.namespace,
            },
          },
        ]
      : [],
  );
  const resolutions = resolveBusinessOwnership(
    preview.claims,
    preview.bindings,
    natives,
    { kind: "interval", from: window.start, to: window.end },
  );
  const excluded: ExcludedItem[] = [];
  const groups = new Map<
    string,
    {
      names: Set<string>;
      authority: string;
      serviceId: string;
      members: AtlasServiceKey[];
    }
  >();
  for (const resolution of resolutions) {
    const label = `Binding ${resolution.binding.authority}/${resolution.binding.recordId}`;
    if (
      resolution.status !== "resolved" ||
      resolution.conflict ||
      resolution.coverage === "unknown" ||
      !resolution.claim ||
      !resolution.native
    ) {
      excluded.push({
        item: label,
        reason:
          resolution.reasons[0] ??
          "The binding does not resolve to a qualified Atlas service in this window.",
      });
      continue;
    }
    const { claim, native } = resolution;
    const key = JSON.stringify([claim.authority, claim.serviceId]);
    const group = groups.get(key) ?? {
      names: new Set<string>(),
      authority: claim.authority,
      serviceId: claim.serviceId,
      members: [],
    };
    group.names.add(claim.serviceName);
    group.members.push(native.key);
    groups.set(key, group);
  }
  const parents: BusinessServiceParent[] = [];
  for (const group of groups.values()) {
    if (group.names.size !== 1) {
      excluded.push({
        item: `Business service ${group.authority}/${group.serviceId}`,
        reason: "Resolved claims disagree on the business-service name.",
      });
      continue;
    }
    parents.push({
      serviceName: [...group.names][0],
      serviceId: group.serviceId,
      authority: group.authority,
      members: group.members,
    });
  }
  return { parents, excluded };
}
