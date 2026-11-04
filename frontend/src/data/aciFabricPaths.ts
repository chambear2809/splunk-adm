import type {
  AciFabricDevice,
  AciFabricLink,
  AciFabricSnapshot,
} from "./aciFabric";

export const MAX_PATH_HOPS = 6;
export const MAX_CANDIDATE_PATHS = 64;
export const MAX_PATH_EXPANSIONS = 100_000;

export interface AciFabricPath {
  devices: AciFabricDevice[];
  links: AciFabricLink[];
}

export interface AciFabricPathResult {
  paths: AciFabricPath[];
  truncated: boolean;
  reason?: string;
}

const switchRole = (device: AciFabricDevice) =>
  device.role === "leaf" || device.role === "spine";

/** Enumerate bounded physical-switch candidates; this never asserts traversal. */
export function enumerateAciFabricPaths(
  snapshot: AciFabricSnapshot,
  sourceId: string,
  destinationId: string,
): AciFabricPathResult {
  const byId = new Map(snapshot.devices.map((device) => [device.id, device]));
  const source = byId.get(sourceId);
  const destination = byId.get(destinationId);
  if (
    !source ||
    !destination ||
    !switchRole(source) ||
    !switchRole(destination)
  )
    return {
      paths: [],
      truncated: false,
      reason: "Select two qualified leaf or spine devices.",
    };

  const linksByKey = new Map<string, AciFabricLink>();
  const endpointIds = new Set(
    snapshot.devices.filter(switchRole).map((device) => device.id),
  );
  for (const link of snapshot.links) {
    if (!endpointIds.has(link.source) || !endpointIds.has(link.target))
      continue;
    const a = `${link.source}\u001f${link.source_interface ?? ""}`;
    const b = `${link.target}\u001f${link.target_interface ?? ""}`;
    const key = [a, b].sort().join("\u001e");
    if (!linksByKey.has(key)) linksByKey.set(key, link);
  }
  const adjacency = new Map<
    string,
    { device: string; link: AciFabricLink }[]
  >();
  for (const link of linksByKey.values()) {
    adjacency.set(link.source, [
      ...(adjacency.get(link.source) ?? []),
      { device: link.target, link },
    ]);
    adjacency.set(link.target, [
      ...(adjacency.get(link.target) ?? []),
      { device: link.source, link },
    ]);
  }
  if (sourceId === destinationId)
    return { paths: [{ devices: [source], links: [] }], truncated: false };

  const paths: AciFabricPath[] = [];
  let truncated = false;
  let reason: string | undefined;
  let expansions = 0;
  const visit = (
    current: string,
    seen: Set<string>,
    devices: AciFabricDevice[],
    links: AciFabricLink[],
  ) => {
    if (expansions >= MAX_PATH_EXPANSIONS) {
      truncated = true;
      reason =
        "Search expansion budget reached; additional candidates were not explored.";
      return;
    }
    if (paths.length >= MAX_CANDIDATE_PATHS) {
      truncated = true;
      reason ??=
        "Candidate path display bound reached; additional candidates were not shown.";
      return;
    }
    if (links.length >= MAX_PATH_HOPS) {
      if (current !== destinationId) {
        truncated = true;
        reason ??=
          "Maximum candidate path depth reached; longer paths were not explored.";
      }
      return;
    }
    for (const next of adjacency.get(current) ?? []) {
      expansions += 1;
      if (expansions > MAX_PATH_EXPANSIONS) {
        truncated = true;
        reason =
          "Search expansion budget reached; additional candidates were not explored.";
        return;
      }
      if (seen.has(next.device)) continue;
      const nextDevice = byId.get(next.device);
      if (!nextDevice) continue;
      const nextDevices = [...devices, nextDevice];
      const nextLinks = [...links, next.link];
      if (next.device === destinationId) {
        paths.push({ devices: nextDevices, links: nextLinks });
        if (paths.length >= MAX_CANDIDATE_PATHS) {
          truncated = true;
          reason ??=
            "Candidate path display bound reached; additional candidates were not shown.";
          return;
        }
      } else {
        visit(
          next.device,
          new Set(seen).add(next.device),
          nextDevices,
          nextLinks,
        );
      }
    }
  };
  visit(sourceId, new Set([sourceId]), [source], []);
  paths.sort(
    (a, b) =>
      a.links.length - b.links.length ||
      a.links
        .map((link) => link.id)
        .join("\u001f")
        .localeCompare(b.links.map((link) => link.id).join("\u001f")),
  );
  return { paths, truncated, ...(reason ? { reason } : {}) };
}
