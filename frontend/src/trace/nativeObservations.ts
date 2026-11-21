import type { TraceHop } from "../data/pathTrace";

/** Independent exporter observations; their display order is never a route. */
export function nativeObservationHops(
  rows: readonly unknown[],
  request: { src: string; dst: string; scope?: string },
): TraceHop[] {
  const hops: TraceHop[] = [];
  for (const value of rows) {
    if (!value || typeof value !== "object") continue;
    const row = value as Record<string, unknown>;
    if (row.row_type !== "observation" || row.flow_source !== "netflow")
      continue;
    // Historical aggregate rows can contribute counts, but cannot name a hop.
    if (row.source_profile === undefined && row.profile_status === undefined)
      continue;
    const text = (key: string) => {
      const v = row[key];
      return typeof v === "string" && v.length <= 512 ? v : "";
    };
    const number = (key: string) => {
      const v = row[key];
      return typeof v === "number" || (typeof v === "string" && v.trim())
        ? Number(v)
        : NaN;
    };
    const src = text("src"),
      dst = text("dst"),
      protocol = text("protocol"),
      exporter = text("observer_device"),
      first = number("first_seen"),
      last = number("last_seen"),
      records = number("records"),
      sport = number("src_port"),
      dport = number("dest_port");
    const forward = src === request.src && dst === request.dst;
    const reverse = src === request.dst && dst === request.src;
    if (
      !request.scope ||
      text("scope") !== request.scope ||
      text("source_profile") !== "nexus_nxos_netflow" ||
      text("profile_status") !== "mapped" ||
      !/^\d+$/.test(text("observation_domain_id")) ||
      !/^[0-9a-fA-F:.]{2,45}$/.test(exporter) ||
      (!forward && !reverse) ||
      text("direction") !== (forward ? "forward" : "reverse") ||
      !["tcp", "udp", "icmp", "ipv6-icmp"].includes(protocol) ||
      !Number.isFinite(first) ||
      !Number.isFinite(last) ||
      first < 0 ||
      last < first ||
      last > 8.64e12 ||
      !Number.isInteger(records) ||
      records < 1 ||
      ((protocol === "tcp" || protocol === "udp") &&
        (![sport, dport].every(Number.isInteger) ||
          sport < 1 ||
          sport > 65535 ||
          dport < 1 ||
          dport > 65535))
    )
      throw new Error(
        "Native path observation failed scope or tuple validation.",
      );
    const port = protocol === "tcp" || protocol === "udp";
    const ingress = text("interface_in"),
      egress = text("interface_out");
    hops.push({
      kind: "gap",
      label: "Ordering and connections between observations are unverified",
      evidence: "gap",
      sources: [],
      seen: [],
    });
    hops.push({
      kind: "switch",
      label: `Nexus exporter ${exporter}`,
      device: exporter,
      evidence: "observed",
      sources: ["Stream NetFlow"],
      seen: [ingress, egress].filter(Boolean),
      ...(ingress ? { in: ingress } : {}),
      ...(egress ? { out: egress } : {}),
      detail: `${protocol.toUpperCase()} ${src}${port ? `:${sport}` : ""} → ${dst}${port ? `:${dport}` : ""}; ${records} exported records; domain ${text("observation_domain_id")}; source timestamps ${new Date(first * 1000).toISOString()}–${new Date(last * 1000).toISOString()}. These observations do not establish adjacent hops, NAT, or a connection to another exporter.`,
      support: [
        "stream:netflow; nexus_nxos_netflow; mapped exporter/domain authority",
        ...(text("reference") ? [text("reference")] : []),
      ],
    });
  }
  const groups = new Map<string, TraceHop[]>();
  for (const hop of hops.filter((hop) => hop.kind === "switch")) {
    const key = hop.device!;
    groups.set(key, [...(groups.get(key) ?? []), hop]);
  }
  const grouped: TraceHop[] = [];
  for (const observations of groups.values()) {
    const first = observations[0];
    grouped.push(hops[0], {
      ...first,
      detail: observations.map((hop) => hop.detail).join("\n"),
      seen: [...new Set(observations.flatMap((hop) => hop.seen))],
      in:
        [...new Set(observations.map((hop) => hop.in).filter(Boolean))].join(
          ", ",
        ) || undefined,
      out:
        [...new Set(observations.map((hop) => hop.out).filter(Boolean))].join(
          ", ",
        ) || undefined,
      support: [...new Set(observations.flatMap((hop) => hop.support ?? []))],
    });
  }
  if (grouped.length)
    grouped.push({
      kind: "gap",
      label: "Remaining packet route is unverified",
      evidence: "gap",
      sources: [],
      seen: [],
    });
  return grouped;
}

/** TA-backed pair observations, kept separate from exporter tuples and captures. */
export function nativeSourceHops(
  rows: readonly unknown[],
  request: { src: string; dst: string; scope?: string },
): TraceHop[] {
  const hops: TraceHop[] = [];
  for (const value of rows) {
    if (!value || typeof value !== "object") continue;
    const r = value as Record<string, unknown>;
    if (
      r.row_type !== "observation" ||
      !["ftd", "hubble"].includes(String(r.flow_source))
    )
      continue;
    if (r.profile_status === undefined && r.source_profile === undefined)
      continue;
    const profile =
      r.flow_source === "ftd"
        ? "cisco_secure_firewall_estreamer"
        : "cilium_hubble";
    const device = r.observer_device;
    const numeric = (value: unknown) =>
      typeof value === "number" || (typeof value === "string" && value.trim())
        ? Number(value)
        : NaN;
    const first = numeric(r.first_seen),
      last = numeric(r.last_seen),
      records = numeric(r.records);
    if (
      !request.scope ||
      r.scope !== request.scope ||
      r.src !== request.src ||
      r.dst !== request.dst ||
      r.profile_status !== "mapped" ||
      r.source_profile !== profile ||
      typeof device !== "string" ||
      !/^[A-Za-z0-9_.:/-]{1,255}$/.test(device) ||
      !["forward", "reverse"].includes(String(r.direction)) ||
      !Number.isFinite(first) ||
      first < 0 ||
      !Number.isFinite(last) ||
      last < first ||
      last > 8.64e12 ||
      !Number.isInteger(records) ||
      records < 1
    )
      throw new Error(
        "Native source observation failed scope or identity validation.",
      );
    const interfaces = (value: unknown): string[] =>
      (Array.isArray(value) ? value : [value])
        .filter(
          (x): x is string =>
            typeof x === "string" && x.length > 0 && x.length <= 128,
        )
        .slice(0, 32);
    const ingress = interfaces(r.interface_in),
      egress = interfaces(r.interface_out);
    const references = interfaces(r.references);
    hops.push({
      kind: "gap",
      label: "Connection to other evidence is unverified",
      evidence: "gap",
      sources: [],
      seen: [],
    });
    hops.push({
      kind: r.flow_source === "ftd" ? "firewall" : "host",
      label: `${r.flow_source === "ftd" ? "Firewall" : "Hubble node"} ${device}`,
      device,
      evidence: "observed",
      sources: [r.flow_source === "ftd" ? "FTD eStreamer" : "Hubble"],
      seen: [...ingress, ...egress],
      ...(ingress.length ? { in: ingress.join(", ") } : {}),
      ...(egress.length ? { out: egress.join(", ") } : {}),
      detail: `${records} ${r.direction} records for IP pair ${request.src} ↔ ${request.dst}; source timestamps ${new Date(first * 1000).toISOString()}–${new Date(last * 1000).toISOString()}. This aggregate may include separate connections. It does not prove NAT, adjacent hops, or ordering with other sources.`,
      support: [profile, ...references],
    });
  }
  if (hops.length)
    hops.push({
      kind: "gap",
      label: "Remaining packet route is unverified",
      evidence: "gap",
      sources: [],
      seen: [],
    });
  return hops;
}
