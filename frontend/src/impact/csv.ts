import { csvRow } from "../csv";
import type { Classified } from "./classify";
import { appsOf, type DependsResult, type FailsResult } from "./model";

export const IMPACT_CSV_COLUMNS = [
  "severity",
  "app",
  "src_ip",
  "src_name",
  "dst_ip",
  "dst_name",
  "dst_port",
  "protocol",
  "bytes",
  "bytes_to_listener",
  "bytes_from_listener",
  "flows",
  "alternate",
  "alternate_evidence",
  "traversal",
  "reason",
  "failed_at",
] as const;

const row = (c: Classified) => [
  c.severity,
  appsOf(c.conv)
    .map((a) => (a.basis === "hosted" ? `~${a.name}` : a.name))
    .join("; "),
  c.conv.src.ip ?? "",
  c.conv.src.name ?? "",
  c.conv.dst.ip ?? "",
  c.conv.dst.name ?? "",
  c.conv.port ?? "",
  c.conv.protocol,
  c.conv.bytes ?? "",
  c.conv.bytesFwd ?? "",
  c.conv.bytesRev ?? "",
  c.conv.flows,
  c.alternate.join("; "),
  c.alternateEvidence ?? "",
  c.traversal,
  c.reason,
  c.failedAt.join("; "),
];

/** Change-ticket export: a header comment with the headline, then one row per affected conversation. */
export function impactCsv(
  r: FailsResult | DependsResult,
  meta: { window: string; source: string; generated: string },
): string {
  const head = [
    csvRow(["# Application Atlas impact", r.headline]),
    csvRow([
      "# window",
      meta.window,
      "source",
      meta.source,
      "generated",
      meta.generated,
    ]),
  ];
  if (r.mode === "depends")
    return [
      ...head,
      csvRow([
        "effect",
        "dependency",
        "tier",
        "alternate",
        "conversations",
        "bytes",
        "evidence",
        "element",
      ]),
      ...r.rows.map((d) =>
        csvRow([
          d.severity === "outage"
            ? "single point"
            : d.severity === "degraded"
              ? "redundant"
              : "unverified",
          d.label,
          d.tier,
          d.alternate.join("; "),
          d.conversations,
          d.bytes,
          d.evidence,
          d.token,
        ]),
      ),
    ].join("\r\n");
  return [
    ...head,
    csvRow([...IMPACT_CSV_COLUMNS]),
    ...r.rows.map((c) => csvRow(row(c))),
  ].join("\r\n");
}
