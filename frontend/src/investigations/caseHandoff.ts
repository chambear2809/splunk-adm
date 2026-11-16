import type { CaseRecord } from "./caseClient";

const line = (value: string) =>
  Array.from(value.replace(/[\r\n\t]+/g, " "))
    .filter(
      (character) =>
        character.charCodeAt(0) >= 32 && character.charCodeAt(0) !== 127,
    )
    .map((character) =>
      "\\`*_{}[]<>#|".includes(character) ? `\\${character}` : character,
    )
    .join("");
const instant = (value: unknown) =>
  typeof value === "number" &&
  Number.isFinite(value) &&
  Math.abs(value) <= 8640000000000
    ? new Date(value * 1000).toISOString()
    : "Unavailable";

/** Formats only the freshly authorized case projection; source rows are omitted. */
export function caseHandoff(record: CaseRecord): string {
  const output = [
    `# ${line(record.title)}`,
    `Case: ${line(record.id)} · Revision: ${record.revision}`,
    `Case window: ${line(record.window.start)} – ${line(record.window.end)}`,
    "",
    "## Investigation entries",
  ];
  if (!record.entries.length) output.push("No visible entries.");
  for (const entry of record.entries) {
    output.push(
      `- ${line(entry.type)} · ${line(entry.author)} · revision ${entry.revision} · ${line(entry.created_at)}`,
    );
    for (const textLine of entry.text.split(/\r?\n/))
      output.push(`  > ${line(textLine)}`);
  }
  output.push("", "## Permitted comparison captures");
  if (!record.captures.length) output.push("No visible captures.");
  for (const capture of record.captures) {
    output.push(
      `- ${line(capture.label)} · captured ${line(capture.captured_at)} · revision ${capture.revision}`,
    );
    const data = capture.data;
    if (typeof data.source_contract === "string")
      output.push(`  - Source contract: ${line(data.source_contract)}`);
    else output.push("  - Source contract unavailable.");
    if (data.source_contract === "admqualified-comparison-v1")
      output.push(
        "  - Observations were indexed by each window end; later arrivals are excluded. Exact indexed times are not retained for all aggregates.",
      );
    if (
      data.scope &&
      typeof data.scope === "object" &&
      !Array.isArray(data.scope)
    ) {
      const scope = data.scope as Record<string, unknown>;
      for (const key of ["service", "environment", "cluster", "namespace"])
        if (typeof scope[key] === "string")
          output.push(`  - ${key}: ${line(scope[key])}`);
    }
    if (Array.isArray(data.windows))
      data.windows.forEach((window: unknown, i: number) => {
        if (!window || typeof window !== "object") return;
        const item = window as Record<string, unknown>;
        output.push(
          `  - ${["Baseline", "Incident", "Recovery"][i] ?? "Window"}: ${instant(item.start)} – ${instant(item.end)} UTC`,
        );
        const meta = Array.isArray(item.rows)
          ? (item.rows.find(
              (row: unknown) =>
                row &&
                typeof row === "object" &&
                (row as Record<string, unknown>).row_type === "meta",
            ) as Record<string, unknown> | undefined)
          : undefined;
        if (meta) {
          const warnings =
            typeof meta.warnings === "string"
              ? [meta.warnings]
              : Array.isArray(meta.warnings)
                ? meta.warnings.filter(
                    (warning: unknown): warning is string =>
                      typeof warning === "string",
                  )
                : [];
          for (const warning of warnings)
            output.push(`    - Coverage warning: ${line(warning)}`);
          for (const key of [
            "read_coverage",
            "raw_pending_seconds",
            "truncated",
            "capped",
            "truncation",
          ]) {
            const value = meta[key];
            if (
              typeof value === "string" ||
              typeof value === "boolean" ||
              (typeof value === "number" && Number.isFinite(value))
            )
              output.push(`    - Reported ${key}: ${line(String(value))}`);
          }
        }
        output.push("    - Unreported coverage details are unknown.");
      });
    output.push(
      "  - Raw source rows are omitted from this handoff. Coverage beyond the stated source contract is not established here.",
    );
  }
  output.push("", "## Access and gaps");
  if (record.redactions)
    output.push(
      `${record.redactions.captures} captures and ${record.redactions.attachments} attachments withheld from this response; they may be unselected or source access could not be confirmed.`,
    );
  else output.push("Redaction counts unavailable.");
  output.push(
    "Case membership does not grant source access. This handoff may contain sensitive investigation details.",
    "",
  );
  return output.join("\n");
}
