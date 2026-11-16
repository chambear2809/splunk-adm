import type { Graph } from "../graph";
import { coverageReasons, validateWindow } from "../incident/model";

export interface NoteRevision {
  revision: number;
  recordedAt: string;
  notes: string;
  hypotheses: string;
  questions: string;
}
export interface PortableInvestigation {
  format: "application-atlas-investigation";
  version: 1;
  id: string;
  createdAt: string;
  captures: Array<{
    id: string;
    capturedAt: string;
    kind: "baseline" | "incident" | "recovery";
    graph: Graph;
  }>;
  revisions: NoteRevision[];
}
const LIMIT = 8 * 1024 * 1024;
const bounded = (value: string) => {
  if (value.length > 20000)
    throw new Error("Each note field is limited to 20,000 characters.");
  return value;
};

/** Detached captures survive graph refreshes and never depend on a search SID. */
export function captureComparison(
  graphs: { baseline: Graph; incident: Graph; recovery?: Graph },
  id: string,
  now = new Date().toISOString(),
): PortableInvestigation {
  if (!id.trim() || !Number.isFinite(Date.parse(now)))
    throw new Error("Capture identity or time is invalid.");
  const captures = (["baseline", "incident", "recovery"] as const).flatMap(
    (kind) => {
      const graph = graphs[kind];
      if (!graph) return [];
      validateWindow(graph.window);
      if (
        graph.boundary.id !== graphs.incident.boundary.id ||
        graph.boundary.cluster !== graphs.incident.boundary.cluster ||
        graph.boundary.namespace !== graphs.incident.boundary.namespace ||
        graph.boundary.service !== graphs.incident.boundary.service ||
        graph.boundary.environment !== graphs.incident.boundary.environment
      )
        throw new Error("Captures must share the same investigation scope.");
      return [
        {
          id: `${id}:${kind}`,
          capturedAt: now,
          kind,
          graph: JSON.parse(JSON.stringify(graph)) as Graph,
        },
      ];
    },
  );
  const draft: PortableInvestigation = {
    format: "application-atlas-investigation",
    version: 1,
    id,
    createdAt: now,
    captures,
    revisions: [],
  };
  serializeInvestigation(draft);
  return draft;
}

export function reviseNotes(
  draft: PortableInvestigation,
  values: Pick<NoteRevision, "notes" | "hypotheses" | "questions">,
  now = new Date().toISOString(),
): PortableInvestigation {
  if (draft.revisions.length >= 100)
    throw new Error("This portable record has reached its 100 revision limit.");
  if (!Number.isFinite(Date.parse(now)))
    throw new Error("Note time is invalid.");
  const next = {
    ...draft,
    revisions: [
      ...draft.revisions,
      {
        revision: draft.revisions.length + 1,
        recordedAt: now,
        notes: bounded(values.notes),
        hypotheses: bounded(values.hypotheses),
        questions: bounded(values.questions),
      },
    ],
  };
  serializeInvestigation(next);
  return next;
}

export function serializeInvestigation(draft: PortableInvestigation): string {
  const result = JSON.stringify(draft, null, 2);
  if (new TextEncoder().encode(result).length > LIMIT)
    throw new Error("The evidence package exceeds the 8 MiB export limit.");
  return result;
}

export function readableHandoff(draft: PortableInvestigation): string {
  const incident = draft.captures.find(
    (capture) => capture.kind === "incident",
  )!;
  const latest = draft.revisions.at(-1);
  return [
    `Application Atlas investigation: ${incident.graph.boundary.service}`,
    `Record: ${draft.id}`,
    `Captured: ${draft.createdAt}`,
    ...draft.captures.map(
      (capture) =>
        `${capture.kind}: ${capture.graph.window.start} – ${capture.graph.window.end} (${capture.graph.snapshot_id}; ${capture.graph.demo ? "demo evidence" : "captured source observations"})`,
    ),
    "Captured graph observations retain their original coverage warnings. Snapshot differences do not establish causation.",
    ...draft.captures.flatMap((capture) =>
      coverageReasons(capture.graph).map(
        (warning) => `${capture.kind} coverage: ${warning}`,
      ),
    ),
    `Notes (revision ${latest?.revision ?? 0}):\n${latest?.notes || "None recorded"}`,
    `Hypotheses:\n${latest?.hypotheses || "None recorded"}`,
    `Unresolved questions:\n${latest?.questions || "None recorded"}`,
    "Portable export; no shared case save or recipient access authorization has been established.",
  ].join("\n\n");
}
