import { canonicalJson, HASH_ID, sha256Hex } from "./canonicalJson";
import type {
  CapturedDependencyBinding,
  ChangeAttribution,
  ChangeAttributionChain,
  ChangeHistoryRow,
  ChangeRelationshipLink,
  ChangeTimelineContext,
  ChangeTimelineWindow,
  QualifiedChangeIdentity,
} from "./types";

export const MAX_ATTRIBUTION_LINKS = 500;
export const MAX_ATTRIBUTION_DEPTH = 8;
export const MAX_ATTRIBUTION_CHAINS = 200;
export const MAX_ATTRIBUTION_STEPS = 5_000;
export const MAX_BINDING_RECEIPTS = 100;
export const CAPTURED_DEPENDENCY_AUTHORITY = "atlas:observed_dependency";
export const CAPTURED_DEPENDENCY_TYPE = "captured_dependency";
export const CAPTURED_DEPENDENCY_PREFIX = "captured_dependency:";
export const CAPTURED_RECEIPT_BASIS = "query_input_coverage_v1";

const MAX_EPOCH = 253_402_300_799;
const MAX_CHANGE_WINDOW_SECONDS = 86_400;
const BASE_RELATIONSHIP_FIELDS = [
  "basis",
  "evidence_id",
  "from_authority",
  "from_id",
  "from_type",
  "scope",
  "to_authority",
  "to_id",
  "to_type",
  "valid_from",
  "valid_to",
].sort();
const ADMIN_RELATIONSHIP_FIELDS = [
  ...BASE_RELATIONSHIP_FIELDS,
  "actor",
  "attestation_version",
  "generation_id",
  "issuer",
  "proof",
  "proof_qualification",
  "qualification",
  "record_id",
  "semantics",
  "source_refs",
  "source_version",
  "target_binding",
].sort();
const ADMIN_ATTRIBUTE_FIELDS = [
  "from_authority",
  "from_type",
  "from_id",
  "to_authority",
  "to_type",
  "to_id",
  "scope",
  "valid_from",
  "valid_to",
  "evidence_id",
  "basis",
  "semantics",
  "issuer",
  "attestation_version",
  "proof",
  "proof_qualification",
  "qualification",
  "binding_scenario_id",
  "binding_execution_id",
  "binding_graph_result_key",
  "binding_graph_result_sha256",
  "binding_edge_id",
  "binding_scope",
  "binding_query_sha256",
  "binding_receipt_basis",
  "binding_query_input_coverage_sha256",
  "binding_active_traffic_contract_sha256",
  "binding_window_earliest",
  "binding_window_latest",
  "binding_receipt_fingerprints",
].sort();
const REFERENCE_FIELDS = [
  "authority",
  "identity_type",
  "scenario_id",
  "execution_id",
  "graph_result_key",
  "graph_result_sha256",
  "edge_id",
  "scope",
  "window",
  "query_sha256",
  "receipt_basis",
  "query_input_coverage_sha256",
  "active_traffic_contract_sha256",
  "receipt_fingerprints",
].sort();
const HASH_CHARS = /^[a-f0-9]{64}$/;

type RelationshipStatus = {
  relationships: ChangeRelationshipLink[];
  complete: boolean;
  reason: string | null;
};

const object = (value: unknown): Record<string, unknown> | undefined =>
  value && typeof value === "object" && !Array.isArray(value)
    ? (value as Record<string, unknown>)
    : undefined;

function exactKeys(
  value: Record<string, unknown>,
  keys: readonly string[],
  label: string,
) {
  const actual = Object.keys(value).sort();
  if (
    actual.length !== keys.length ||
    actual.some((key, index) => key !== keys[index])
  )
    throw new Error(`${label} has an unsupported field shape.`);
}

function text(value: unknown, label: string, max = 512): string {
  if (
    typeof value !== "string" ||
    value.length === 0 ||
    value.length > max ||
    Array.from(value).some(
      (character) =>
        character.charCodeAt(0) < 32 || character.charCodeAt(0) === 127,
    )
  )
    throw new Error(`${label} is invalid.`);
  return value;
}

function timestamp(value: unknown, label: string): number {
  if (
    typeof value !== "number" ||
    !Number.isFinite(value) ||
    value < 0 ||
    value > MAX_EPOCH
  )
    throw new Error(`${label} is outside the supported range.`);
  canonicalJson(value);
  return value;
}

function hash(value: unknown, label: string): string {
  const result = text(value, label, 64);
  if (!HASH_ID.test(result))
    throw new Error(`${label} must be lowercase SHA-256 hex.`);
  return result;
}

function identity(value: unknown, label: string): QualifiedChangeIdentity {
  const record = object(value);
  if (!record) throw new Error(`${label} is invalid.`);
  exactKeys(record, ["authority", "type", "id"].sort(), label);
  return {
    authority: text(record.authority, `${label} authority`),
    type: text(record.type, `${label} type`),
    id: text(record.id, `${label} ID`),
  };
}

export function normalizeCapturedDependencyBinding(
  value: unknown,
): CapturedDependencyBinding {
  const binding = object(value);
  if (!binding) throw new Error("Captured dependency binding is invalid.");
  exactKeys(binding, REFERENCE_FIELDS, "Captured dependency binding");
  if (
    binding.authority !== CAPTURED_DEPENDENCY_AUTHORITY ||
    binding.identity_type !== CAPTURED_DEPENDENCY_TYPE
  )
    throw new Error("Captured dependency identity is unsupported.");
  const window = object(binding.window);
  if (!window) throw new Error("Captured dependency window is invalid.");
  exactKeys(
    window,
    ["earliest", "latest"].sort(),
    "Captured dependency window",
  );
  const earliest = timestamp(window.earliest, "Captured dependency start");
  const latest = timestamp(window.latest, "Captured dependency end");
  if (earliest >= latest || latest - earliest > MAX_CHANGE_WINDOW_SECONDS)
    throw new Error("Captured dependency window is unsupported.");
  if (
    !Array.isArray(binding.receipt_fingerprints) ||
    binding.receipt_fingerprints.length === 0 ||
    binding.receipt_fingerprints.length > MAX_BINDING_RECEIPTS
  )
    throw new Error("Captured dependency receipts are incomplete.");
  const receipts = binding.receipt_fingerprints.map((item, index) =>
    hash(item, `Indexed receipt fingerprint ${index + 1}`),
  );
  if (receipts.some((item, index) => index > 0 && receipts[index - 1] >= item))
    throw new Error("Captured dependency receipts must be sorted and unique.");
  const receiptBasis = text(
    binding.receipt_basis,
    "Captured receipt basis",
    64,
  );
  if (receiptBasis !== CAPTURED_RECEIPT_BASIS)
    throw new Error("Captured dependency receipt basis is unsupported.");
  const normalized: CapturedDependencyBinding = {
    authority: CAPTURED_DEPENDENCY_AUTHORITY,
    identity_type: CAPTURED_DEPENDENCY_TYPE,
    scenario_id: text(binding.scenario_id, "Captured scenario ID"),
    execution_id: text(binding.execution_id, "Captured execution ID"),
    graph_result_key: text(
      binding.graph_result_key,
      "Captured graph result key",
    ),
    graph_result_sha256: hash(
      binding.graph_result_sha256,
      "Captured graph result SHA-256",
    ),
    edge_id: text(binding.edge_id, "Captured graph edge ID"),
    scope: text(binding.scope, "Captured routing scope"),
    window: { earliest, latest },
    query_sha256: hash(binding.query_sha256, "Captured query SHA-256"),
    receipt_basis: CAPTURED_RECEIPT_BASIS,
    query_input_coverage_sha256: hash(
      binding.query_input_coverage_sha256,
      "Captured query input coverage SHA-256",
    ),
    active_traffic_contract_sha256: hash(
      binding.active_traffic_contract_sha256,
      "Active traffic contract SHA-256",
    ),
    receipt_fingerprints: receipts,
  };
  return normalized;
}

/** Shared by capture tooling and retained-generation validation. */
export async function capturedDependencyIdentity(
  value: unknown,
): Promise<QualifiedChangeIdentity & { binding: CapturedDependencyBinding }> {
  const binding = normalizeCapturedDependencyBinding(value);
  return {
    authority: CAPTURED_DEPENDENCY_AUTHORITY,
    type: CAPTURED_DEPENDENCY_TYPE,
    id: `${CAPTURED_DEPENDENCY_PREFIX}${await sha256Hex(canonicalJson(binding))}`,
    binding,
  };
}

function bindingFromAttributes(
  value: Record<string, unknown>,
): CapturedDependencyBinding {
  return normalizeCapturedDependencyBinding({
    authority: CAPTURED_DEPENDENCY_AUTHORITY,
    identity_type: CAPTURED_DEPENDENCY_TYPE,
    scenario_id: value.binding_scenario_id,
    execution_id: value.binding_execution_id,
    graph_result_key: value.binding_graph_result_key,
    graph_result_sha256: value.binding_graph_result_sha256,
    edge_id: value.binding_edge_id,
    scope: value.binding_scope,
    window: {
      earliest: value.binding_window_earliest,
      latest: value.binding_window_latest,
    },
    query_sha256: value.binding_query_sha256,
    receipt_basis: value.binding_receipt_basis,
    query_input_coverage_sha256: value.binding_query_input_coverage_sha256,
    active_traffic_contract_sha256:
      value.binding_active_traffic_contract_sha256,
    receipt_fingerprints: value.binding_receipt_fingerprints,
  });
}

async function fromPersistedRow(
  row: ChangeHistoryRow,
): Promise<ChangeRelationshipLink> {
  if (
    row.product !== "atlas" ||
    row.family !== "relationship_attestation" ||
    row.authority !== "atlas:administrator_attestation" ||
    row.partition !== "administrator_relationship_attestations" ||
    row.record_type !== "observation" ||
    row.kind !== "operational" ||
    row.context_only !== true ||
    row.coverage_complete !== true ||
    row.gap !== false ||
    row.native_sample_unqualified !== true ||
    row.projection_qualification !== "administrator_attestation_unqualified" ||
    row.time_qualification !== "unknown_source_time" ||
    row.clock_uncertainty_unknown !== true ||
    row.earliest_at !== null ||
    row.latest_at !== null ||
    row.actor === null ||
    row.source_version === null ||
    row.object_id === null
  )
    throw new Error("Retained administrator relationship row is malformed.");
  hash(row.record_id, "Relationship row ID");
  hash(row.generation_id, "Relationship generation ID");
  const fields = object(row.attributes);
  if (!fields) throw new Error("Retained relationship attributes are invalid.");
  exactKeys(fields, ADMIN_ATTRIBUTE_FIELDS, "Retained relationship attributes");
  const binding = bindingFromAttributes(fields);
  const target = await capturedDependencyIdentity(binding);
  if (
    fields.basis !== "administrator_attestation" ||
    fields.semantics !== "potential_dependency" ||
    fields.proof_qualification !== "administrator_supplied_unverified" ||
    ![
      "owned_local_lab_admin_unqualified",
      "synthetic_admin_artifact_unqualified",
    ].includes(String(fields.qualification)) ||
    fields.to_authority !== target.authority ||
    fields.to_type !== target.type ||
    fields.to_id !== target.id ||
    fields.scope !== binding.scope ||
    row.object_id !== fields.evidence_id
  )
    throw new Error(
      "Retained administrator relationship proof is inconsistent.",
    );
  const refs = [...row.source_refs];
  if (refs.some((item, index) => index > 0 && refs[index - 1] >= item))
    throw new Error("Retained relationship source references are invalid.");
  return {
    from_authority: text(
      fields.from_authority,
      "Relationship source authority",
    ),
    from_type: text(fields.from_type, "Relationship source type"),
    from_id: text(fields.from_id, "Relationship source ID"),
    to_authority: target.authority,
    to_type: target.type,
    to_id: target.id,
    scope: text(fields.scope, "Relationship scope"),
    valid_from: timestamp(fields.valid_from, "Relationship validity start"),
    valid_to: timestamp(fields.valid_to, "Relationship validity end"),
    evidence_id: text(fields.evidence_id, "Relationship evidence ID"),
    basis: "administrator_attestation",
    semantics: "potential_dependency",
    issuer: text(fields.issuer, "Administrator issuer"),
    source_version: row.source_version,
    attestation_version: text(
      fields.attestation_version,
      "Attestation version",
    ),
    proof: text(fields.proof, "Administrator proof reference"),
    proof_qualification: "administrator_supplied_unverified",
    actor: text(row.actor, "Administrator actor"),
    qualification:
      fields.qualification as ChangeRelationshipLink["qualification"],
    target_binding: binding,
    generation_id: row.generation_id,
    record_id: row.record_id,
    source_refs: refs,
  };
}

/**
 * Extract administrator links from the fully validated generation, before a
 * caller applies its selected display window. A malformed/conflicting set is
 * suppressed as a whole so no partial blast radius is presented as complete.
 */
export async function extractRetainedRelationships(
  rows: ChangeHistoryRow[],
  generationId: string,
): Promise<RelationshipStatus> {
  try {
    const candidates = rows.filter(
      (row) =>
        row.product === "atlas" && row.family === "relationship_attestation",
    );
    if (candidates.length > MAX_ATTRIBUTION_LINKS)
      throw new Error("relationship_limit");
    const byEvidenceId = new Map<string, ChangeRelationshipLink>();
    const signatures = new Map<string, string>();
    for (const row of candidates) {
      if (row.generation_id !== generationId)
        throw new Error("mixed_relationship_generation");
      const link = validateRelationship(await fromPersistedRow(row));
      if (link.valid_from >= link.valid_to)
        throw new Error("invalid_relationship_time");
      const signature = canonicalJson(link);
      const previous = signatures.get(link.evidence_id);
      if (previous !== undefined && previous !== signature)
        throw new Error("conflicting_relationship_identity");
      signatures.set(link.evidence_id, signature);
      byEvidenceId.set(link.evidence_id, link);
    }
    return {
      relationships: [...byEvidenceId.entries()]
        .sort(([left], [right]) => left.localeCompare(right))
        .map(([, value]) => value),
      complete: true,
      reason: null,
    };
  } catch (cause) {
    const message =
      cause instanceof Error ? cause.message : "invalid_relationship";
    return { relationships: [], complete: false, reason: message };
  }
}

function validateRelationship(value: unknown): ChangeRelationshipLink {
  const record = object(value);
  if (!record) throw new Error("A retained relationship is invalid.");
  const keys = Object.keys(record).sort();
  const isAdmin =
    keys.length === ADMIN_RELATIONSHIP_FIELDS.length &&
    keys.every((key, index) => key === ADMIN_RELATIONSHIP_FIELDS[index]);
  if (!isAdmin)
    exactKeys(record, BASE_RELATIONSHIP_FIELDS, "Retained relationship");
  const basis = text(record.basis, "Relationship basis");
  if (basis !== "native" && basis !== "administrator_attestation")
    throw new Error("A retained relationship has an unsupported basis.");
  if ((basis === "administrator_attestation") !== isAdmin)
    throw new Error(
      "Administrator relationship proof is missing or unexpected.",
    );
  const link: ChangeRelationshipLink = {
    from_authority: text(
      record.from_authority,
      "Relationship source authority",
    ),
    from_type: text(record.from_type, "Relationship source type"),
    from_id: text(record.from_id, "Relationship source ID"),
    to_authority: text(record.to_authority, "Relationship target authority"),
    to_type: text(record.to_type, "Relationship target type"),
    to_id: text(record.to_id, "Relationship target ID"),
    scope: text(record.scope, "Relationship scope"),
    valid_from: timestamp(record.valid_from, "Relationship validity start"),
    valid_to: timestamp(record.valid_to, "Relationship validity end"),
    evidence_id: text(record.evidence_id, "Relationship evidence ID"),
    basis,
  };
  if (link.valid_from >= link.valid_to)
    throw new Error("A retained relationship has an empty validity interval.");
  if (isAdmin) {
    const binding = normalizeCapturedDependencyBinding(record.target_binding);
    const refs = record.source_refs;
    if (
      record.semantics !== "potential_dependency" ||
      record.proof_qualification !== "administrator_supplied_unverified" ||
      ![
        "owned_local_lab_admin_unqualified",
        "synthetic_admin_artifact_unqualified",
      ].includes(String(record.qualification)) ||
      record.to_authority !== CAPTURED_DEPENDENCY_AUTHORITY ||
      record.to_type !== CAPTURED_DEPENDENCY_TYPE ||
      record.scope !== binding.scope ||
      !Array.isArray(refs) ||
      refs.length > 64 ||
      refs.some((item) => typeof item !== "string") ||
      refs.some((item, index) => index > 0 && refs[index - 1] >= item)
    )
      throw new Error("A retained administrator relationship is incomplete.");
    link.semantics = "potential_dependency";
    link.issuer = text(record.issuer, "Administrator issuer");
    link.source_version = text(
      record.source_version,
      "Attestation source version",
    );
    link.attestation_version = text(
      record.attestation_version,
      "Attestation version",
    );
    link.proof = text(record.proof, "Administrator proof reference");
    link.proof_qualification = "administrator_supplied_unverified";
    link.actor = text(record.actor, "Administrator actor");
    link.qualification =
      record.qualification as ChangeRelationshipLink["qualification"];
    link.target_binding = binding;
    link.generation_id = hash(
      record.generation_id,
      "Relationship generation ID",
    );
    link.record_id = hash(record.record_id, "Relationship row ID");
    link.source_refs = refs as string[];
  }
  return link;
}

const identityKey = (value: QualifiedChangeIdentity): string =>
  canonicalJson([value.authority, value.type, value.id]);

function capturedDependency(value: QualifiedChangeIdentity) {
  return (
    value.authority === CAPTURED_DEPENDENCY_AUTHORITY &&
    value.type === CAPTURED_DEPENDENCY_TYPE &&
    value.id.startsWith(CAPTURED_DEPENDENCY_PREFIX) &&
    HASH_CHARS.test(value.id.slice(CAPTURED_DEPENDENCY_PREFIX.length))
  );
}

function attribution(
  attributionClass: ChangeAttribution["attribution_class"],
  reason: string,
  chains: ChangeAttributionChain[] = [],
): ChangeAttribution {
  return {
    attribution_class: attributionClass,
    reason,
    chain: chains[0]?.links ?? [],
    chains,
  };
}

/** Caller context is accepted only as pre-verified authority-qualified evidence. */
export function attributeChangeRow(
  row: ChangeHistoryRow,
  view: { scope: string; window: ChangeTimelineWindow },
  context?: ChangeTimelineContext,
  retainedRelationships: ChangeRelationshipLink[] = [],
  retainedRelationshipsComplete = true,
  retainedRelationshipsReason?: string | null,
): ChangeAttribution {
  const empty = (reason: string) => attribution("context_only", reason);
  if (row.scope !== view.scope)
    return attribution("excluded", "different_verified_scope");
  if (row.context_only) return empty("source_projection_context_only");
  if (row.record_type !== "change")
    return empty("no_qualified_relationship_chain");
  if (
    row.earliest_at === null ||
    row.latest_at === null ||
    row.latest_at - row.earliest_at > MAX_CHANGE_WINDOW_SECONDS ||
    row.earliest_at > row.latest_at
  )
    return empty("unknown_or_overwide_change_interval");
  if (row.earliest_at >= view.window.end || row.latest_at < view.window.start)
    return attribution("excluded", "outside_selected_interval");
  if (row.object_id === null) return empty("no_qualified_relationship_chain");

  let selectedObjects: QualifiedChangeIdentity[];
  let observedDependencies: QualifiedChangeIdentity[];
  let links: ChangeRelationshipLink[];
  try {
    selectedObjects = (context?.selectedObjects ?? []).map((item) =>
      identity(item, "Selected object identity"),
    );
    observedDependencies = (context?.observedDependencies ?? []).map((item) => {
      const normalized = identity(item, "Observed dependency identity");
      if (!capturedDependency(normalized))
        throw new Error("Observed dependency has no captured graph proof.");
      return normalized;
    });
    links = [
      ...retainedRelationships,
      ...(context?.relationshipsVerified === true
        ? (context.relationships ?? [])
        : []),
    ].map(validateRelationship);
  } catch {
    return empty("no_qualified_relationship_chain");
  }
  if (!retainedRelationshipsComplete)
    return empty(
      retainedRelationshipsReason ?? "relationship_evidence_incomplete",
    );
  if (
    links.length > MAX_ATTRIBUTION_LINKS ||
    selectedObjects.length + observedDependencies.length > MAX_ATTRIBUTION_LINKS
  )
    return empty("relationship_limit");
  const origin: QualifiedChangeIdentity = {
    authority: row.authority,
    type: row.family,
    id: row.object_id,
  };
  const originKey = identityKey(origin);
  const selected = new Set(selectedObjects.map(identityKey));
  const dependencies = new Set(observedDependencies.map(identityKey));
  const intervalReason =
    row.earliest_at < view.window.start || row.latest_at >= view.window.end
      ? "overlapping_change_interval"
      : "qualified_object_reference";
  if (selected.has(originKey))
    return attribution("direct_object", intervalReason);

  const linkByEvidenceId = new Map<string, ChangeRelationshipLink>();
  const signatureByEvidenceId = new Map<string, string>();
  for (const link of links) {
    const signature = canonicalJson(link);
    const previous = signatureByEvidenceId.get(link.evidence_id);
    if (previous !== undefined && previous !== signature)
      return empty("conflicting_relationship_identity");
    signatureByEvidenceId.set(link.evidence_id, signature);
    linkByEvidenceId.set(link.evidence_id, link);
  }

  const graph = new Map<
    string,
    {
      target: string;
      identity: QualifiedChangeIdentity;
      link: ChangeRelationshipLink;
    }[]
  >();
  const allScopeGraph = new Map<string, string[]>();
  const partialSources: string[] = [];
  for (const link of linkByEvidenceId.values()) {
    if (link.scope !== view.scope) continue;
    const from = identityKey({
      authority: link.from_authority,
      type: link.from_type,
      id: link.from_id,
    });
    const targetIdentity = {
      authority: link.to_authority,
      type: link.to_type,
      id: link.to_id,
    };
    const target = identityKey(targetIdentity);
    const allEdges = allScopeGraph.get(from) ?? [];
    allEdges.push(target);
    allScopeGraph.set(from, allEdges);
    if (link.valid_from > row.earliest_at || link.valid_to <= row.latest_at) {
      partialSources.push(from);
      continue;
    }
    const edges = graph.get(from) ?? [];
    edges.push({ target, identity: targetIdentity, link });
    graph.set(from, edges);
  }
  for (const edges of graph.values())
    edges.sort((left, right) =>
      left.link.evidence_id.localeCompare(right.link.evidence_id),
    );

  const matches = new Map<string, ChangeAttributionChain>();
  const stack: {
    node: string;
    pathNodes: Set<string>;
    links: ChangeRelationshipLink[];
  }[] = [{ node: originKey, pathNodes: new Set([originKey]), links: [] }];
  let truncated = false;
  let steps = 0;
  while (stack.length && !truncated) {
    const current = stack.pop()!;
    for (const edge of graph.get(current.node) ?? []) {
      steps += 1;
      if (steps > MAX_ATTRIBUTION_STEPS) {
        truncated = true;
        break;
      }
      if (current.pathNodes.has(edge.target)) continue;
      const nextLinks = [...current.links, edge.link];
      const targetClass = dependencies.has(edge.target)
        ? "observed_dependency"
        : selected.has(edge.target)
          ? "selected_object"
          : undefined;
      if (targetClass) {
        const key = canonicalJson([
          edge.identity.authority,
          edge.identity.type,
          edge.identity.id,
          nextLinks.map((link) => link.evidence_id),
        ]);
        matches.set(key, {
          target: edge.identity,
          target_class: targetClass,
          links: nextLinks,
        });
        if (matches.size > MAX_ATTRIBUTION_CHAINS) {
          truncated = true;
          break;
        }
      }
      const outgoing = graph.get(edge.target) ?? [];
      if (nextLinks.length >= MAX_ATTRIBUTION_DEPTH) {
        if (
          outgoing.some((candidate) => !current.pathNodes.has(candidate.target))
        ) {
          truncated = true;
          break;
        }
        continue;
      }
      const pathNodes = new Set(current.pathNodes);
      pathNodes.add(edge.target);
      stack.push({ node: edge.target, pathNodes, links: nextLinks });
    }
  }
  if (truncated) return empty("relationship_traversal_incomplete");

  const reachable = new Set([originKey]);
  const todo = [originKey];
  while (todo.length) {
    const node = todo.pop()!;
    for (const target of allScopeGraph.get(node) ?? []) {
      if (!reachable.has(target)) {
        reachable.add(target);
        todo.push(target);
      }
    }
  }
  const partialReachable = partialSources.some((source) =>
    reachable.has(source),
  );
  const chains = [...matches.values()].sort((left, right) => {
    const leftTarget = identityKey(left.target);
    const rightTarget = identityKey(right.target);
    return (
      leftTarget.localeCompare(rightTarget) ||
      left.links
        .map((link) => link.evidence_id)
        .join("\u0000")
        .localeCompare(
          right.links.map((link) => link.evidence_id).join("\u0000"),
        )
    );
  });
  if (!chains.length)
    return empty(
      partialReachable
        ? "relationship_validity_incomplete"
        : "no_qualified_relationship_chain",
    );
  return attribution(
    chains.some((chain) => chain.target_class === "observed_dependency")
      ? "observed_dependency"
      : "direct_object",
    intervalReason,
    chains,
  );
}
