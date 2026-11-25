import { describe, expect, it, vi } from "vitest";
import type { RunResult, SearchClient } from "../data/searchClient";
import projectedNumbersGolden from "../../../fixtures/change-correlation/shared/projected_numbers_python_v1.json";
import activationGolden from "../../../fixtures/change-correlation/shared/activation_python_v1.json";

// Keep the history unit suite independent of the retired general demo provider
// fixtures. These history tests inject a SearchClient and only need the routing
// scope validator from the much broader evidence module.
vi.mock("../provider", () => ({
  splunkErrors: () => [],
  splunkWarnings: () => [],
}));
vi.mock("../data/evidence", () => ({
  routingScope(value: string) {
    if (
      typeof value !== "string" ||
      !/^[A-Za-z0-9][A-Za-z0-9._:/@-]{0,252}$/.test(value) ||
      /^(unmapped|unknown|reserved)(:|$)/i.test(value)
    )
      throw new Error("Choose one verified routing scope.");
    return value;
  },
}));
import {
  attributeChangeRow,
  buildChangeActivationSearch,
  buildChangeGenerationSearch,
  countTimelineExclusions,
  filterTimelineRows,
  loadChangeActivation,
  loadChangeTimeline,
  validateChangeActivation,
  validateCapturedChangeTimeline,
} from "./history";
import {
  canonicalJson,
  parseCanonicalJson,
  sha256Hex,
  withoutKeys,
} from "./canonicalJson";
import type {
  ChangeGenerationActivation,
  ChangeGenerationManifest,
  ChangeHistoryRow,
} from "./types";

const BASELINE_ID =
  "032f2eeca805db5569e9bc15554d5020ef0034db318b14b1501544a658ee048e";
const CHANGE_ID =
  "f1c05b5894ccffd683b0325152d73abfd4848d5897f3eba2641309b7c1bc848c";
const GENERATION_ID =
  "c1fe8e313015597cdbaee96e40e6ff83a84dc4940ffabbe95db6fd5811e91ac6";
const ROWS_SHA256 =
  "f46a8316fcf792c454835a2409121af6e1e0c7149e7b8fda2715d9a6d621bbae";

function baselineRow(): ChangeHistoryRow {
  return {
    actor: null,
    attributes: {},
    authority: "cluster:prod-east",
    change_type: "baseline",
    clock_uncertainty_unknown: false,
    context_only: false,
    coverage_complete: true,
    earliest_at: 1000,
    effective_at: null,
    event_at: null,
    family: "service_snapshot",
    field_diffs: [],
    gap: false,
    generation_id: GENERATION_ID,
    kind: null,
    latest_at: 1010,
    native_sample_unqualified: true,
    object_id: null,
    observed_at: null,
    partition: "cluster-prod-east",
    permissions_fingerprint: "perm-a",
    product: "kubernetes",
    projection_qualification: "normalized_export_only",
    qualification: "complete_baseline:initial",
    received_at: 1011,
    record_id: BASELINE_ID,
    record_type: "baseline",
    revision: null,
    schema_version: 1,
    scope: "prod-east",
    source_refs: ["capture:cap-1", "snapshot:cap-1"],
    source_version: "1.0",
    time_qualification: "collection_interval",
  };
}

function changedRow(): ChangeHistoryRow {
  return {
    actor: null,
    attributes: {},
    authority: "cluster:prod-east",
    change_type: "modified",
    clock_uncertainty_unknown: false,
    context_only: false,
    coverage_complete: true,
    earliest_at: 1000,
    effective_at: null,
    event_at: null,
    family: "service_snapshot",
    field_diffs: [
      {
        after: "LoadBalancer",
        after_present: true,
        before: "ClusterIP",
        before_present: true,
        field: "service_type",
      },
    ],
    gap: false,
    generation_id: GENERATION_ID,
    kind: "configuration",
    latest_at: 1030,
    native_sample_unqualified: true,
    object_id: "service:payments",
    observed_at: 1030,
    partition: "cluster-prod-east",
    permissions_fingerprint: "perm-a",
    product: "kubernetes",
    projection_qualification: "normalized_export_only",
    qualification: "snapshot_interval",
    received_at: 1031,
    record_id: CHANGE_ID,
    record_type: "change",
    revision: null,
    schema_version: 1,
    scope: "prod-east",
    source_refs: [
      "capture:cap-1",
      "capture:cap-2",
      "snapshot:cap-1",
      "snapshot:cap-2",
    ],
    source_version: "1.0",
    time_qualification: "snapshot_interval",
  };
}

function manifest(): ChangeGenerationManifest {
  return {
    algorithm_version: "configuration-history-v1",
    canonicalization: "bounded-decimal-json-v1",
    generation_id: GENERATION_ID,
    record_id_hash_excludes: ["record_id", "generation_id"],
    record_type: "generation_manifest",
    row_count: 2,
    row_hash_excludes: ["generation_id"],
    row_order: "record_id-asc-v1",
    rows_sha256: ROWS_SHA256,
    schema_version: 1,
    source_earliest: 1010,
    source_latest: 1030,
    source_receipt_hashes: [
      "7548213ce8127e594ef7b6f81ab8b9e3e4519b50272dd1943032a76e34689456",
      "bd92f05a71fb8cd860620733cecf197f0f71233a7f0ee293a452715a2dfaeb3a",
    ],
  };
}

async function activationFor(
  value = manifest(),
): Promise<ChangeGenerationActivation> {
  const activation: ChangeGenerationActivation = {
    schema_version: 1,
    record_type: "generation_activation",
    activation_id: "0".repeat(64),
    generation_id: value.generation_id,
    index: "atlas_changes",
    source_earliest: value.source_earliest,
    source_latest: value.source_latest,
    index_earliest: 2000,
    index_latest: 2100,
    activated_at: 2100,
    viewer_entitlement_attested: true,
    validation_method: "sha256-full-generation-v1",
    manifest: value,
  };
  activation.activation_id = await sha256Hex(
    canonicalJson(withoutKeys(activation, ["activation_id"])),
  );
  return activation;
}

const view = {
  scope: "prod-east",
  window: { start: 1005, end: 1030 },
};

describe("configuration history canonical generation validation", () => {
  it("matches the independent Python golden IDs and validates the full generation before filtering", async () => {
    const rows = [changedRow(), baselineRow()];
    expect(
      await sha256Hex(
        canonicalJson(
          withoutKeys(baselineRow(), ["record_id", "generation_id"]),
        ),
      ),
    ).toBe(BASELINE_ID);
    expect(
      await sha256Hex(
        canonicalJson(
          withoutKeys(changedRow(), ["record_id", "generation_id"]),
        ),
      ),
    ).toBe(CHANGE_ID);
    expect(
      await sha256Hex(
        canonicalJson(withoutKeys(manifest(), ["generation_id"])),
      ),
    ).toBe(GENERATION_ID);
    expect(
      await sha256Hex(
        rows
          .sort((left, right) => left.record_id.localeCompare(right.record_id))
          .map((row) => canonicalJson(withoutKeys(row, ["generation_id"])))
          .join("\n"),
      ),
    ).toBe(ROWS_SHA256);

    const payloads = [
      canonicalJson(changedRow()),
      canonicalJson(manifest()),
      canonicalJson(baselineRow()),
    ];
    const client: SearchClient = {
      search: vi.fn(async () => ({
        rows: payloads.map((timeline_payload) => ({ timeline_payload })),
        warnings: [],
        errors: [],
      })),
    };
    const calls: { source: string; request: unknown }[] = [];
    const runner = async (
      source: string,
      _key: string,
      passedClient: SearchClient,
      request: Parameters<SearchClient["search"]>[0],
    ): Promise<RunResult> => {
      calls.push({ source, request });
      return passedClient.search(request);
    };
    const result = await loadChangeTimeline(
      client,
      { activation: await activationFor(), ...view },
      new AbortController().signal,
      runner,
    );
    if (result.provenance !== "validated_live")
      throw new Error("Expected verified live history result.");

    expect(calls).toHaveLength(1);
    expect(calls[0].source).toBe("change_timeline");
    expect(result.validation).toEqual({
      method: "sha256-full-generation-v1",
      row_count: 2,
      rows_sha256: ROWS_SHA256,
    });
    expect(result.rows.map((row) => row.record_id)).toEqual([
      BASELINE_ID,
      CHANGE_ID,
    ]);
    const request = calls[0].request as {
      search: string;
      earliest: string;
      latest: string;
      maxRows: number;
    };
    expect(request.search).toContain("search index=atlas_changes");
    expect(request.search).toContain(`generation_id="${GENERATION_ID}"`);
    expect(request.search).toContain("_index_earliest=2000 _index_latest=2100");
    expect(request.search).toContain(
      'sourcetype="adm:configuration_change:v1"',
    );
    expect(request.search).toContain(
      'sourcetype="adm:configuration_change_manifest:v1"',
    );
    expect(request.search).not.toContain("prod-east");
    expect(request.earliest).toBe("1010");
    expect(request.latest).toBe("2100");
    expect(request.maxRows).toBe(10_001);
    expect(request.search).toContain("| dedup timeline_payload");
  });

  it("accepts exact duplicate manifest and row replay but rejects conflicting duplicates", async () => {
    const activation = await activationFor();
    const payloads = [
      canonicalJson(changedRow()),
      canonicalJson(manifest()),
      canonicalJson(baselineRow()),
      canonicalJson(changedRow()),
      canonicalJson(manifest()),
    ];
    const fake: SearchClient = {
      search: vi.fn(async () => ({
        rows: payloads.map((timeline_payload) => ({ timeline_payload })),
        warnings: [],
        errors: [],
      })),
    };
    const result = await loadChangeTimeline(
      fake,
      { activation, ...view },
      new AbortController().signal,
      (_source, _key, client, request) => client.search(request),
    );
    if (result.provenance !== "validated_live")
      throw new Error("Expected validated live history.");
    expect(result.provenance).toBe("validated_live");
    expect(result.rows).toHaveLength(2);

    const conflict = canonicalJson({ ...changedRow(), actor: "tampered" });
    const conflicting: SearchClient = {
      search: vi.fn(async () => ({
        rows: [
          ...payloads.map((timeline_payload) => ({ timeline_payload })),
          { timeline_payload: conflict },
        ],
        warnings: [],
        errors: [],
      })),
    };
    await expect(
      loadChangeTimeline(
        conflicting,
        { activation, ...view },
        new AbortController().signal,
        (_source, _key, client, request) => client.search(request),
      ),
    ).rejects.toThrow(/conflicting duplicate/i);
  });

  it("validates the shared actual-Python activation, partial receipt and source-clock extrema", async () => {
    const activation = await validateChangeActivation(
      activationGolden.activation,
    );
    expect(activation.source_latest).toBe(1793102400.123);
    const query = buildChangeGenerationSearch(activation);
    expect(query.earliest).toBe("1793102000");
    expect(query.latest).toBe("1793102400.124");
    expect(query.search).toContain("| dedup timeline_payload");
    expect(query.search).toContain("| table timeline_payload | head");

    const payloads = [
      ...activationGolden.rows.map((row) => canonicalJson(row)),
      canonicalJson(activationGolden.manifest),
    ];
    const fake: SearchClient = {
      search: vi.fn(async () => ({
        rows: payloads.map((timeline_payload) => ({ timeline_payload })),
        warnings: [],
        errors: [],
      })),
    };
    const result = await loadChangeTimeline(
      fake,
      {
        activation,
        scope: "change-a",
        window: { start: 1793102000, end: 1793102030 },
      },
      new AbortController().signal,
      (_source, _key, client, request) => client.search(request),
    );
    if (result.provenance !== "validated_live")
      throw new Error("Expected validated live history.");
    expect(result.provenance).toBe("validated_live");
    expect(result.validation.row_count).toBe(2);
    const gap = result.generation_rows?.find(
      (row) => row.record_type === "coverage",
    );
    expect(gap).toMatchObject({
      permissions_fingerprint: null,
      earliest_at: 1793102020,
      latest_at: null,
      coverage_complete: false,
    });
  });

  it("accepts Python-produced signed and large projected integers without relaxing timestamps", async () => {
    for (const vector of projectedNumbersGolden.vectors) {
      const result = await validateCapturedChangeTimeline({
        manifest: vector.manifest,
        rows: vector.rows,
        label: "Synthetic numeric contract vector",
      });
      expect(result.rows[0].attributes.generation).toBe(vector.value);
      const invalid = structuredClone(vector.rows);
      invalid[0].observed_at = -1;
      await expect(
        validateCapturedChangeTimeline({
          manifest: vector.manifest,
          rows: invalid,
          label: "Invalid clock",
        }),
      ).rejects.toThrow(/observed|timestamp|invalid/i);
    }
  });

  it("validates captured rows as synthetic and exposes the full generation", async () => {
    const result = await validateCapturedChangeTimeline({
      manifest: activationGolden.manifest,
      rows: activationGolden.rows,
      label: "Synthetic shared fixture",
    });
    expect(result.provenance).toBe("synthetic_demo");
    expect(result.rows).toHaveLength(2);
    expect(result.generation_rows).toHaveLength(2);
    expect(result.manifest.generation_id).toBe(
      activationGolden.manifest.generation_id,
    );
    expect(result.retained_relationships).toEqual([]);
  });

  it("rejects unentitled activations, row tampering, missing manifests, and incomplete result sets", async () => {
    const goodActivation = await activationFor();
    const denied = {
      ...goodActivation,
      activation_id: "0".repeat(64),
      viewer_entitlement_attested: false,
    } as unknown as ChangeGenerationActivation;
    denied.activation_id = await sha256Hex(
      canonicalJson(withoutKeys(denied, ["activation_id"])),
    );
    const noSearch: SearchClient = {
      search: vi.fn(async () => ({ rows: [], warnings: [], errors: [] })),
    };
    await expect(
      loadChangeTimeline(
        noSearch,
        { activation: denied, ...view },
        new AbortController().signal,
        async () => ({ rows: [], warnings: [], errors: [] }),
      ),
    ).rejects.toThrow(/activation/i);
    expect(noSearch.search).not.toHaveBeenCalled();

    const malformedSets: unknown[][] = [
      [canonicalJson(changedRow()), canonicalJson(baselineRow())],
      [canonicalJson(changedRow()), canonicalJson(manifest())],
      [
        canonicalJson({ ...changedRow(), actor: "tampered" }),
        canonicalJson(manifest()),
        canonicalJson(baselineRow()),
      ],
    ];
    for (const payloads of malformedSets) {
      const fake: SearchClient = {
        search: vi.fn(async () => ({
          rows: payloads.map((timeline_payload) => ({ timeline_payload })),
          warnings: [],
          errors: [],
        })),
      };
      await expect(
        loadChangeTimeline(
          fake,
          { activation: goodActivation, ...view },
          new AbortController().signal,
          (_source, _key, client, request) => client.search(request),
        ),
      ).rejects.toThrow();
    }
  });

  it("resolves exactly one literal activation and enforces its closed ingest bounds", async () => {
    const activation = await activationFor();
    const bounds = buildChangeActivationSearch(
      "atlas_changes",
      activation.activation_id,
      3000,
    );
    expect(bounds).toMatchObject({ earliest: "0", latest: "3000", maxRows: 2 });
    expect(bounds.search).toContain("index=atlas_changes");
    expect(bounds.search).toContain("| table timeline_payload | head 2");
    expect(bounds.search).toContain(
      'sourcetype="adm:configuration_change_activation:v1"',
    );
    expect(bounds.search).toContain(
      `activation_id="${activation.activation_id}"`,
    );
    expect(bounds.search).toContain("head 2");
    expect(() =>
      buildChangeActivationSearch(
        "atlas_changes | delete",
        activation.activation_id,
        3000,
      ),
    ).toThrow(/index/i);

    let seen:
      | { source: string; request: Parameters<SearchClient["search"]>[0] }
      | undefined;
    const client: SearchClient = {
      search: vi.fn(async () => ({ rows: [], warnings: [], errors: [] })),
    };
    const loaded = await loadChangeActivation(
      client,
      "atlas_changes",
      activation.activation_id,
      new AbortController().signal,
      async (source, _key, passedClient, request) => {
        seen = { source, request };
        return {
          rows: [{ timeline_payload: canonicalJson(activation) }],
          warnings: [],
          errors: [],
        };
      },
    );
    expect(loaded).toEqual(activation);
    expect(seen?.source).toBe("change_timeline");
    expect(seen?.request.maxRows).toBe(2);

    const conflicting = await activationFor();
    conflicting.index_latest = conflicting.activated_at + 1;
    conflicting.activation_id = "0".repeat(64);
    conflicting.activation_id = await sha256Hex(
      canonicalJson(withoutKeys(conflicting, ["activation_id"])),
    );
    await expect(validateChangeActivation(conflicting)).rejects.toThrow(
      /bounds/i,
    );

    for (const rows of [
      [],
      [
        { timeline_payload: canonicalJson(activation) },
        { timeline_payload: canonicalJson(activation) },
      ],
    ]) {
      await expect(
        loadChangeActivation(
          client,
          "atlas_changes",
          activation.activation_id,
          new AbortController().signal,
          async () => ({ rows, warnings: [], errors: [] }),
        ),
      ).rejects.toThrow();
    }
  });

  it("rejects non-canonical numbers, duplicate JSON keys, and finer-than-millisecond values", () => {
    expect(
      canonicalJson({ z: 1.0, text: "café", milli: 1.234, zero: -0 }),
    ).toBe('{"milli":1.234,"text":"café","z":1,"zero":0}');
    expect(() => canonicalJson(1.2345)).toThrow(/millisecond/i);
    expect(() => canonicalJson(Number.POSITIVE_INFINITY)).toThrow(/finite/i);
    expect(() => canonicalJson("\ud800")).toThrow(/Unicode/i);
    expect(parseCanonicalJson('{"a":1,"b":2}')).toEqual({ a: 1, b: 2 });
    expect(() => parseCanonicalJson('{"a":1, "b":2}')).toThrow(/canonical/i);
    expect(() => parseCanonicalJson('{"a":1,"a":2}')).toThrow(/canonical/i);
    expect(() => parseCanonicalJson('{"a":1e3}')).toThrow(/canonical/i);
  });
});

describe("configuration change attribution", () => {
  it("never uses application labels or an incomplete interval as a relationship", () => {
    const row = changedRow();
    const labelOnly = attributeChangeRow(row, view, {
      application: {
        service: "payments",
        environment: "prod",
        cluster: "prod-east",
        namespace: "payments",
      },
    });
    expect(labelOnly).toMatchObject({
      attribution_class: "context_only",
      reason: "no_qualified_relationship_chain",
    });

    const audit = {
      ...row,
      earliest_at: null,
      latest_at: null,
      event_at: 1015,
      time_qualification: "source_event_time_reported",
      clock_uncertainty_unknown: true,
    };
    expect(filterTimelineRows([audit], view)).toHaveLength(1);
    expect(
      attributeChangeRow(audit, view, {
        selectedObjects: [
          {
            authority: row.authority,
            type: row.family,
            id: row.object_id!,
          },
        ],
      }),
    ).toMatchObject({
      attribution_class: "context_only",
      reason: "unknown_or_overwide_change_interval",
    });
  });

  it("requires exact authority-qualified identities and full relationship validity", () => {
    const row = changedRow();
    const direct = attributeChangeRow(row, view, {
      selectedObjects: [
        {
          authority: row.authority,
          type: row.family,
          id: row.object_id!,
        },
      ],
    });
    expect(direct).toMatchObject({
      attribution_class: "direct_object",
      reason: "overlapping_change_interval",
    });

    const link = {
      from_authority: row.authority,
      from_type: row.family,
      from_id: row.object_id!,
      to_authority: "atlas:observed_dependency",
      to_type: "captured_dependency",
      to_id: `captured_dependency:${"a".repeat(64)}`,
      scope: "prod-east",
      valid_from: 999,
      valid_to: 1031,
      evidence_id: "relationship:payments-to-db",
      basis: "native" as const,
    };
    const dependency = attributeChangeRow(row, view, {
      observedDependencies: [
        {
          authority: link.to_authority,
          type: link.to_type,
          id: link.to_id,
        },
      ],
      relationships: [link],
      relationshipsVerified: true,
    });
    expect(dependency).toMatchObject({
      attribution_class: "observed_dependency",
      reason: "overlapping_change_interval",
      chain: [link],
    });

    expect(
      attributeChangeRow(row, view, {
        observedDependencies: [
          {
            authority: link.to_authority,
            type: link.to_type,
            id: link.to_id,
          },
        ],
        relationships: [{ ...link, valid_to: 1030 }],
        relationshipsVerified: true,
      }),
    ).toMatchObject({
      attribution_class: "context_only",
      reason: "relationship_validity_incomplete",
    });
    expect(
      attributeChangeRow(row, view, {
        observedDependencies: [
          {
            authority: link.to_authority,
            type: link.to_type,
            id: link.to_id,
          },
        ],
        relationships: [{ ...link, from_authority: "wrong-authority" }],
        relationshipsVerified: true,
      }),
    ).toMatchObject({
      attribution_class: "context_only",
      reason: "no_qualified_relationship_chain",
    });
  });

  it("keeps source-projection restrictions separate from application attribution", () => {
    const row = { ...changedRow(), context_only: true };
    expect(
      attributeChangeRow(row, view, {
        selectedObjects: [
          {
            authority: row.authority,
            type: row.family,
            id: row.object_id!,
          },
        ],
      }),
    ).toMatchObject({
      attribution_class: "context_only",
      reason: "source_projection_context_only",
    });
  });
});

describe("configuration timeline view exclusions", () => {
  it("counts scope, window and unpositioned records for the exported view", () => {
    const outOfScope = { ...changedRow(), scope: "other" };
    const outside = { ...changedRow(), earliest_at: 1100, latest_at: 1110 };
    const unknown = {
      ...changedRow(),
      record_type: "observation" as const,
      earliest_at: null,
      latest_at: null,
      event_at: null,
      observed_at: null,
    };
    expect(
      countTimelineExclusions([outOfScope, outside, unknown], view),
    ).toEqual({
      different_verified_scope: 1,
      outside_selected_interval: 1,
      unknown_time_unpositioned: 1,
    });
  });
});
