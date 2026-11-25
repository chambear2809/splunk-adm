import { describe, expect, it } from "vitest";
import { canonicalJson, sha256Hex } from "./canonicalJson";
import {
  verifyConnectedScenarioBundle,
  type ConnectedScenarioContractV2,
} from "./scenarioV2";
import fixture from "../../../fixtures/change-correlation-v2/connected-bundle-track-b.json";

describe("connected scenario v2 bundle", () => {
  const contract: ConnectedScenarioContractV2 = {
    scenario_id: fixture.scenario_id,
    variant_id: fixture.variant_id,
    template_sha256: fixture.template_sha256,
    application: fixture.application,
    connected_services: fixture.connected_services,
    event_ids: fixture.events.map((event) => event.id),
    phase_ids: fixture.phase_proof.map((phase) => phase.phase_id),
    content_sha256: {
      application:
        "2d1e17f026d276e16d7419b16b7aeb14299da16dbff7df5f0c8d857461a41b75",
      connected_services:
        "1eced87c5a22c0513f69a8c3b4260a798e49782d8897388d1b45b62e7a166060",
      identities:
        "6c76611dac3f16d7164768bb4f5d4a92dab62af67fbf6d3871692b27dc2bf7b9",
      events:
        "c82dd3ef122dbde43e4929727ee1d1482c1c1429474f2f70e569879d2f4583d9",
      phase_proof:
        "4d4262e2f656a24fac483dde2085a805666613fee193117d984b4f2ba91f4bbe",
      limitations:
        "03c7dd69112cf5b88205966f7ae633e2cf853c9ede37971de443b35d24ca9447",
    },
    anchor_epoch: fixture.anchor_epoch,
    execution_id: fixture.execution_id,
  };
  it("accepts a Python-shaped source bundle with no receipt claims", async () => {
    const bundle = fixture;
    await expect(
      verifyConnectedScenarioBundle(bundle, contract),
    ).resolves.toEqual(bundle);
  });

  it("rejects receipt claims even when the outer hash is valid", async () => {
    const body = structuredClone(fixture);
    (body.events[0] as Record<string, unknown>).indexed_receipt_epoch = 1;
    delete (body as Record<string, unknown>).bundle_sha256;
    const bundle = {
      ...body,
      bundle_sha256: await sha256Hex(canonicalJson(body)),
    };
    await expect(
      verifyConnectedScenarioBundle(bundle, contract),
    ).rejects.toThrow("receipt claims");
  });

  it("rejects a known variant with a rehashed template mutation", async () => {
    const body = structuredClone(fixture);
    body.template_sha256 = "f".repeat(64);
    delete (body as Record<string, unknown>).bundle_sha256;
    const bundle = {
      ...body,
      bundle_sha256: await sha256Hex(canonicalJson(body)),
    };
    await expect(
      verifyConnectedScenarioBundle(bundle, contract),
    ).rejects.toThrow("template binding");
  });

  it("rejects rehashed execution and status mutations", async () => {
    const execution = structuredClone(fixture);
    execution.execution_id = "00000000-0000-4000-8000-000000000072";
    delete (execution as Record<string, unknown>).bundle_sha256;
    const executionBundle = {
      ...execution,
      bundle_sha256: await sha256Hex(canonicalJson(execution)),
    };
    await expect(
      verifyConnectedScenarioBundle(executionBundle, contract),
    ).rejects.toThrow("template binding");
    const status = structuredClone(fixture);
    (status.events[0] as Record<string, unknown>).status = "unknown";
    delete (status as Record<string, unknown>).bundle_sha256;
    const statusBundle = {
      ...status,
      bundle_sha256: await sha256Hex(canonicalJson(status)),
    };
    await expect(
      verifyConnectedScenarioBundle(statusBundle, contract),
    ).rejects.toThrow("content binding");
  });

  it("rejects independently rehashed payload, identity, phase, and anchor mutations", async () => {
    for (const [section, mutate] of [
      ["events", (body: any) => (body.events[0].id = "forged")],
      [
        "identities",
        (body: any) => (body.identities.primary.cluster = "forged"),
      ],
      ["phase_proof", (body: any) => (body.phase_proof[0].phase_id = "impact")],
      ["anchor", (body: any) => (body.anchor_epoch += 300)],
    ] as const) {
      const body = structuredClone(fixture) as any;
      mutate(body);
      delete body.bundle_sha256;
      const forged = {
        ...body,
        bundle_sha256: await sha256Hex(canonicalJson(body)),
      };
      await expect(
        verifyConnectedScenarioBundle(forged, contract),
      ).rejects.toThrow(
        section === "anchor" ? "template binding" : "content binding",
      );
    }
  });

  it("rejects contracts without exact execution and anchor bindings", async () => {
    const missing = { ...contract, execution_id: "", anchor_epoch: Number.NaN };
    await expect(
      verifyConnectedScenarioBundle(fixture, missing),
    ).rejects.toThrow("template binding");
    const relabeled = {
      ...contract,
      execution_id: "00000000-0000-4000-8000-000000000072",
    };
    await expect(
      verifyConnectedScenarioBundle(fixture, relabeled),
    ).rejects.toThrow("template binding");
  });
});
