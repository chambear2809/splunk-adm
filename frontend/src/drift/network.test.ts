import { describe, expect, it, vi } from "vitest";
import { BaselineWriteError } from "./client";
import { createDependencyClient } from "./network";
const selection = {
  service: "svc",
  environment: "prod",
  cluster: "c",
  namespace: "n",
};
const json = (value: unknown, status = 200) =>
  new Response(JSON.stringify(value), { status });
describe("authenticated dependency client", () => {
  it("reads capability separately and fails closed on unavailable source", async () => {
    const transport = vi
      .fn()
      .mockResolvedValueOnce(
        json({
          available: true,
          sourceAvailable: false,
          qualificationReasons: ["No completeness proof"],
        }),
      )
      .mockResolvedValueOnce(json({ error: "source_unavailable" }, 422));
    const client = createDependencyClient({
      selection,
      baseUrl: "/test",
      transport,
    });
    const signal = new AbortController().signal;
    expect(await client.capabilities(signal)).toMatchObject({
      available: true,
      sourceAvailable: false,
    });
    await expect(
      client.source.capture({ start: 100, end: 200 }, signal),
    ).rejects.toThrow("unavailable");
    expect(transport.mock.calls[1][0]).toContain("service=svc");
    expect(transport.mock.calls[1][0]).toContain("start=100");
  });
  it("sends only reference and revision, retaining key on lost-response replay", async () => {
    const transport = vi
      .fn()
      .mockRejectedValueOnce(new Error("lost"))
      .mockResolvedValueOnce(
        json({ id: "id", revision: 5, resultWithheld: true }),
      );
    const { repository } = createDependencyClient({
      selection,
      baseUrl: "/test",
      transport,
    });
    const evaluate = () =>
      repository.evaluate!("id", "watch", 4, 2, "opaque", "same-key");
    await expect(evaluate()).rejects.toMatchObject({ uncertain: true });
    await expect(evaluate()).resolves.toEqual({
      id: "id",
      revision: 5,
      resultWithheld: true,
    });
    expect(transport.mock.calls[0]).toEqual(transport.mock.calls[1]);
    const init = transport.mock.calls[0][1] as RequestInit;
    expect(JSON.parse(init.body as string)).toEqual({
      expected_revision: 4,
      baseline_version: 2,
      reference: "opaque",
    });
    expect(init.headers).toMatchObject({ "Idempotency-Key": "same-key" });
  });
  it("distinguishes definite source failure from uncertain auth failure", async () => {
    const transport = vi
      .fn()
      .mockResolvedValueOnce(json({}, 422))
      .mockResolvedValueOnce(json({}, 403));
    const { repository } = createDependencyClient({
      selection,
      baseUrl: "/test",
      transport,
    });
    await expect(repository.create("x", "r", "a")).rejects.toMatchObject({
      uncertain: false,
    });
    await expect(repository.create("x", "r", "a")).rejects.toMatchObject({
      uncertain: true,
    });
  });
  it("rejects malformed write receipts as uncertain", async () => {
    const transport = vi.fn(async () => json({ id: "id" }));
    const { repository } = createDependencyClient({
      selection,
      baseUrl: "/test",
      transport,
    });
    await expect(repository.create("x", "r", "a")).rejects.toBeInstanceOf(
      BaselineWriteError,
    );
  });
});

it("validates server-derived kinds and pinned version without guessing", async () => {
  const base = {
    seq: 1,
    signature: "opaque",
    window: { start: 100, end: 200 },
    observedAt: 210,
  };
  const signal = new AbortController().signal;
  for (const kinds of [
    ["new_destination_port"],
    ["changed_dependency"],
    ["newly_blocked"],
    ["lost_redundancy"],
    ["not_observed"],
    ["newly_blocked", "lost_redundancy"],
    ["lost_redundancy", "newly_blocked"],
  ]) {
    const client = createDependencyClient({
      selection,
      baseUrl: "/test",
      transport: async () =>
        json({
          items: [{ ...base, changeKinds: kinds, baselineVersion: 1 }],
          next: null,
        }),
    });
    await expect(
      client.repository.occurrences!("id", "w", signal),
    ).resolves.toMatchObject({
      items: [{ changeKinds: kinds, baselineVersion: 1 }],
    });
  }
  const legacy = createDependencyClient({
    selection,
    baseUrl: "/test",
    transport: async () => json({ items: [base], next: null }),
  });
  await expect(
    legacy.repository.occurrences!("id", "w", signal),
  ).resolves.toMatchObject({ items: [base] });
  const invalid = [
    { changeKinds: ["newly_blocked"] },
    { baselineVersion: 1 },
    { changeKinds: [], baselineVersion: 1 },
    { changeKinds: ["future_kind"], baselineVersion: 1 },
    { changeKinds: ["newly_blocked", "newly_blocked"], baselineVersion: 1 },
    { changeKinds: ["newly_blocked", "not_observed"], baselineVersion: 1 },
    {
      changeKinds: ["new_destination_port", "changed_dependency"],
      baselineVersion: 1,
    },
    { changeKinds: ["not_observed"], baselineVersion: 0 },
    { changeKinds: ["not_observed"], baselineVersion: 1.5 },
    { changeKinds: ["not_observed"], baselineVersion: "1" },
    { changeKinds: null, baselineVersion: 1 },
  ];
  for (const extra of invalid) {
    const client = createDependencyClient({
      selection,
      baseUrl: "/test",
      transport: async () =>
        json({ items: [{ ...base, ...extra }], next: null }),
    });
    await expect(
      client.repository.occurrences!("id", "w", signal),
    ).rejects.toThrow("Watch history is invalid");
  }
});
