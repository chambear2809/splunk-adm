import { describe, expect, it, vi } from "vitest";
import { CaseError, createCaseClient, type CaseTransport } from "./caseClient";

const sample = {
  schema_version: 1,
  id: "case-1",
  revision: 1,
  title: "Incident",
  window: { start: "2026-01-01T00:00:00Z", end: "2026-01-01T01:00:00Z" },
  entries: [],
  captures: [],
  attachments: [],
};
const json = (value: unknown, status = 200) =>
  new Response(JSON.stringify(value), { status });

describe("shared case client", () => {
  it("keeps a write uncertain when access is lost after a possible commit", async () => {
    for (const status of [401, 403, 404]) {
      const transport = vi.fn<CaseTransport>(async () =>
        json({ error: "unavailable" }, status),
      );
      const client = createCaseClient({ transport, baseUrl: "/cases-api" });
      await expect(
        client.append("case-1", 1, "note", "hello").execute(),
      ).rejects.toMatchObject({ status, uncertain: true });
      await expect(client.get("case-1")).rejects.toMatchObject({
        status,
        uncertain: false,
      });
    }
  });
  it("retains the exact request through a lost response, denial, and restored access", async () => {
    const transport = vi
      .fn<CaseTransport>()
      .mockRejectedValueOnce(new Error("response lost after commit"))
      .mockResolvedValueOnce(json({ error: "forbidden" }, 403))
      .mockResolvedValueOnce(json({ ...sample, revision: 2 }));
    const client = createCaseClient({
      transport,
      baseUrl: "/cases-api",
      requestId: () => "same-request",
    });
    const operation = client.append("case-1", 1, "note", "hello");
    await expect(operation.execute()).rejects.toMatchObject({
      uncertain: true,
    });
    await expect(operation.execute()).rejects.toMatchObject({
      status: 403,
      uncertain: true,
    });
    await expect(operation.execute()).resolves.toMatchObject({ revision: 2 });
    expect(transport.mock.calls[0]).toEqual(transport.mock.calls[1]);
    expect(transport.mock.calls[1]).toEqual(transport.mock.calls[2]);
  });
  it("uses injected authenticated transport and rejects permission errors", async () => {
    const transport = vi.fn(async () => json({ error: "forbidden" }, 403));
    const client = createCaseClient({
      transport,
      baseUrl: "/adm/investigations",
    });
    await expect(client.get("case-1")).rejects.toMatchObject({
      status: 403,
      uncertain: false,
    });
    expect(transport).toHaveBeenCalledWith(
      "/adm/investigations/cases/case-1",
      expect.objectContaining({ method: "GET" }),
    );
  });
  it("retries an uncertain write with the same id, revision, and body", async () => {
    const transport = vi
      .fn()
      .mockRejectedValueOnce(new Error("network lost"))
      .mockResolvedValueOnce(json({ ...sample, revision: 2 }));
    const client = createCaseClient({
      transport,
      baseUrl: "/adm/investigations",
      requestId: () => "stable-id",
    });
    const operation = client.append("case-1", 1, "note", "hello");
    await expect(operation.execute()).rejects.toMatchObject({
      uncertain: true,
    });
    await expect(operation.execute()).resolves.toMatchObject({ revision: 2 });
    expect(transport).toHaveBeenCalledTimes(2);
    expect(transport.mock.calls[0]).toEqual(transport.mock.calls[1]);
    const init = transport.mock.calls[0][1] as RequestInit;
    expect(init.headers).toMatchObject({ "Idempotency-Key": "stable-id" });
    expect(JSON.parse(init.body as string)).toEqual({
      expected_revision: 1,
      item: { type: "note", text: "hello" },
    });
    await operation.execute();
    expect(transport).toHaveBeenCalledTimes(2);
  });
  it("treats malformed success as an uncertain mutation and rejects malformed records on reads", async () => {
    const transport = vi.fn(async () =>
      json({ ...sample, entries: [{ type: "note" }] }),
    );
    const client = createCaseClient({
      transport,
      baseUrl: "/api",
      requestId: () => "id",
    });
    await expect(client.get("x")).rejects.toBeInstanceOf(CaseError);
    await expect(
      client.create("Incident", sample.window).execute(),
    ).rejects.toMatchObject({ uncertain: true });
  });
  it("sends revision preconditions for delete and passes read abort signals", async () => {
    const transport = vi
      .fn()
      .mockResolvedValueOnce(json({ items: [sample], next: null }))
      .mockResolvedValueOnce(json({ id: "case-1", deleted: true }));
    const client = createCaseClient({
      transport,
      baseUrl: "/api",
      requestId: () => "id",
    });
    const signal = new AbortController().signal;
    await client.list(signal);
    expect(transport.mock.calls[0][1].signal).toBe(signal);
    await client.delete("case-1", 1).execute();
    expect(JSON.parse(transport.mock.calls[1][1].body)).toEqual({
      expected_revision: 1,
    });
  });
});

it("sends only the source reference, retries with the same request, and validates redactions", async () => {
  const reference =
    '{"schema":1,"scope":{"cluster":"c","environment":"e","namespace":"n","service":"s"},"windows":[{"end":200,"start":100},{"end":300,"start":200}]}';
  const transport = vi
    .fn()
    .mockRejectedValueOnce(new Error("lost"))
    .mockResolvedValueOnce(
      json({
        ...sample,
        revision: 2,
        redactions: { captures: 1, attachments: 0 },
      }),
    );
  const client = createCaseClient({
    transport,
    baseUrl: "/api",
    requestId: () => "capture-key",
  });
  const operation = client.capture("case-1", 1, reference, "Comparison");
  await expect(operation.execute()).rejects.toMatchObject({ uncertain: true });
  await expect(operation.execute()).resolves.toMatchObject({
    redactions: { captures: 1 },
  });
  expect(transport.mock.calls[0]).toEqual(transport.mock.calls[1]);
  expect(JSON.parse(transport.mock.calls[0][1].body)).toEqual({
    expected_revision: 1,
    reference,
    label: "Comparison",
  });
  const invalid = createCaseClient({
    baseUrl: "/api",
    transport: async () =>
      json({ ...sample, redactions: { captures: -1, attachments: 0 } }),
  });
  await expect(invalid.get("case-1")).rejects.toBeInstanceOf(CaseError);
});

it("accepts only bounded comparison references rather than graph payloads", async () => {
  const { isComparisonReference } = await import("./CaseEvidence");
  const reference = {
    schema: 1,
    scope: { service: "s", environment: "e", cluster: "c", namespace: "n" },
    windows: [
      { start: 100, end: 200 },
      { start: 200, end: 300 },
    ],
  };
  expect(isComparisonReference(JSON.stringify(reference))).toBe(true);
  expect(
    isComparisonReference(JSON.stringify({ ...reference, graph: {} })),
  ).toBe(false);
  expect(
    isComparisonReference(
      JSON.stringify({
        ...reference,
        windows: [
          { start: 1, end: 302 },
          { start: 302, end: 400 },
        ],
      }),
    ),
  ).toBe(false);
  expect(
    isComparisonReference(
      JSON.stringify({
        ...reference,
        windows: [
          { start: 100, end: 200 },
          { start: 199, end: 300 },
        ],
      }),
    ),
  ).toBe(false);
});

it("treats unavailable source evidence as a definite failed write", async () => {
  const client = createCaseClient({
    baseUrl: "/api",
    transport: async () => json({ error: "source_unavailable" }, 422),
    requestId: () => "id",
  });
  await expect(
    client.capture("case-1", 1, "reference").execute(),
  ).rejects.toMatchObject({
    status: 422,
    uncertain: false,
    message:
      "Evidence cannot currently be revalidated. Your notes remain available.",
  });
});

it("validates capture indices and selects only a UUID on reads and exports", async () => {
  const id = "00000000-0000-4000-8000-000000000001";
  const transport = vi.fn<CaseTransport>(async () =>
    json({ ...sample, capture_ids: [id] }),
  );
  const client = createCaseClient({ baseUrl: "/api", transport });
  await client.get("case-1", undefined, id);
  await client.export("case-1", undefined, id);
  expect(transport.mock.calls[0][0]).toBe(`/api/cases/case-1?capture_id=${id}`);
  expect(transport.mock.calls[1][0]).toBe(
    `/api/cases/case-1/export?capture_id=${id}`,
  );
  await expect(
    client.get("case-1", undefined, "bad-selector"),
  ).rejects.toBeInstanceOf(CaseError);
  expect(transport).toHaveBeenCalledTimes(2);
  const invalid = createCaseClient({
    baseUrl: "/api",
    transport: async () => json({ ...sample, capture_ids: ["not-a-uuid"] }),
  });
  await expect(invalid.get("case-1")).rejects.toBeInstanceOf(CaseError);
});

it("validates capabilities and refuses contradictory or malformed responses", async () => {
  const transport = vi
    .fn<CaseTransport>()
    .mockResolvedValueOnce(
      json({
        available: true,
        evidenceWrites: false,
        mode: "notes_only",
        qualified: false,
      }),
    )
    .mockResolvedValueOnce(
      json({
        available: false,
        evidenceWrites: true,
        mode: "notes_only",
        qualified: false,
      }),
    )
    .mockResolvedValueOnce(json({ available: true }));
  const client = createCaseClient({ baseUrl: "/api", transport });
  await expect(client.capabilities()).resolves.toMatchObject({
    available: true,
    evidenceWrites: false,
  });
  expect(transport.mock.calls[0][0]).toBe("/api/capabilities");
  await expect(client.capabilities()).rejects.toBeInstanceOf(CaseError);
  await expect(client.capabilities()).rejects.toBeInstanceOf(CaseError);
});
