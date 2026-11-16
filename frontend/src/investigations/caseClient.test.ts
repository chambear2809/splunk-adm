import { describe, expect, it, vi } from "vitest";
import { CaseError, createCaseClient } from "./caseClient";

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
