import { describe, expect, it, vi } from "vitest";

vi.mock("@splunk/splunk-utils/fetch", () => ({
  getDefaultFetchInit: () => ({ headers: { "X-Splunk-Form-Key": "k" } }),
}));
vi.mock("@splunk/splunk-utils/url", () => ({
  createRESTURL: (path: string) =>
    `/splunkd/__raw/servicesNS/nobody/splunk_adm/${path}`,
}));

import {
  AssertionClient,
  AssertionStoreError,
  assertionsOf,
  storeMessage,
} from "./assertionClient";

const assertion = {
  id: "a1",
  name: "Web reaches DB",
  owner: "alice",
  kind: "reaches",
  scope: "prod",
  src: "10.1.1.10",
  dst: "10.2.2.20",
  transport: "tcp",
  port: 5432,
};
const reply = (status: number, body: unknown) =>
  Promise.resolve(new Response(JSON.stringify(body), { status }));

describe("AssertionClient", () => {
  it("reads kind=assertions and validates every row", async () => {
    const fetcher = vi.fn(() =>
      reply(200, {
        entry: [
          { content: { revision: "r1", payload: { assertions: [assertion] } } },
        ],
      }),
    );
    const doc = await new AssertionClient(
      fetcher as unknown as typeof fetch,
    ).load();
    expect(doc).toEqual({ revision: "r1", assertions: [assertion] });
    expect(String((fetcher.mock.calls[0] as unknown[])[0])).toContain(
      "adm/collaboration?kind=assertions",
    );
  });
  it("fails closed on a malformed stored row", () => {
    expect(() =>
      assertionsOf({ assertions: [{ ...assertion, port: 0 }] }),
    ).toThrow(AssertionStoreError);
    expect(assertionsOf(null)).toEqual([]);
  });
  it("posts CAS saves and requires a committed revision", async () => {
    const fetcher = vi.fn(() =>
      reply(200, {
        committedRevision: "r2",
        payload: { assertions: [assertion] },
      }),
    );
    const client = new AssertionClient(fetcher as unknown as typeof fetch);
    const saved = await client.save([assertion as never], "r1", "req-1");
    expect(saved.revision).toBe("r2");
    const body = JSON.parse(
      String(
        (fetcher.mock.calls[0] as unknown as [string, RequestInit])[1].body,
      ),
    );
    expect(body).toEqual({
      expectedRevision: "r1",
      requestId: "req-1",
      payload: { assertions: [assertion] },
    });
    const unconfirmed = new AssertionClient((() =>
      reply(200, { payload: null })) as unknown as typeof fetch);
    await expect(unconfirmed.save([], null, "req-2")).rejects.toThrow(
      /not confirmed/,
    );
  });
  it("explains permission and conflict failures honestly", async () => {
    const denied = new AssertionClient((() =>
      reply(403, {
        error: "Collection write permission is required.",
      })) as unknown as typeof fetch);
    const error = await denied.save([], null, "r").catch((e: unknown) => e);
    expect(storeMessage(error)).toMatch(/admin or sc_admin/);
    expect(
      storeMessage(
        new AssertionStoreError(
          "Cannot delete an assertion owned by another user.",
          403,
        ),
      ),
    ).toMatch(/Only the owner/);
    expect(storeMessage(new AssertionStoreError("x", 409))).toMatch(/Reload/);
  });
});
