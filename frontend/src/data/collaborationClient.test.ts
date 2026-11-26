import { describe, expect, it, vi } from "vitest";
import { CollaborationClient } from "./collaborationClient";

vi.mock("@splunk/splunk-utils/fetch", () => ({
  getDefaultFetchInit: () => ({ credentials: "same-origin" }),
}));
vi.mock("@splunk/splunk-utils/url", () => ({
  createRESTURL: (path: string) => `/rest/${path}`,
}));

const respond = (body: unknown) =>
  vi.fn(async () => new Response(JSON.stringify(body), { status: 200 }));

describe("collaboration views writability", () => {
  it("reports writable only when the server explicitly allows it", async () => {
    for (const [writable, expected] of [
      [true, true],
      [false, false],
      [undefined, false],
      ["true", false],
    ] as const) {
      const client = new CollaborationClient(
        respond({ state: "absent", revision: null, payload: null, writable }),
      );
      expect((await client.loadViews()).writable).toBe(expected);
    }
  });

  it("keeps shared views readable when the caller cannot write", async () => {
    const client = new CollaborationClient(
      respond({
        state: "configured",
        revision: "r1",
        writable: false,
        payload: {
          views: [
            {
              id: "s1",
              name: "Shared",
              visibility: "shared",
              owner: "alice",
              state: { mode: "live" },
            },
          ],
        },
      }),
    );
    const document = await client.loadViews();
    expect(document.writable).toBe(false);
    expect(document.views.map((view) => view.name)).toEqual(["Shared"]);
  });
});
