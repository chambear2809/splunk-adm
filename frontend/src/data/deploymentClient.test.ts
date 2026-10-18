import { describe, expect, it, vi } from "vitest";
vi.mock("@splunk/splunk-utils/url", () => ({
  createRESTURL: (path: string) => `/rest/${path}`,
}));
vi.mock("@splunk/splunk-utils/fetch", () => ({
  getDefaultFetchInit: () => ({
    headers: new Headers({ "X-Splunk-Form-Key": "csrf-test" }),
  }),
}));
import { ToolkitDeploymentClient } from "./deploymentClient";
import {
  defaultExpectations,
  DATA_CONTRACT_SELECTORS,
  selectedHealthProbes,
} from "./deploymentHealth";

const response = (body: unknown, status = 200) =>
  ({ ok: status < 300, status, json: async () => body }) as Response;
const entry = (content: Record<string, unknown>, canWrite = true) => ({
  entry: [{ content, acl: { can_write: canWrite } }],
});
function fixture({
  admin = true,
  writable = true,
  unreadable = false,
  readbackMismatch = false,
  contract = 1,
  mixedSelector = false,
  missingSelector = false,
  indexDefinition = "index=netflow",
  unreadableIndex = false,
} = {}) {
  let record: Record<string, unknown> | undefined;
  const fetcher = vi.fn(
    async (input: RequestInfo | URL, init?: RequestInit) => {
      const path = String(input);
      if (path.includes("authentication/current-context"))
        return response(
          entry({ capabilities: admin ? ["admin_all_objects"] : ["search"] }),
        );
      if (path.includes("configs/conf-macros")) {
        const name = decodeURIComponent(
          path.split("conf-macros/")[1].split("?")[0],
        );
        if (name === "adm_index_netflow")
          return unreadableIndex
            ? response({}, 403)
            : response(entry({ definition: indexDefinition }));
        if (name === "adm_index_summary")
          return response(entry({ definition: "index=adm_summary" }));
        if (name === "adm_summary_index_name")
          return response(entry({ definition: "adm_summary" }));
        if (missingSelector && name === "adm_topology")
          return response({}, 403);
        const selector = DATA_CONTRACT_SELECTORS.find(
          (item) => item.name === name,
        )!;
        return response(
          entry({
            definition:
              selector[
                mixedSelector && name === "adm_topology"
                  ? "before"
                  : contract === 1
                    ? "before"
                    : "after"
              ],
          }),
        );
      }
      if (path.includes("storage/collections/config"))
        return response(entry({}, writable));
      if (init?.method === "POST") {
        record = JSON.parse(String(init.body));
        if (readbackMismatch) record = { ...record, revision: "conflict" };
        return response({});
      }
      if (unreadable) return response({}, 403);
      return record ? response(record) : response({}, 404);
    },
  );
  return { fetcher, client: new ToolkitDeploymentClient(fetcher) };
}

describe("administrator deployment settings persistence", () => {
  it("verifies selected index configuration and never scans defaults through an empty macro", async () => {
    for (const [options, expected] of [
      [{}, "configured"],
      [{ indexDefinition: "" }, "not_configured"],
      [{ indexDefinition: "index=netflow OR search *" }, "not_configured"],
      [{ unreadableIndex: true }, "unavailable"],
    ] as const) {
      const { client } = fixture(options);
      const settings = defaultExpectations();
      settings.sources.netflow.state = "active";
      const saved = await client.write(settings);
      expect(saved.sourceConfiguration?.netflow).toBe(expected);
      expect(
        selectedHealthProbes(saved).some(
          (probe) => probe.macro === "adm_health_source_netflow",
        ),
      ).toBe(expected === "configured");
      expect(
        selectedHealthProbes(saved).some(
          (probe) => probe.macro === "adm_health_quality_netflow",
        ),
      ).toBe(expected === "configured");
    }
  });
  it("verifies public selector coherence instead of trusting the version marker", async () => {
    expect((await fixture({ contract: 2 }).client.read()).activeContract).toBe(
      2,
    );
    expect(
      (await fixture({ contract: 2, mixedSelector: true }).client.read())
        .activeContract,
    ).toBeUndefined();
    expect(
      (await fixture({ missingSelector: true }).client.read()).activeContract,
    ).toBeUndefined();
  });
  it("distinguishes absent settings from restricted evidence", async () => {
    expect((await fixture().client.read()).state).toBe("absent");
    expect((await fixture({ unreadable: true }).client.read()).state).toBe(
      "unavailable",
    );
  });
  it("requires both effective admin capability and collection permission", async () => {
    for (const options of [{ admin: false }, { writable: false }]) {
      const { client, fetcher } = fixture(options);
      await expect(client.write(defaultExpectations())).rejects.toThrow(
        "Administrator",
      );
      expect(
        fetcher.mock.calls.some(([, init]) => init?.method === "POST"),
      ).toBe(false);
    }
  });
  it("persists a fixed shared document with CSRF protection and verifies readback", async () => {
    const { client, fetcher } = fixture();
    const settings = defaultExpectations();
    settings.sources.catalyst.state = "active";
    const saved = await client.write(settings);
    expect(saved.state).toBe("configured");
    expect(saved.settings?.sources.catalyst).toEqual(settings.sources.catalyst);
    expect(saved.activeContract).toBe(1);
    const write = fetcher.mock.calls.find(
      ([, init]) => init?.method === "POST",
    )!;
    expect(new Headers(write[1]?.headers).get("X-Splunk-Form-Key")).toBe(
      "csrf-test",
    );
    expect(JSON.parse(String(write[1]?.body))._key).toBe("deployment");
    await expect(client.write(settings)).rejects.toThrow("changed");
    expect((await client.write(settings, saved.settings!.revision)).state).toBe(
      "configured",
    );
  });
  it("fails readback and aborted writes without publishing a healthy configuration", async () => {
    await expect(
      fixture({ readbackMismatch: true }).client.write(defaultExpectations()),
    ).rejects.toThrow("readback");
    const { client, fetcher } = fixture();
    const controller = new AbortController();
    controller.abort();
    await expect(
      client.write(defaultExpectations(), undefined, controller.signal),
    ).rejects.toThrow("cancelled");
    expect(fetcher).not.toHaveBeenCalled();
  });
});
