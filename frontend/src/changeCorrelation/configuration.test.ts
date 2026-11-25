import { describe, expect, it, vi } from "vitest";
vi.mock("@splunk/splunk-utils/url", () => ({
  createRESTURL: (path: string, context: unknown) =>
    `/rest/${JSON.stringify(context)}/${path}`,
}));
vi.mock("@splunk/splunk-utils/fetch", () => ({
  getDefaultFetchInit: () => ({
    credentials: "same-origin",
    headers: {
      "X-Splunk-Form-Key": "test-csrf",
      "X-Requested-With": "XMLHttpRequest",
    },
  }),
}));

import { ToolkitChangeTimelineConfigurationClient } from "./configuration";

const jsonResponse = (payload: unknown, status = 200) =>
  new Response(JSON.stringify(payload), {
    status,
    headers: { "Content-Type": "application/json" },
  });

function macroFetcher(definitions: Record<string, string>) {
  const calls: { name: string; path: string }[] = [];
  const fetcher = vi.fn(
    async (input: RequestInfo | URL, init?: RequestInit) => {
      const path = String(input);
      const url = new URL(path, "https://example.test");
      if (
        init?.method !== "POST" ||
        !(init.headers instanceof Headers) ||
        init.headers.get("Content-Type") !== "application/json" ||
        init.headers.get("X-Splunk-Form-Key") !== "test-csrf" ||
        init.headers.get("X-Requested-With") !== "XMLHttpRequest" ||
        url.searchParams.get("view") !== "app-merged" ||
        !path.includes('"app":"splunk_adm","owner":"nobody"')
      )
        throw new Error("Incorrect caller-owned app-merged macro read.");
      const body = JSON.parse(String(init.body)) as { stanza: string };
      calls.push({ name: body.stanza, path });
      const definition = definitions[body.stanza];
      if (definition === undefined) return jsonResponse({ settings: [] });
      return jsonResponse({
        settings: [{ setting: "definition", value: definition }],
      });
    },
  );
  return { fetcher, calls };
}

describe("optional configuration history selector", () => {
  it("reads the disabled flag first and does not read index or activation while off", async () => {
    const { fetcher, calls } = macroFetcher({
      adm_configuration_history_enabled: "0",
      adm_index_configuration_changes: "index=atlas_changes",
      adm_configuration_activation: "a".repeat(64),
    });
    const client = new ToolkitChangeTimelineConfigurationClient(fetcher);

    await expect(client.read()).resolves.toEqual({ state: "not_selected" });
    expect(calls.map(({ name }) => name)).toEqual([
      "adm_configuration_history_enabled",
    ]);
  });

  it("requires one literal index and lowercase activation hash when enabled", async () => {
    const activationId = "a".repeat(64);
    const { fetcher, calls } = macroFetcher({
      adm_configuration_history_enabled: "1",
      adm_index_configuration_changes: "index=atlas_changes",
      adm_configuration_activation: activationId,
    });
    const client = new ToolkitChangeTimelineConfigurationClient(fetcher);

    await expect(client.read()).resolves.toEqual({
      state: "selected",
      index: "atlas_changes",
      activation_id: activationId,
    });
    expect(calls.map(({ name }) => name)).toEqual([
      "adm_configuration_history_enabled",
      "adm_index_configuration_changes",
      "adm_configuration_activation",
    ]);
  });

  it.each([
    {
      label: "bad index",
      index: "index=atlas_changes OR index=other",
      activation: "a".repeat(64),
      enabled: "1",
    },
    {
      label: "placeholder index",
      index: "index=unconfigured_optional",
      activation: "a".repeat(64),
      enabled: "1",
    },
    {
      label: "bad activation",
      index: "index=atlas_changes",
      activation: "unconfigured",
      enabled: "1",
    },
    {
      label: "bad enabled value",
      index: "index=atlas_changes",
      activation: "a".repeat(64),
      enabled: "true",
    },
  ])("fails closed for $label", async ({ index, activation, enabled }) => {
    const { fetcher } = macroFetcher({
      adm_configuration_history_enabled: enabled,
      adm_index_configuration_changes: index,
      adm_configuration_activation: activation,
    });
    const client = new ToolkitChangeTimelineConfigurationClient(fetcher);
    await expect(client.read()).rejects.toThrow(/unavailable/i);
  });

  it("reports caller denial as unavailable instead of selecting a fallback", async () => {
    const fetcher = vi.fn(async () => jsonResponse({}, 403));
    const client = new ToolkitChangeTimelineConfigurationClient(fetcher);
    await expect(client.read()).rejects.toThrow(/unavailable/i);
    expect(fetcher).toHaveBeenCalledTimes(1);
  });
});
