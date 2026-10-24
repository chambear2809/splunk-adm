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
import { ToolkitEvidenceConfigClient } from "./evidenceConfig";
import { defaultExpectations, type DeploymentClient } from "./deploymentHealth";

function fixture({
  active = true,
  privateShadow = false,
  duplicates = false,
  lowCap = false,
  invalidBounds = false,
  identityNull = false,
  invalidIdentityEpoch = false,
  legacy = false,
  placeholderIndex = false,
  optional = false,
  optionalPlaceholder = false,
  o11y = false,
  invalidMms = false,
} = {}) {
  const settings = defaultExpectations();
  if (active) settings.sources.dns_stream.state = "active";
  if (optional) {
    settings.sources.proxy_envoy.state = "active";
    settings.sources.proxy_envoy.staleAfterSeconds = 1500;
  }
  if (o11y) settings.sources.o11y_health.state = "active";
  const deployment: DeploymentClient = {
    read: async () => ({
      state: "configured",
      settings,
      activeContract: 1,
      canWrite: false,
    }),
    write: async () => {
      throw Error("readonly");
    },
  };
  const mappings = [
    {
      _key: "one",
      observer_kind: "dns_sensor",
      observer: "sensor",
      scope: legacy ? "default" : "prod",
      cluster: "",
      mapping_status: "verified",
    },
    ...(duplicates
      ? [
          {
            _key: "two",
            observer_kind: "dns_sensor",
            observer: "sensor",
            scope: "elsewhere",
            cluster: "",
            mapping_status: "verified",
          },
        ]
      : []),
    ...(optional
      ? [
          {
            _key: "proxy",
            observer_kind: "envoy_proxy",
            observer: "proxy1",
            scope: "prod",
            cluster: "",
            mapping_status: "verified",
          },
        ]
      : []),
    ...(o11y
      ? [
          {
            _key: "o11y",
            observer_kind: "o11y_export",
            observer: "o11y-exporter",
            scope: "prod",
            cluster: "cluster-a",
            mapping_status: "verified",
            organization_id: "org-a",
            realm: "us0",
            apm_mms_id: invalidMms ? "bad,id" : "mms-123",
          },
        ]
      : []),
  ];
  const fetcher = vi.fn(
    async (input: RequestInfo | URL, init?: RequestInit) => {
      const path = String(input);
      const url = new URL(path, "https://example.test");
      let body: unknown;
      if (path.includes("conftypes/macros/stanzas:get")) {
        if (
          init?.method !== "POST" ||
          !(init.headers instanceof Headers) ||
          init.headers.get("Content-Type") !== "application/json" ||
          init.headers.get("X-Splunk-Form-Key") !== "test-csrf" ||
          init.headers.get("X-Requested-With") !== "XMLHttpRequest"
        )
          throw Error("wrong v1 read method");
        const name = (JSON.parse(String(init.body)) as { stanza: string })
          .stanza;
        expect(url.searchParams.get("view")).toBe("app-merged");
        const definitions: Record<string, string> = {
          adm_index_summary: "index=adm_summary",
          adm_summary_index_name: "adm_summary",
          adm_index_dns_stream: placeholderIndex
            ? "index=unconfigured_dns"
            : "index=dns",
          adm_dns_max_age_seconds: invalidBounds ? "10000000" : "3600",
          adm_dns_clock_uncertainty_seconds: "unknown",
          adm_dns_stream_schema_qualified: "0",
          adm_index_proxy_envoy: optionalPlaceholder
            ? "index=unconfigured_optional"
            : "index=proxy_evidence",
          adm_proxy_envoy_schema_qualified: "0",
          adm_index_o11y_health: "index=atlas_o11y",
          adm_o11y_health_schema_qualified: "1",
        };
        body = {
          settings: [
            {
              setting: "definition",
              value:
                privateShadow &&
                (!path.includes('"owner":"nobody"') ||
                  url.searchParams.get("view") !== "app-merged")
                  ? "index=private_dns_shadow"
                  : definitions[name],
            },
          ],
        };
      } else if (path.includes("adm_observer_scope"))
        body = lowCap
          ? mappings
          : url.searchParams.has("skip")
            ? mappings.slice(1)
            : mappings;
      else if (path.includes("adm_ip_identity"))
        body = url.searchParams.has("skip")
          ? []
          : [
              {
                _key: "identity",
                ip: "10.0.0.1",
                scope: legacy ? "default" : "prod",
                entity_kind: "pod",
                entity_id: "uid",
                valid_from: identityNull
                  ? null
                  : invalidIdentityEpoch
                    ? 1e20
                    : 100,
                valid_end: 500,
                scope_mapping_verified: legacy ? 0 : 1,
              },
            ];
      else throw Error("unexpected request");
      return {
        ok: true,
        status: 200,
        text: async () => JSON.stringify(body),
      } as Response;
    },
  );
  return {
    client: new ToolkitEvidenceConfigClient(fetcher, deployment),
    fetcher,
  };
}
describe("caller-context evidence configuration", () => {
  it("uses explicit app/shared reads and treats unselected old settings as inert", async () => {
    const { client, fetcher } = fixture({ active: false });
    const config = await client.read(undefined, ["10.0.0.1"], "prod");
    expect(config.dns.every((s) => s.state === "not_selected")).toBe(true);
    expect(config.supplemental?.every((s) => s.state === "not_selected")).toBe(
      true,
    );
    expect(
      fetcher.mock.calls.every(([url]) =>
        String(url).includes('"owner":"nobody"'),
      ),
    ).toBe(true);
    expect(
      fetcher.mock.calls.some(([, init]) =>
        String(init?.body).includes("adm_index_dns_stream"),
      ),
    ).toBe(false);
  });
  it("selects only a verified optional authority and rejects its placeholder index", async () => {
    const ready = await fixture({ active: false, optional: true }).client.read(
      undefined,
      [],
      "prod",
    );
    expect(
      ready.supplemental?.find((s) => s.source === "proxy_envoy"),
    ).toMatchObject({
      state: "active",
      authorities: ["proxy1"],
      indexes: ["proxy_evidence"],
      schemaQualified: false,
      staleAfterSeconds: 1500,
    });
    const placeholder = await fixture({
      active: false,
      optional: true,
      optionalPlaceholder: true,
    }).client.read(undefined, [], "prod");
    expect(
      placeholder.supplemental?.find((s) => s.source === "proxy_envoy")?.error,
    ).toBeDefined();
  });
  it("requires an exact custom MMS ID before exposing the Observability authority", async () => {
    const qualified = await fixture({ active: false, o11y: true }).client.read(
      undefined,
      [],
      "prod",
    );
    expect(
      qualified.supplemental?.find((s) => s.source === "o11y_health"),
    ).toMatchObject({
      state: "active",
      authorities: ["o11y-exporter"],
      mappings: [{ apm_mms_id: "mms-123" }],
      schemaQualified: true,
    });
    const unqualified = await fixture({
      active: false,
      o11y: true,
      invalidMms: true,
    }).client.read(undefined, [], "prod");
    expect(
      unqualified.supplemental?.find((s) => s.source === "o11y_health")?.error,
    ).toBeDefined();
  });
  it("uses the explicit nobody app-merged view despite a private shadow", async () => {
    const { client, fetcher } = fixture({ privateShadow: true });
    const result = await client.read();
    expect(result.summaryIndexes).toEqual(["adm_summary"]);
    expect(
      fetcher.mock.calls.some(
        ([url, init]) =>
          String(url).includes("stanzas:get") &&
          init?.method === "POST" &&
          String(init.body).includes("adm_index_summary"),
      ),
    ).toBe(true);
  });
  it("suppresses DNS for conflicting source authority or unreadable bounds without blocking core config", async () => {
    for (const options of [
      { duplicates: true },
      { invalidBounds: true },
      { placeholderIndex: true },
    ]) {
      const config = await fixture(options).client.read(
        undefined,
        ["10.0.0.1"],
        "prod",
      );
      expect(config.summaryIndexes).toEqual(["adm_summary"]);
      expect(config.dns[0].error).toBeDefined();
    }
  });
  it("detects lower server caps and quarantines unverified legacy-default identities", async () => {
    await expect(fixture({ lowCap: true }).client.read()).rejects.toThrow(
      /completeness/,
    );
    const config = await fixture({ legacy: true }).client.read(
      undefined,
      ["10.0.0.1"],
      "default",
    );
    expect(config.identities).toEqual([]);
  });
  it("fails identity attribution closed for malformed ownership intervals", async () => {
    const config = await fixture({ identityNull: true }).client.read(
      undefined,
      ["10.0.0.1"],
      "prod",
    );
    expect(config.identityAvailable).toBe(false);
    expect(config.identities).toEqual([]);
  });
  it("fails identity attribution closed for an unrenderable epoch", async () => {
    const config = await fixture({ invalidIdentityEpoch: true }).client.read(
      undefined,
      ["10.0.0.1"],
      "prod",
    );
    expect(config.identityAvailable).toBe(false);
    expect(config.identities).toEqual([]);
  });
  it("reads bounded scoped IPv6 ownership history before canonical comparison, retaining equivalent conflicts", async () => {
    const original = fixture({ active: false });
    const fetcher = vi.fn(
      async (input: RequestInfo | URL, init?: RequestInit) => {
        if (String(input).includes("adm_ip_identity")) {
          const url = new URL(String(input), "https://example.test");
          expect(JSON.parse(url.searchParams.get("query")!)).toEqual({
            scope: "prod",
          });
          const all = [
            {
              _key: "one",
              ip: "2001:0db8:0:0:0:0:0:1",
              scope: "prod",
              entity_kind: "pod",
              entity_id: "old",
              valid_from: 100,
              valid_end: 300,
            },
            {
              _key: "two",
              ip: "2001:db8::1",
              scope: "prod",
              entity_kind: "pod",
              entity_id: "new",
              valid_from: 200,
              valid_end: 500,
            },
          ];
          return {
            ok: true,
            status: 200,
            text: async () =>
              JSON.stringify(url.searchParams.has("skip") ? all.slice(1) : all),
          } as Response;
        }
        return original.fetcher(input, init);
      },
    );
    const settings = defaultExpectations();
    const client = new ToolkitEvidenceConfigClient(fetcher, {
      read: async () => ({
        state: "configured",
        settings,
        activeContract: 1,
        canWrite: false,
      }),
      write: async () => {
        throw Error("readonly");
      },
    });
    const config = await client.read(undefined, ["2001:db8::1"], "prod");
    expect(config.identityAvailable).toBe(true);
    expect(config.identities.map((o) => o.ip)).toEqual([
      "2001:db8::1",
      "2001:db8::1",
    ]);
    expect(config.identities.map((o) => o.entity_id)).toEqual(["old", "new"]);
  });
});
