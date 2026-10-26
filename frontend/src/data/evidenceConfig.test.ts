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
  detector = false,
  appd = false,
  thousandeyes = false,
  teBindings = "[]",
  detectorIds = '["detector-1"]',
  controllerOrigin = "https://controller.example.test",
} = {}) {
  const settings = defaultExpectations();
  if (active) settings.sources.dns_stream.state = "active";
  if (optional) {
    settings.sources.proxy_envoy.state = "active";
    settings.sources.proxy_envoy.staleAfterSeconds = 1500;
  }
  if (o11y) settings.sources.o11y_health.state = "active";
  if (detector) settings.sources.o11y_detector_events.state = "active";
  if (appd) settings.sources.appdynamics_inventory.state = "staged";
  if (thousandeyes) settings.sources.thousandeyes.state = "active";
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
    ...(detector
      ? [
          {
            _key: "detector",
            observer_kind: "o11y_detector",
            observer: "detector-exporter",
            scope: "prod",
            cluster: "cluster-a",
            mapping_status: "verified",
            organization_id: "org-a",
            realm: "us0",
            detector_ids: detectorIds,
          },
        ]
      : []),
    ...(appd
      ? [
          {
            _key: "controller",
            observer_kind: "appd_controller",
            observer: "controller-a",
            scope: "prod",
            cluster: "",
            mapping_status: "verified",
            controller_origin: controllerOrigin,
          },
        ]
      : []),
    ...(thousandeyes
      ? [
          {
            _key: "te",
            observer_kind: "thousandeyes_account_group",
            observer: "te-primary",
            scope: "prod",
            cluster: "",
            mapping_status: "verified",
            te_account_group_id: "1234",
            te_stream_account_id: "2345",
            te_alert_account_id: "3456",
            te_organization_id: "org-123",
            te_families: '["metric","alert"]',
            te_bindings: teBindings,
            te_path_sources: "[]",
            thousandeyes_origin: "https://app.thousandeyes.com",
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
          adm_index_o11y_detector_events: "index=atlas_o11y",
          adm_o11y_detector_events_schema_qualified: "0",
          adm_index_appdynamics_inventory: "index=atlas_asset",
          adm_appdynamics_inventory_schema_qualified: "0",
          adm_index_thousandeyes: "index=atlas_te",
          adm_thousandeyes_schema_qualified: "0",
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
      if (path.includes("storage/collections/data/") && Array.isArray(body)) {
        // KV returns only requested fields: a parser-only mock would hide a
        // missing browser REST projection even when fixtures contain the data.
        const fields = new Set(
          (url.searchParams.get("fields") ?? "").split(","),
        );
        body = body.map((row: Record<string, unknown>) =>
          Object.fromEntries(
            Object.entries(row).filter(([key]) => fields.has(key)),
          ),
        );
      }
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
  it("projects ThousandEyes identity and historical binding fields through shared app reads", async () => {
    const { client, fetcher } = fixture({ active: false, thousandeyes: true });
    const config = await client.read(undefined, [], "prod");
    expect(
      config.supplemental?.find((source) => source.source === "thousandeyes"),
    ).toMatchObject({
      state: "active",
      indexes: ["atlas_te"],
      authorities: ["te-primary"],
      schemaQualified: false,
      mappings: [
        expect.objectContaining({
          te_account_group_id: "1234",
          te_stream_account_id: "2345",
          te_alert_account_id: "3456",
          te_organization_id: "org-123",
          te_bindings: "[]",
          te_families: '["metric","alert"]',
          thousandeyes_origin: "https://app.thousandeyes.com",
        }),
      ],
    });
    expect(
      fetcher.mock.calls.every(([url]) =>
        String(url).includes('"owner":"nobody"'),
      ),
    ).toBe(true);
  });

  it("refuses malformed historical ThousandEyes bindings before source admission", async () => {
    const config = await fixture({
      active: false,
      thousandeyes: true,
      teBindings: '[{"authority":"other"}]',
    }).client.read(undefined, [], "prod");
    const source = config.supplemental?.find(
      (entry) => entry.source === "thousandeyes",
    );
    expect(source?.error).toBeDefined();
    expect(source?.authorities).toEqual([]);
  });
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
  it("admits selected detector bindings independently of metric MMS identity", async () => {
    const config = await fixture({ active: false, detector: true }).client.read(
      undefined,
      [],
      "prod",
    );
    expect(
      config.supplemental?.find((s) => s.source === "o11y_detector_events"),
    ).toMatchObject({
      state: "active",
      authorities: ["detector-exporter"],
      schemaQualified: false,
      mappings: [{ detector_ids: '["detector-1"]' }],
    });
    for (const detectorIds of [
      "[]",
      '["duplicate","duplicate"]',
      '["bad/id"]',
      "null",
      '"id"',
      "not json",
    ]) {
      const rejected = await fixture({
        active: false,
        detector: true,
        detectorIds,
      }).client.read(undefined, [], "prod");
      expect(
        rejected.supplemental?.find((s) => s.source === "o11y_detector_events")
          ?.error,
      ).toBeDefined();
      expect(rejected.summaryIndexes).toEqual(["adm_summary"]);
    }
  });
  it("rejects unsafe Controller navigation origins without blocking core configuration", async () => {
    const accepted = await fixture({ active: false, appd: true }).client.read(
      undefined,
      [],
      "prod",
    );
    expect(
      accepted.supplemental?.find((s) => s.source === "appdynamics_inventory"),
    ).toMatchObject({
      state: "staged",
      schemaQualified: false,
      mappings: [{ controller_origin: "https://controller.example.test" }],
    });
    for (const controllerOrigin of [
      "http://controller.example.test",
      "https://user:password@controller.example.test",
      "https://controller.example.test/path",
      "https://controller.example.test?token=unsafe",
      "https://controller.example.test#fragment",
      " https://controller.example.test",
      "javascript:alert(1)",
    ]) {
      const rejected = await fixture({
        active: false,
        appd: true,
        controllerOrigin,
      }).client.read(undefined, [], "prod");
      expect(
        rejected.supplemental?.find((s) => s.source === "appdynamics_inventory")
          ?.error,
      ).toBeDefined();
      expect(rejected.summaryIndexes).toEqual(["adm_summary"]);
    }
  });
  it("changes the configuration fingerprint when a Controller origin or detector binding changes", async () => {
    const first = await fixture({
      active: false,
      appd: true,
      detector: true,
    }).client.read(undefined, [], "prod");
    const moved = await fixture({
      active: false,
      appd: true,
      detector: true,
      controllerOrigin: "https://other-controller.example.test",
    }).client.read(undefined, [], "prod");
    const rebound = await fixture({
      active: false,
      appd: true,
      detector: true,
      detectorIds: '["detector-2"]',
    }).client.read(undefined, [], "prod");
    expect(first.fingerprint).not.toEqual(moved.fingerprint);
    expect(first.fingerprint).not.toEqual(rebound.fingerprint);
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
