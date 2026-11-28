import { readFileSync } from "node:fs";
import { describe, expect, it, vi } from "vitest";
import { protocolConfigClient } from "../../../data/evidenceConfig";
import {
  SearchAccessDeniedError,
  type SearchClient,
} from "../../../data/searchClient";
import { parseProtocolProfiles } from "../../inputs";
import type {
  BaseProtocolProfile,
  ProtocolConfiguration,
  ProtocolRequest,
} from "../../shared/contract";
import {
  FORBIDDEN_SENSITIVE_FIELDS,
  LENS_FIELD_ALLOWLISTS,
  SQL_FORBIDDEN_FIELDS,
  assertNoForbiddenFieldsInSpl,
} from "../../shared/fields";
import { readProtocolConfiguration } from "../../shared/runner";
import {
  DB_PROJECTED_FIELDS,
  buildAppTransactionsAnalysis,
  buildAppTransactionsRawEventsUrl,
  buildAppTransactionsSearch,
  buildOtelTransactionsSearch,
  investigateAppTransactions,
  makeAppTransactionRowId,
  normalizeAppTransactionRow,
  resolveAppTransactionsThresholds,
  sanitizeUriPath,
  summarizeAppTransactions,
  validateAppTransactionsExtra,
} from "./adapter";

const EARLIEST = 1764246500;
const NOW = 1764247100;

function makeProfile(
  overrides: Partial<BaseProtocolProfile> = {},
): BaseProtocolProfile {
  return {
    id: "app-txns-dc1",
    source: "protocol_app_transactions",
    lens: "app_transactions",
    scope: "prod:dc1",
    index: "stream_app",
    observer: "stream-fwd-01",
    validFrom: EARLIEST - 3600,
    validUntil: NOW + 3600,
    ...overrides,
  };
}

function makeConfig(
  profiles: BaseProtocolProfile[],
  fingerprint = "fp-initial",
): ProtocolConfiguration {
  return { profiles, fingerprint };
}

function makeRequest(
  overrides: Partial<ProtocolRequest> = {},
): ProtocolRequest {
  return {
    version: 1,
    lens: "app_transactions",
    scope: "prod:dc1",
    earliest: EARLIEST,
    latest: NOW,
    ...overrides,
  };
}

describe("validateAppTransactionsExtra (fail-closed profile validation)", () => {
  it("accepts valid configuration and integrates with parseProtocolProfiles", () => {
    expect(validateAppTransactionsExtra(undefined)).toBeUndefined();
    expect(
      validateAppTransactionsExtra({
        sourceKind: "http",
        errorRateWarnPct: 2.5,
        latencyWarnMs: 250,
      }),
    ).toEqual({
      sourceKind: "http",
      errorRateWarnPct: 2.5,
      latencyWarnMs: 250,
    });
    expect(
      validateAppTransactionsExtra({
        sourceKind: "db",
        errorRateWarnPct: 100,
        latencyWarnMs: 60_000,
      }),
    ).toEqual({
      sourceKind: "db",
      errorRateWarnPct: 100,
      latencyWarnMs: 60_000,
    });

    const profiles = parseProtocolProfiles(
      {
        version: 1,
        profiles: [
          {
            id: "app-txns-dc1",
            source: "protocol_app_transactions",
            lens: "app_transactions",
            scope: "prod:dc1",
            index: "stream_app",
            observer: "stream-fwd-01",
            validFrom: EARLIEST - 3600,
            validUntil: NOW + 3600,
            extra: { latencyWarnMs: 400 },
          },
        ],
      },
      { app_transactions: validateAppTransactionsExtra },
    );
    expect(resolveAppTransactionsThresholds(profiles[0])).toEqual({
      sourceKind: "auto",
      errorRateWarnPct: 5,
      latencyWarnMs: 400,
    });
  });

  it("rejects unknown keys and out-of-range thresholds", () => {
    expect(() => validateAppTransactionsExtra({ unknownKey: true })).toThrow(
      /Unsupported app_transactions/,
    );
    expect(() =>
      validateAppTransactionsExtra({ sourceKind: "grpc" as never }),
    ).toThrow(/sourceKind/);
    expect(() => validateAppTransactionsExtra({ errorRateWarnPct: 0 })).toThrow(
      /errorRateWarnPct/,
    );
    expect(() =>
      validateAppTransactionsExtra({ errorRateWarnPct: -1 }),
    ).toThrow(/errorRateWarnPct/);
    expect(() =>
      validateAppTransactionsExtra({ errorRateWarnPct: 101 }),
    ).toThrow(/errorRateWarnPct/);
    expect(() => validateAppTransactionsExtra({ latencyWarnMs: 0 })).toThrow(
      /latencyWarnMs/,
    );
    expect(() =>
      validateAppTransactionsExtra({ latencyWarnMs: 60_001 }),
    ).toThrow(/latencyWarnMs/);
    expect(() =>
      validateAppTransactionsExtra({ latencyWarnMs: Number.NaN }),
    ).toThrow(/latencyWarnMs/);
  });
});

describe("SPL builders, privacy boundary, and normalization helpers", () => {
  it("emits | head BEFORE | table and never references SQL query or sensitive fields", () => {
    for (const kind of ["http", "db"] as const) {
      const spl = buildAppTransactionsSearch({
        index: "stream_app",
        kind,
        filter: {
          src: "10.42.0.20",
          dst: "10.42.0.30",
          device: "stream-fwd-01",
        },
        maxRows: 256,
      });
      const headIdx = spl.indexOf("| head 257");
      const tableIdx = spl.indexOf("| table ");
      expect(headIdx).toBeGreaterThan(0);
      expect(tableIdx).toBeGreaterThan(headIdx);
      expect(spl.slice(headIdx)).not.toContain("| where ");
      expect(() =>
        assertNoForbiddenFieldsInSpl("app_transactions", spl),
      ).not.toThrow();

      for (const bad of [
        ...FORBIDDEN_SENSITIVE_FIELDS,
        ...SQL_FORBIDDEN_FIELDS,
      ]) {
        expect(spl.toLowerCase()).not.toMatch(new RegExp(`\\b${bad}\\b`));
      }
    }

    expect(DB_PROJECTED_FIELDS).not.toContain("error");
    const dbSpl = buildAppTransactionsSearch({
      index: "stream_app",
      kind: "db",
      maxRows: 256,
    });
    const dbTableIdx = dbSpl.indexOf("| table ");
    expect(dbSpl.slice(0, dbTableIdx)).toContain(
      'if(isnotnull(error) AND error!="", "SQL_ERROR", null())',
    );
    expect(dbSpl.slice(dbTableIdx)).not.toMatch(/\berror\b/);
  });

  it("builds literal()-quoted raw events URL and safe row IDs without ->", () => {
    const url = buildAppTransactionsRawEventsUrl({
      index: "stream_app",
      serverIp: "10.42.0.50",
      destPort: 5432,
      sourcetypes: ["stream:postgres"],
      earliest: EARLIEST,
      latest: NOW,
    });
    expect(url).toContain("/app/splunk_adm/search?");
    const decoded = decodeURIComponent(url);
    expect(decoded).toContain("index=stream_app");
    expect(decoded).toContain('dest_ip="10.42.0.50"');
    expect(decoded).toContain("dest_port=5432");
    expect(decoded).not.toContain("query");

    const id = makeAppTransactionRowId(
      "TDS / SQL Server",
      "2001:0db8:85a3:0000:0000:8a2e:0370:7334",
      1433,
    );
    expect(id).toMatch(/^[A-Za-z0-9._:/-]{1,128}$/);
    expect(id).not.toContain("->");
  });

  it("defensively strips query strings and fragments from uri_path", () => {
    expect(sanitizeUriPath("/api/v1/orders?token=secret123&user=alice")).toBe(
      "/api/v1/orders",
    );
    expect(sanitizeUriPath("/checkout#step2")).toBe("/checkout");
    expect(sanitizeUriPath("?only=query")).toBeUndefined();

    const norm = normalizeAppTransactionRow(
      {
        _time: EARLIEST + 10,
        sourcetype: "stream:http",
        src_ip: "10.42.0.20",
        dest_ip: "10.42.0.30",
        dest_port: 8080,
        http_method: "get",
        status: 200,
        uri_path: "/api/v1/items?apiKey=secret",
        time_taken: 45_000,
      },
      "http",
    )!;
    expect(norm.uriPath).toBe("/api/v1/items");
    expect(norm.httpMethod).toBe("GET");
    expect(norm.latencyMs).toBe(45);
  });

  it("normalizes DB errors across sql_error_code arrays, maps free-text error strings strictly to SQL_ERROR, and uses response_time fallback", () => {
    const tdsErr = normalizeAppTransactionRow(
      {
        _time: EARLIEST + 20,
        sourcetype: "stream:tds",
        src_ip: "10.42.0.30",
        dest_ip: "10.42.0.52",
        dest_port: 1433,
        dbname: "ledger_db",
        sql_error_code: ["0", "1205"],
        response_time: 610_000,
        result_row_count: 0,
      },
      "db",
    )!;
    expect(tdsErr.protocolLabel).toBe("TDS / SQL Server");
    expect(tdsErr.isError).toBe(true);
    expect(tdsErr.sqlErrorCode).toBe("1205");
    expect(tdsErr.latencyMs).toBe(610);

    const pgOk = normalizeAppTransactionRow(
      {
        _time: EARLIEST + 25,
        sourcetype: "stream:postgres",
        src_ip: "10.42.0.30",
        dest_ip: "10.42.0.50",
        dest_port: 5432,
        dbname: "orders_db",
        sql_error_code: "00000",
        time_taken: 12_000,
      },
      "db",
    )!;
    expect(pgOk.hasStatusSample).toBe(true);
    expect(pgOk.isError).toBe(false);
    expect(pgOk.latencyMs).toBe(12);

    const legacyFreeTextErr = normalizeAppTransactionRow(
      {
        _time: EARLIEST + 30,
        sourcetype: "stream:postgres",
        src_ip: "10.42.0.30",
        dest_ip: "10.42.0.50",
        dest_port: 5432,
        dbname: "orders_db",
        error: 'syntax error at or near "SELECT secret_col FROM users"',
        time_taken: 18_000,
      },
      "db",
    )!;
    expect(legacyFreeTextErr.isError).toBe(true);
    expect(legacyFreeTextErr.sqlErrorCode).toBe("SQL_ERROR");
    expect(legacyFreeTextErr.errorLabel).toBe("SQL_ERROR");

    const freeTextCode = normalizeAppTransactionRow(
      {
        _time: EARLIEST + 35,
        sourcetype: "stream:postgres",
        src_ip: "10.42.0.30",
        dest_ip: "10.42.0.50",
        dest_port: 5432,
        dbname: "orders_db",
        sql_error_code: "deadlock detected on table secret_orders",
        time_taken: 22_000,
      },
      "db",
    )!;
    expect(freeTextCode.isError).toBe(true);
    expect(freeTextCode.sqlErrorCode).toBe("SQL_ERROR");
    expect(freeTextCode.errorLabel).toBe("SQL_ERROR");
    expect(JSON.stringify(freeTextCode)).not.toContain("secret_orders");
  });
});

describe("Grounded fixture analysis (stream_http + stream_db)", () => {
  it("keeps forbidden sensitive fields, SQL query text, and raw error out of fixture files", () => {
    const httpRaw = readFileSync(
      "fixtures/protocols/app_transactions/stream_http.ndjson",
      "utf8",
    );
    const dbRaw = readFileSync(
      "fixtures/protocols/app_transactions/stream_db.ndjson",
      "utf8",
    );
    for (const line of [
      ...httpRaw.trim().split("\n"),
      ...dbRaw.trim().split("\n"),
    ]) {
      const obj = JSON.parse(line) as Record<string, unknown>;
      for (const key of Object.keys(obj)) {
        expect(FORBIDDEN_SENSITIVE_FIELDS.has(key)).toBe(false);
        expect(SQL_FORBIDDEN_FIELDS.has(key)).toBe(false);
        expect(LENS_FIELD_ALLOWLISTS.app_transactions.includes(key)).toBe(true);
      }
    }
  });

  it("correlates grounded HTTP and DB fixtures into golden signals, DistributionBar, HeatMatrix, and SwimlaneTimeline", () => {
    const httpLines = readFileSync(
      "fixtures/protocols/app_transactions/stream_http.ndjson",
      "utf8",
    )
      .trim()
      .split("\n")
      .map((l) => JSON.parse(l) as Record<string, unknown>);
    const dbLines = readFileSync(
      "fixtures/protocols/app_transactions/stream_db.ndjson",
      "utf8",
    )
      .trim()
      .split("\n")
      .map((l) => JSON.parse(l) as Record<string, unknown>);

    const events = [
      ...httpLines.map((r) => ({
        event: normalizeAppTransactionRow(r, "http")!,
        indexName: "stream_app",
      })),
      ...dbLines.map((r) => ({
        event: normalizeAppTransactionRow(r, "db")!,
        indexName: "stream_app",
      })),
    ];

    const result = buildAppTransactionsAnalysis({
      events,
      thresholds: resolveAppTransactionsThresholds(),
      earliest: EARLIEST,
      latest: NOW,
      outcomes: [
        {
          source: "protocol_app_transactions",
          profile: "app-txns-dc1",
          state: "complete",
        },
      ],
      capped: false,
      httpConfigured: true,
      dbConfigured: true,
    });

    expect(result.verdictStatus).toBe("attention");
    expect(result.verdict).toContain("of 7 services need attention");
    expect(result.kpis).toHaveLength(4);
    expect(result.kpis.map((k) => k.id)).toEqual([
      "transactions",
      "error-rate",
      "p95-latency",
      "flagged-services",
    ]);
    expect(result.sourceMode).toBe("mixed");

    // Flagged services sort before healthy services, all IDs valid
    expect(result.rows).toHaveLength(7);
    const flaggedCount = result.rows.filter((r) => r.attention).length;
    expect(flaggedCount).toBe(4);
    for (const row of result.rows) {
      expect(row.id).toMatch(/^[A-Za-z0-9._:/-]{1,128}$/);
      expect(row.id).not.toContain("->");
    }

    const checkout = result.rows.find((r) => r.serverIp === "10.42.0.30")!;
    expect(checkout.attention).toBe(true);
    expect(checkout.http5xxCount).toBe(2);
    expect(checkout.errorPct).toBeCloseTo(40, 1);
    expect(checkout.latencyP95Ms).toBe(920);

    const postgres = result.rows.find((r) => r.serverIp === "10.42.0.50")!;
    expect(postgres.attention).toBe(true);
    expect(postgres.sqlErrorCount).toBe(1);
    expect(postgres.latencyP95Ms).toBe(680);

    const catalog = result.rows.find((r) => r.serverIp === "10.42.0.32")!;
    expect(catalog.attention).toBe(false);
    expect(catalog.status).toBe("ok");

    expect(result.distribution.length).toBeGreaterThan(0);
    for (const item of result.distribution) {
      expect(item.label).not.toContain("(");
    }
    expect(result.matrixRows.length).toBeGreaterThan(0);
    expect(result.matrixCols.length).toBeGreaterThan(0);
    expect(result.timelineEvents.some((e) => e.label === "HTTP 503")).toBe(
      true,
    );
    expect(
      result.timelineEvents.some((e) => e.label.includes("SQL error 40001")),
    ).toBe(true);
  });
});

describe("investigateAppTransactions & summarizeAppTransactions", () => {
  it("runs Stream Estimate check ONLY when a queried stream group returns 0 rows", async () => {
    const search = vi
      .fn()
      // stream:http returns 1 row
      .mockResolvedValueOnce({
        rows: [
          {
            _time: EARLIEST + 10,
            sourcetype: "stream:http",
            src_ip: "10.42.0.20",
            dest_ip: "10.42.0.32",
            dest_port: 8080,
            http_method: "GET",
            status: 200,
            uri_path: "/healthz",
            time_taken: 18_000,
          },
        ],
        warnings: [],
        errors: [],
      })
      // DB streams return 0 rows
      .mockResolvedValueOnce({ rows: [], warnings: [], errors: [] })
      // checkStreamEstimateMode(["mysql", "postgres", "tds", "tns"])
      .mockResolvedValueOnce({
        rows: [
          { host: "stream-fwd-01", stream_id: "mysql", stats_only: "true" },
          { host: "stream-fwd-01", stream_id: "postgres", stats_only: "true" },
        ],
        warnings: [],
        errors: [],
      });

    const result = await investigateAppTransactions(
      { search },
      makeRequest(),
      makeConfig([makeProfile()]),
      new AbortController().signal,
      { skipConfigRecheck: true },
    );

    expect(search).toHaveBeenCalledTimes(3);
    const readinessSpl = search.mock.calls[2][0].search as string;
    expect(readinessSpl).toContain('sourcetype="stream:stats"');
    expect(readinessSpl).not.toContain('"http"');
    expect(readinessSpl).toContain('"mysql"');
    expect(result.bannerState).toBe("estimate_only");
    expect(result.rows).toHaveLength(1);
  });

  it("does NOT run Stream Estimate check when both HTTP and DB return rows", async () => {
    const search = vi
      .fn()
      .mockResolvedValueOnce({
        rows: [
          {
            _time: EARLIEST + 10,
            sourcetype: "stream:http",
            src_ip: "10.42.0.20",
            dest_ip: "10.42.0.32",
            dest_port: 8080,
            status: 200,
            time_taken: 20_000,
          },
        ],
        warnings: [],
        errors: [],
      })
      .mockResolvedValueOnce({
        rows: [
          {
            _time: EARLIEST + 20,
            sourcetype: "stream:mysql",
            src_ip: "10.42.0.32",
            dest_ip: "10.42.0.51",
            dest_port: 3306,
            dbname: "inventory_db",
            sql_error_code: "0",
            time_taken: 15_000,
          },
        ],
        warnings: [],
        errors: [],
      });

    const result = await investigateAppTransactions(
      { search },
      makeRequest(),
      makeConfig([makeProfile()]),
      new AbortController().signal,
      { skipConfigRecheck: true },
    );

    expect(search).toHaveBeenCalledTimes(2);
    expect(result.verdictStatus).toBe("ok");
  });

  it("downgrades capped-empty to unknown (never none_observed) and downgrades degraded summaries", async () => {
    const cappedEmpty = await summarizeAppTransactions(
      {
        search: vi.fn().mockResolvedValue({
          rows: [],
          truncated: true,
          warnings: [],
          errors: [],
        }),
      },
      makeRequest(),
      makeConfig([makeProfile({ extra: { sourceKind: "http" } })]),
      new AbortController().signal,
      { skipConfigRecheck: true },
    );
    expect(cappedEmpty.status).toBe("unknown");
    expect(cappedEmpty.capped).toBe(true);

    // Healthy HTTP + blocked DB -> summarizeAppTransactions downgrades ok -> attention
    const searchBlocked = vi
      .fn()
      .mockResolvedValueOnce({
        rows: [
          {
            _time: EARLIEST + 10,
            sourcetype: "stream:http",
            src_ip: "10.42.0.20",
            dest_ip: "10.42.0.32",
            dest_port: 8080,
            status: 200,
            time_taken: 20_000,
          },
        ],
        warnings: [],
        errors: [],
      })
      .mockRejectedValueOnce(new SearchAccessDeniedError());

    const degradedOk = await summarizeAppTransactions(
      { search: searchBlocked },
      makeRequest(),
      makeConfig([makeProfile()]),
      new AbortController().signal,
      { skipConfigRecheck: true },
    );
    expect(degradedOk.status).toBe("attention");
  });

  it("reports unknown/unavailable when raw rows are returned but none normalize (never none_observed)", async () => {
    const search = vi.fn().mockResolvedValue({
      rows: [
        { _time: EARLIEST + 10, sourcetype: "stream:http" },
        {
          _time: EARLIEST + 20,
          sourcetype: "stream:http",
          status: 200,
        },
      ],
      warnings: [],
      errors: [],
    });

    const result = await investigateAppTransactions(
      { search },
      makeRequest(),
      makeConfig([makeProfile({ extra: { sourceKind: "http" } })]),
      new AbortController().signal,
      { skipConfigRecheck: true },
    );

    expect(result.verdictStatus).toBe("unknown");
    expect(result.coverageStatus).toBe("unknown");
    expect(result.bannerState).toBe("unavailable");
    expect(result.verdict).toContain(
      "2 rows returned but could not be normalized",
    );
    expect(result.bannerReason).toContain(
      "2 rows returned but could not be normalized",
    );

    const summary = await summarizeAppTransactions(
      { search },
      makeRequest(),
      makeConfig([makeProfile({ extra: { sourceKind: "http" } })]),
      new AbortController().signal,
      { skipConfigRecheck: true },
    );
    expect(summary.status).toBe("unknown");
  });

  it("strips forbidden sensitive fields and enforces stale-config recheck with profileValidators", async () => {
    const search = vi.fn().mockResolvedValue({
      rows: [
        {
          _time: EARLIEST + 10,
          sourcetype: "stream:postgres",
          src_ip: "10.42.0.30",
          dest_ip: "10.42.0.50",
          dest_port: 5432,
          dbname: "orders_db",
          sql_error_code: "00000",
          time_taken: 25_000,
          query: "SELECT * FROM secret_table WHERE ssn='123'",
          sql_statement: "SELECT",
          bind_variable_value: "secret-bind",
          uri_query: "token=secret",
          cookie: "session=secret",
          form_data: "pw=secret",
          login: "admin",
          _raw: "raw-secret",
        },
      ],
      warnings: [],
      errors: [],
    });
    const client: SearchClient = { search };
    const profile = makeProfile({ extra: { sourceKind: "db" } });

    const spy = vi
      .spyOn(protocolConfigClient, "readProtocolProfileDocument")
      .mockResolvedValue({
        version: 1,
        profiles: [profile],
      });
    try {
      const config = await readProtocolConfiguration({
        app_transactions: validateAppTransactionsExtra,
      });
      const summary = await summarizeAppTransactions(
        client,
        makeRequest(),
        config,
        new AbortController().signal,
        {
          profileValidators: { app_transactions: validateAppTransactionsExtra },
        },
      );
      expect(summary.status).toBe("ok");

      spy.mockResolvedValueOnce({
        version: 1,
        profiles: [
          makeProfile({
            index: "other_stream_db",
            extra: { sourceKind: "db" },
          }),
        ],
      });
      const stale = await investigateAppTransactions(
        client,
        makeRequest(),
        config,
        new AbortController().signal,
        {
          profileValidators: { app_transactions: validateAppTransactionsExtra },
        },
      );
      expect(stale.bannerState).toBe("stale_config");
      expect(stale.rows).toEqual([]);
    } finally {
      spy.mockRestore();
    }
  });

  it("propagates AbortError when AbortSignal fires", async () => {
    const controller = new AbortController();
    const search = vi.fn().mockImplementation(() => {
      controller.abort();
      return Promise.reject(new DOMException("Aborted", "AbortError"));
    });
    await expect(
      investigateAppTransactions(
        { search },
        makeRequest(),
        makeConfig([makeProfile({ extra: { sourceKind: "http" } })]),
        controller.signal,
        { skipConfigRecheck: true },
      ),
    ).rejects.toThrow();
  });

  it("supports otel:traces HTTP and DB spans without ever selecting SQL query text", async () => {
    const spl = buildOtelTransactionsSearch({
      index: "otel_traces",
      filter: { src: "10.1.175.14", port: "8080" },
      maxRows: 256,
    });
    expect(spl).toContain('sourcetype="otel:traces"');
    expect(spl).toContain("attributes.http.request.method=*");
    expect(spl).toContain("attributes.db.system=*");
    expect(spl).not.toContain("db.statement");
    expect(spl).not.toContain("url.query");
    expect(spl.indexOf("| head 257")).toBeLessThan(spl.indexOf("| table "));
    expect(() =>
      assertNoForbiddenFieldsInSpl("app_transactions", spl),
    ).not.toThrow();

    const search = vi.fn().mockResolvedValue({
      rows: [
        {
          _time: EARLIEST + 30,
          host: "teastore-microk8s",
          sourcetype: "otel:traces",
          src_ip: "10.1.175.14",
          dest_ip: "teastore-persistence",
          dest_port: 8080,
          http_method: "GET",
          status: "ERROR",
          status_code: 500,
          error_code: "OTEL_ERROR",
          uri_path: "/rest/categories",
          site: "teastore-persistence",
          time_taken: 4200,
        },
        {
          _time: EARLIEST + 35,
          host: "teastore-microk8s",
          sourcetype: "otel:traces",
          src_ip: "10.1.175.14",
          dest_ip: "teastore-db",
          dest_port: 3306,
          db_type: "mysql",
          database: "teadb",
          status: "OK",
          time_taken: 1800,
        },
      ],
      warnings: [],
      errors: [],
    });

    const res = await investigateAppTransactions(
      { search },
      makeRequest(),
      makeConfig([
        makeProfile({
          id: "otel-teastore",
          index: "otel_traces",
          extra: { sourceKind: "otel" },
        }),
      ]),
      new AbortController().signal,
      { skipConfigRecheck: true },
    );

    expect(res.verdictStatus).toBe("attention");
    expect(res.rows).toHaveLength(2);
    const httpRow = res.rows.find((r) => r.protocolLabel === "HTTP (OTel)");
    expect(httpRow?.http5xxCount).toBe(1);
    expect(httpRow?.errorCount).toBe(1);
    expect(res.rows.map((r) => r.protocolLabel)).toContain("MYSQL (OTel)");
    expect(() =>
      assertNoForbiddenFieldsInSpl(
        "app_transactions",
        'search index=otel_traces | table _time "attributes.db.statement"',
      ),
    ).toThrow(/SQL query text/i);
    expect(
      buildAppTransactionsRawEventsUrl({
        index: "otel_traces",
        serverIp: "teastore-db",
        destPort: 3306,
        sourcetypes: ["otel:traces"],
        earliest: EARLIEST,
        latest: NOW,
      }),
    ).toContain("attributes.server.address");
  });
});
