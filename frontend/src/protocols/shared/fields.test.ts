import { describe, expect, it } from "vitest";
import {
  assertNoForbiddenFieldsInSpl,
  buildAllowedFieldsClause,
  isFieldAllowedForLens,
} from "./fields";

describe("protocol field allowlists and sensitive-field guards", () => {
  it("builds a clean fields clause for allowlisted fields", () => {
    expect(
      buildAllowedFieldsClause("tcp_tls", [
        "_time",
        "src_ip",
        "dest_ip",
        "client_rtt",
        "server_rtt",
      ]),
    ).toBe("| fields _time src_ip dest_ip client_rtt server_rtt");
  });

  it("rejects globally forbidden sensitive fields on every lens", () => {
    for (const bad of [
      "cookie",
      "form_data",
      "uri_query",
      "sql_statement",
      "bind_variable_value",
      "content",
      "community",
      "value_raw",
      "varbind_list",
      "login",
    ]) {
      expect(isFieldAllowedForLens("app_transactions", bad)).toBe(false);
      expect(isFieldAllowedForLens("mgmt_plane", bad)).toBe(false);
      expect(isFieldAllowedForLens("enterprise_l7", bad)).toBe(false);
      expect(() =>
        assertNoForbiddenFieldsInSpl(
          "mgmt_plane",
          `search index=main | fields src_ip ${bad}`,
        ),
      ).toThrow(/forbidden sensitive field/i);
    }
  });

  it("allows DNS `query` on dns_ops but forbids SQL `query` on app_transactions", () => {
    expect(isFieldAllowedForLens("dns_ops", "query")).toBe(true);
    expect(isFieldAllowedForLens("app_transactions", "query")).toBe(false);
    expect(() =>
      assertNoForbiddenFieldsInSpl(
        "app_transactions",
        "search index=stream sourcetype=stream:mysql | fields src_ip query",
      ),
    ).toThrow(/SQL query text/i);
  });

  it("gates row-expansion-only fields unless explicitly requested", () => {
    expect(isFieldAllowedForLens("enterprise_l7", "calling_station_id")).toBe(
      false,
    );
    expect(
      isFieldAllowedForLens("enterprise_l7", "calling_station_id", {
        includeRowExpansion: true,
      }),
    ).toBe(true);
  });
});
