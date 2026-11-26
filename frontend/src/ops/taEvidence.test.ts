import { describe, expect, it } from "vitest";
import { lbLegFields, TA_SOURCES, taSearch } from "./taEvidence";

describe("ecosystem TA contracts", () => {
  it("searches Splunkbase and Stream sourcetypes, never a custom collector", () => {
    const f5 = TA_SOURCES.find((source) => source.id === "f5")!;
    expect(f5.sourcetype).toBe("f5:bigip:syslog");
    expect(taSearch(f5)).toBe(
      'search `adm_index_f5` sourcetype="f5:bigip:syslog" | head 64',
    );
    expect(lbLegFields("haproxy")).toContain("backend_name");
    expect(TA_SOURCES.every((source) => source.transport !== undefined)).toBe(
      true,
    );
  });
});
