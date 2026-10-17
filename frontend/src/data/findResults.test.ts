import { describe, expect, it } from "vitest";
import { settledFindResults } from "./findResults";
import type { RunResult } from "./searchClient";

const result = (rows: RunResult["rows"]): RunResult => ({ rows, warnings: [] });

describe("settledFindResults", () => {
  it("keeps successful client evidence when application Find fails", () => {
    const clients = result([
      { row_type: "network_client", client_ip: "10.0.0.2" },
    ]);
    expect(
      settledFindResults(
        { status: "rejected", reason: new Error("permission denied") },
        { status: "fulfilled", value: clients },
      ),
    ).toEqual({
      applicationError: "Application Find unavailable: permission denied",
      networkClients: clients,
    });
  });

  it("keeps successful application results and reports unavailable client evidence", () => {
    const applications = result([
      { row_type: "application", service: "checkout" },
    ]);
    expect(
      settledFindResults(
        { status: "fulfilled", value: applications },
        { status: "rejected", reason: new Error("search was truncated") },
      ),
    ).toEqual({
      applications,
      networkClientError:
        "Network-client Find unavailable: search was truncated",
    });
  });

  it("represents two complete empty searches without an error", () => {
    const empty = result([]);
    expect(
      settledFindResults(
        { status: "fulfilled", value: empty },
        { status: "fulfilled", value: empty },
      ),
    ).toEqual({ applications: empty, networkClients: empty });
  });
});
