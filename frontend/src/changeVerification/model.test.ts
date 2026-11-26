import { describe, expect, it } from "vitest";
import {
  canonicalIp,
  evaluate,
  livenessCandidates,
  parseObservations,
  validateAssertion,
  windowErrors,
  windowIssues,
  windowsAround,
  type Assertion,
  type WindowEvidence,
} from "./model";

const reaches: Assertion = {
  id: "a1",
  name: "Web reaches DB",
  kind: "reaches",
  scope: "prod",
  src: "10.1.1.10",
  dst: "10.2.2.20",
  transport: "tcp",
  port: 5432,
};
const redundant: Assertion = {
  ...reaches,
  id: "a2",
  kind: "redundant",
  minObservers: 2,
};
const noNew: Assertion = {
  id: "a3",
  name: "No new drops",
  kind: "no_new_blocked",
  scope: "prod",
  src: "10.1.1.10",
  dst: "10.2.2.20",
};

const row = (overrides: Record<string, unknown>) => ({
  row_type: "observation",
  flow_source: "aci_acllog",
  observer_device: "pod-1/node-101",
  observer: "aci_acllog:pod-1/node-101",
  direction: "forward",
  records: "4",
  drops: "0",
  services: ["tcp/5432"],
  observers_capped: "0",
  ...overrides,
});
const ev = (...rows: Record<string, unknown>[]): WindowEvidence =>
  parseObservations(rows);
const empty = ev();

describe("canonicalIp", () => {
  it("matches the server's canonical text", () => {
    expect(canonicalIp("10.0.0.1")).toBe("10.0.0.1");
    expect(canonicalIp("2001:DB8:0:0:0:0:0:1")).toBe("2001:db8::1");
    expect(canonicalIp("2001:db8:0:1:0:0:0:1")).toBe("2001:db8:0:1::1");
    expect(canonicalIp("2001:db8:0:1:1:1:1:1")).toBe("2001:db8:0:1:1:1:1:1");
    expect(canonicalIp("::")).toBe("::");
    expect(canonicalIp("10.0.0.01")).toBeUndefined();
    expect(canonicalIp("::ffff:a00:1")).toBeUndefined();
    expect(canonicalIp("1::2::3")).toBeUndefined();
    expect(canonicalIp("host.example")).toBeUndefined();
  });
});

describe("validateAssertion", () => {
  it("accepts canonical rows and rejects what the server rejects", () => {
    expect(validateAssertion(reaches)).toEqual(reaches);
    expect(validateAssertion({ ...noNew, name: "  x  " }).name).toBe("x");
    for (const bad of [
      { ...reaches, src: "2001:DB8::1" },
      { ...reaches, dst: reaches.src },
      { ...reaches, scope: "unmapped:x" },
      { ...reaches, port: 0 },
      { ...reaches, transport: "icmp" },
      { ...reaches, minObservers: 2 },
      { ...redundant, minObservers: 9 },
      { ...noNew, port: 53 },
      { ...reaches, note: "a\nb" },
      { ...reaches, extra: true },
    ])
      expect(() => validateAssertion(bad)).toThrow();
  });
});

describe("windows", () => {
  it("builds before/after windows and rejects overlap or oversize", () => {
    const w = windowsAround(10_000, 12_000, 3600);
    expect(w).toEqual({
      before: { start: 6400, end: 10_000 },
      after: { start: 12_000, end: 15_600 },
    });
    expect(windowErrors(w)).toEqual([]);
    expect(windowErrors({ before: w.after, after: w.before })[0]).toMatch(
      /before window must end/,
    );
    expect(
      windowErrors({ ...w, after: { start: 12_000, end: 12_000 + 90_000 } })[0],
    ).toMatch(/24 hours/);
    expect(windowIssues(w.after, 15_700)).toHaveLength(1);
    expect(windowIssues(w.after, 20_000)).toEqual([]);
  });
});

describe("parseObservations", () => {
  it("fails closed on caps and malformed rows", () => {
    expect(ev(row({ observers_capped: "1" })).issues).toHaveLength(1);
    expect(ev(row({ records: "x" })).issues[0]).toMatch(/malformed/);
    expect(ev(row({ drops: "9" })).issues[0]).toMatch(/drop counts/);
    expect(ev(row({ row_type: "endpoint" })).observations).toEqual([]);
  });
  it("derives NetFlow listener services by direction", () => {
    const w = ev(
      row({
        flow_source: "netflow",
        observer_device: "10.9.9.1",
        protocol: "tcp",
        dest_port: "5432",
        src_port: "40000",
        services: undefined,
      }),
      row({
        flow_source: "netflow",
        observer_device: "10.9.9.1",
        direction: "reverse",
        protocol: "tcp",
        dest_port: "40000",
        src_port: "5432",
        services: undefined,
      }),
    );
    expect(w.observations.map((o) => o.services)).toEqual([
      ["tcp/5432"],
      ["tcp/5432"],
    ]);
  });
});

describe("evaluate reaches", () => {
  it("passes on forwarded traffic from a verdict source", () => {
    const v = evaluate(reaches, empty, ev(row({})));
    expect(v.status).toBe("pass");
    expect(v.basis).toBe("observed");
  });
  it("never passes on incomplete after evidence", () => {
    const v = evaluate(
      reaches,
      empty,
      ev(row({}), row({ observers_capped: "1" })),
    );
    expect(v.status).toBe("unknown");
  });
  it("fails on observed drops only", () => {
    const v = evaluate(
      reaches,
      empty,
      ev(row({ drops: "4", drop_services: ["tcp/5432"] })),
    );
    expect(v).toMatchObject({ status: "fail", basis: "observed" });
  });
  it("treats mixed-service drop rows as ambiguous", () => {
    const v = evaluate(
      reaches,
      empty,
      ev(
        row({
          records: "5",
          drops: "1",
          services: ["tcp/5432", "tcp/443"],
          drop_services: ["tcp/5432"],
        }),
      ),
    );
    expect(v.status).toBe("unknown");
  });
  it("needs both directions for presence-only sources", () => {
    const fwd = row({ flow_source: "nd", observer_device: "fabric1" });
    expect(evaluate(reaches, empty, ev(fwd)).status).toBe("unknown");
    expect(
      evaluate(reaches, empty, ev(fwd, { ...fwd, direction: "reverse" }))
        .status,
    ).toBe("pass");
    expect(
      evaluate(
        reaches,
        empty,
        ev(row({ flow_source: "ftd", observer_device: "10.0.0.5" })),
      ).status,
    ).toBe("unknown");
  });
  it("fails by inference only when every baseline observer is proven live", () => {
    const before = ev(row({}));
    expect(livenessCandidates(reaches, before, empty)).toEqual([
      "aci_acllog:pod-1/node-101",
    ]);
    expect(evaluate(reaches, before, empty).status).toBe("unknown");
    const v = evaluate(
      reaches,
      before,
      empty,
      new Set(["aci_acllog:pod-1/node-101"]),
    );
    expect(v).toMatchObject({ status: "fail", basis: "inferred" });
    expect(evaluate(reaches, empty, empty).status).toBe("unknown");
    expect(
      evaluate(reaches, ev(row({ observers_capped: "1" })), empty).status,
    ).toBe("unknown");
  });
});

describe("evaluate redundant", () => {
  const a = row({});
  const b = row({
    observer_device: "pod-1/node-102",
    observer: "aci_acllog:pod-1/node-102",
  });
  it("passes with enough distinct forwarding observers", () => {
    expect(evaluate(redundant, empty, ev(a, b)).status).toBe("pass");
  });
  it("fails only against a complete baseline with live missing observers", () => {
    expect(evaluate(redundant, empty, ev(a)).status).toBe("unknown");
    expect(evaluate(redundant, ev(a, b), ev(a)).status).toBe("unknown");
    expect(livenessCandidates(redundant, ev(a, b), ev(a))).toEqual([
      "aci_acllog:pod-1/node-102",
    ]);
    expect(
      evaluate(
        redundant,
        ev(a, b),
        ev(a),
        new Set(["aci_acllog:pod-1/node-102"]),
      ).status,
    ).toBe("fail");
    expect(
      evaluate(
        redundant,
        ev(a, b),
        ev(a, { ...b, drops: "4", drop_services: ["tcp/5432"] }),
      ),
    ).toMatchObject({ status: "fail", basis: "observed" });
  });
});

describe("evaluate no_new_blocked", () => {
  const drop = row({
    drops: "2",
    services: ["tcp/22"],
    drop_services: ["tcp/22"],
  });
  it("fails on drops absent before and passes on pre-existing drops", () => {
    expect(evaluate(noNew, ev(row({})), ev(drop))).toMatchObject({
      status: "fail",
      basis: "observed",
    });
    expect(evaluate(noNew, ev(drop), ev(drop)).status).toBe("pass");
    expect(
      evaluate(noNew, ev(row({ observers_capped: "1" })), ev(drop)).status,
    ).toBe("unknown");
  });
  it("passes on no drops only when a drop-reporting source saw the pair", () => {
    expect(evaluate(noNew, empty, ev(row({}))).status).toBe("pass");
    expect(
      evaluate(
        noNew,
        empty,
        ev(row({ flow_source: "nd", observer_device: "f1" })),
      ).status,
    ).toBe("unknown");
    expect(evaluate(noNew, empty, empty).status).toBe("unknown");
  });
});
