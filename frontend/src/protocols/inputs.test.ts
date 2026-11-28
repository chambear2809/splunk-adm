import { describe, expect, it } from "vitest";
import {
  parseProtocolLink,
  parseProtocolProfiles,
  protocolLink,
  validateProtocolRequest,
} from "./inputs";

const NOW = 1800000000;

describe("protocol inputs and URL contract", () => {
  it("parses valid p_* link parameters and round-trips", () => {
    const params = protocolLink(
      {
        lens: "tcp_tls",
        scope: "prod:dc1",
        earliest: NOW - 900,
        latest: NOW - 60,
        view: "matrix",
        filter: { src: "10.0.0.1", dst: "10.0.0.2", vni: "5001" },
        item: "pair-1",
      },
      NOW,
    );
    expect(parseProtocolLink(params, NOW)).toEqual({
      lens: "tcp_tls",
      scope: "prod:dc1",
      earliest: NOW - 900,
      latest: NOW - 60,
      view: "matrix",
      filter: { src: "10.0.0.1", dst: "10.0.0.2", vni: "5001" },
      item: "pair-1",
    });
  });

  it("rejects unknown p_* keys, duplicate keys, bad scopes, and >3600s windows", () => {
    expect(() =>
      parseProtocolLink(new URLSearchParams("p_unknown=1"), NOW),
    ).toThrow(/unsupported/i);
    expect(() =>
      parseProtocolLink(
        new URLSearchParams("p_lens=tcp_tls&p_lens=dns_ops"),
        NOW,
      ),
    ).toThrow(/unsupported/i);
    expect(() =>
      parseProtocolLink(new URLSearchParams("p_scope=unmapped:foo"), NOW),
    ).toThrow(/unsupported/i);
    expect(() =>
      parseProtocolLink(
        new URLSearchParams(`p_earliest=${NOW - 7200}&p_latest=${NOW}`),
        NOW,
      ),
    ).toThrow(/up to one hour/i);
    expect(() =>
      parseProtocolLink(new URLSearchParams("p_vni=99999999"), NOW),
    ).toThrow(/VNI/i);
  });

  it("validates protocol requests fail-closed", () => {
    const req = validateProtocolRequest(
      {
        version: 1,
        lens: "dns_ops",
        scope: "lab:dc1",
        earliest: NOW - 600,
        latest: NOW - 10,
      },
      NOW,
    );
    expect(req.lens).toBe("dns_ops");
    expect(() =>
      validateProtocolRequest({ version: 2, lens: "dns_ops" }, NOW),
    ).toThrow();
  });

  it("parses adm_protocol_profiles envelope and runs per-lens extra validators", () => {
    const valid = {
      version: 1,
      profiles: [
        {
          id: "tcp-dc1",
          source: "protocol_tcp_tls",
          lens: "tcp_tls",
          scope: "lab:dc1",
          index: "netflow",
          observer: "streamfwd-01",
          validFrom: NOW - 3600,
          validUntil: NOW + 3600,
          extra: { rttWarnMs: 50 },
        },
      ],
    };
    const tcpValidator = (extra: Record<string, unknown> | undefined) => {
      if (typeof extra?.rttWarnMs !== "number")
        throw new Error("bad rttWarnMs");
      return { rttWarnMs: extra.rttWarnMs };
    };
    const parsed = parseProtocolProfiles(valid, {
      tcp_tls: tcpValidator,
    });
    expect(parsed).toHaveLength(1);
    expect(parsed[0].extra).toEqual({ rttWarnMs: 50 });

    expect(() => parseProtocolProfiles(valid, {})).toThrow(
      /unvalidated extra/i,
    );

    expect(() =>
      parseProtocolProfiles(
        {
          version: 1,
          profiles: [
            {
              ...valid.profiles[0],
              source: "protocol_dns_ops",
            },
          ],
        },
        {},
      ),
    ).toThrow(/does not match lens/i);

    expect(() =>
      parseProtocolProfiles(
        {
          version: 1,
          profiles: [
            valid.profiles[0],
            { ...valid.profiles[0], id: "tcp-dc1-dup" },
          ],
        },
        { tcp_tls: tcpValidator },
      ),
    ).toThrow(/ambiguous or duplicate/i);

    expect(parseProtocolProfiles(undefined)).toEqual([]);
  });

  it("validates and round-trips port, bidirectional, and interface filters", () => {
    const urlParams = protocolLink(
      {
        lens: "tcp_tls",
        scope: "prod:dc1",
        view: "overview",
        filter: {
          src: "10.0.0.1",
          dst: "10.0.0.2",
          port: "443",
          bidirectional: true,
          iface: "eth1/1",
        },
      },
      1800000000,
    );
    expect(urlParams.get("p_port")).toBe("443");
    expect(urlParams.get("p_bidir")).toBe("1");
    expect(urlParams.get("p_iface")).toBe("eth1/1");

    const parsed = parseProtocolLink(urlParams, 1800000000);
    expect(parsed.filter).toEqual({
      src: "10.0.0.1",
      dst: "10.0.0.2",
      port: "443",
      bidirectional: true,
      iface: "eth1/1",
    });

    expect(() =>
      parseProtocolLink(new URLSearchParams("p_port=70000"), 1800000000),
    ).toThrow(/Port must be/i);
    expect(() =>
      parseProtocolLink(new URLSearchParams("p_bidir=2"), 1800000000),
    ).toThrow(/unsupported/i);
    expect(() =>
      parseProtocolLink(
        new URLSearchParams("p_iface=eth1/1|delete"),
        1800000000,
      ),
    ).toThrow(/Invalid interface/i);
  });
});
