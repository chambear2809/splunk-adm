import { describe, expect, it } from "vitest";
import {
  assertNoForbiddenFieldsInSpl,
  projectRowToLensAllowlist,
} from "../fields";
import {
  MULTI_VENDOR_SC4S_SOURCETYPES,
  buildMultiVendorSyslogSearches,
  normalizeMultiVendorSyslogRow,
} from "./multiVendorSyslog";

describe("multiVendorSyslog SC4S operational adapter registry", () => {
  it("builds bounded, privacy-safe SPL per vendor family passing assertNoForbiddenFieldsInSpl", () => {
    const searches = buildMultiVendorSyslogSearches({
      index: "netops",
      sourcetypes: MULTI_VENDOR_SC4S_SOURCETYPES,
      device: "edge-01",
      includeAci: true,
      maxRows: 100,
    });
    expect(searches.map((s) => s.family)).toEqual([
      "cisco_ios_aci",
      "arista_eos",
      "cisco_asa_ftd",
      "juniper_junos",
      "pan_system",
      "fortigate_event",
      "f5_syslog",
    ]);
    for (const item of searches) {
      expect(item.spl).toContain("| head 101");
      expect(item.spl).toContain("| table _time host sourcetype");
      expect(() =>
        assertNoForbiddenFieldsInSpl("state_events", item.spl),
      ).not.toThrow();
    }
    const junosSpl = searches.find((s) => s.family === "juniper_junos")!.spl;
    expect(junosSpl).toContain("junos_5424_tag");
  });

  it("normalizes Arista, Juniper, PAN, FortiGate (via allowlist), F5, and ASA operational rows", () => {
    const base = { _time: 1764246600, host: "sw-01" };

    const arista = normalizeMultiVendorSyslogRow(
      {
        ...base,
        sourcetype: "arista:eos",
        category: "BGP",
        severity_id: 5,
        mnemonics: "ADJCHANGE",
        syslog_msg: "neighbor 10.0.0.2 Down",
      },
      0,
    );
    expect(arista?.sourceKind).toBe("sc4s_arista_eos");
    expect(arista?.domain).toBe("bgp");

    const junos = normalizeMultiVendorSyslogRow(
      {
        ...base,
        sourcetype: "juniper:junos:structured",
        category: "rpd",
        mnemonics: "RPD_BGP_NEIGHBOR_STATE_CHANGED",
        syslog_msg: "BGP peer 10.1.1.1 changed to Idle",
      },
      1,
    );
    expect(junos?.sourceKind).toBe("sc4s_juniper_junos");
    expect(junos?.domain).toBe("bgp");

    const pan = normalizeMultiVendorSyslogRow(
      {
        ...base,
        sourcetype: "pan:system",
        category: "HA",
        mnemonics: "ha-state-change",
        syslog_msg: "HA Group 1 moved to passive",
      },
      2,
    );
    expect(pan?.sourceKind).toBe("sc4s_pan_system");
    expect(pan?.domain).toBe("hsrp_vrrp");

    const f5 = normalizeMultiVendorSyslogRow(
      {
        ...base,
        sourcetype: "f5:bigip:syslog",
        category: "mcpd",
        severity_id: 3,
        code: "01070638",
        mnemonics: "01070638",
        syslog_msg:
          "Pool /Common/app_pool member 10.2.0.5:443 monitor status down",
      },
      3,
    );
    expect(f5?.sourceKind).toBe("sc4s_f5_syslog");
    expect(f5?.domain).toBe("link");

    const asa = normalizeMultiVendorSyslogRow(
      {
        ...base,
        sourcetype: "cisco:ftd:syslog",
        category: "ASA_OP",
        severity_id: 3,
        mnemonics: "105003",
        syslog_msg: "Failover monitoring on interface outside waiting",
      },
      4,
    );
    expect(asa?.sourceKind).toBe("sc4s_cisco_asa_ftd");
    expect(asa?.domain).toBe("hsrp_vrrp");

    const fgtProjected = projectRowToLensAllowlist("state_events", {
      ...base,
      sourcetype: "fortigate_event",
      category: "SDWAN",
      code: "0113022901",
      mnemonics: "SD-WAN SLA failed",
      syslog_msg: "Health check wan1 failed",
    });
    const fgt = normalizeMultiVendorSyslogRow(fgtProjected, 5);
    expect(fgt?.sourceKind).toBe("sc4s_fortigate_event");
  });

  it("blocks ASA 713228 VPN usernames, F5 iRule/AUDIT, PAN general logins, Arista SYS-5-CONFIG_E, and FortiGate logins", () => {
    const base = { _time: 1764246600, host: "fw-01" };

    expect(
      normalizeMultiVendorSyslogRow(
        {
          ...base,
          sourcetype: "cisco:asa",
          mnemonics: "713228",
          syslog_msg: "Group = RAVPN, Username = jdoe, IP = 203.0.113.5",
        },
        0,
      ),
    ).toBeUndefined();
    expect(
      normalizeMultiVendorSyslogRow(
        {
          ...base,
          sourcetype: "f5:bigip:syslog",
          category: "tmm",
          code: "01220002",
          mnemonics: "01220002",
          syslog_msg: "Rule /Common/x <HTTP_REQUEST>: cookie=secret",
        },
        1,
      ),
    ).toBeUndefined();
    expect(
      normalizeMultiVendorSyslogRow(
        {
          ...base,
          sourcetype: "f5:bigip:syslog",
          category: "mcpd",
          code: "01070417",
          mnemonics: "01070417",
          syslog_msg: "AUDIT - user admin - transaction",
        },
        2,
      ),
    ).toBeUndefined();
    expect(
      normalizeMultiVendorSyslogRow(
        {
          ...base,
          sourcetype: "pan:system",
          category: "GENERAL",
          mnemonics: "admin-login",
          syslog_msg: "User admin logged in via Web from 10.1.1.10",
        },
        3,
      ),
    ).toBeUndefined();
    expect(
      normalizeMultiVendorSyslogRow(
        {
          ...base,
          sourcetype: "arista:eos",
          category: "SYS",
          mnemonics: "CONFIG_E",
          syslog_msg:
            "Enter configuration mode from console by admin on vty3 (192.0.2.10)",
        },
        4,
      ),
    ).toBeUndefined();
    expect(
      normalizeMultiVendorSyslogRow(
        projectRowToLensAllowlist("state_events", {
          ...base,
          sourcetype: "fortigate_event",
          category: "SYSTEM",
          code: "0100032001",
          mnemonics: "Admin login successful",
        }),
        5,
      ),
    ).toBeUndefined();
    expect(
      normalizeMultiVendorSyslogRow(
        projectRowToLensAllowlist("state_events", {
          ...base,
          sourcetype: "fortigate_event",
          category: "SYSTEM",
          mnemonics: "Admin login successful",
        }),
        6,
      ),
    ).toBeUndefined();
  });
});
