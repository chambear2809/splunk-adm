import { describe, expect, it } from "vitest";
import { buildSyslogStateSearch, normalizeSyslogRow } from "./nxosSyslog";

describe("shared SC4S + NX-OS/ACI syslog adapter", () => {
  it("normalizes DCN TA cisco:dc:nexus9k:syslog events and marks TA-qualified categories", () => {
    const ev = normalizeSyslogRow(
      {
        _time: "1800000100",
        host: "leaf1.pseudo.co",
        sourcetype: "cisco:dc:nexus9k:syslog",
        category: "ETHPORT",
        severity_id: "5",
        mnemonics: "IF_DOWN_LINK_FAILURE",
        syslog_msg: "Interface Ethernet1/10 is down (Link failure)",
        interface: "Ethernet1/10",
      },
      0,
    );
    expect(ev).toMatchObject({
      host: "leaf1.pseudo.co",
      sourceKind: "nxos_syslog",
      domain: "link",
      category: "ETHPORT",
      severity: 5,
      mnemonic: "IF_DOWN_LINK_FAILURE",
      mnemonicQualified: true,
      interface: "Ethernet1/10",
    });
  });

  it("normalizes SC4S cisco:ios extracted rows and strips auth/config-change events", () => {
    const ev = normalizeSyslogRow(
      {
        _time: 1800000200,
        host: "198.18.131.3",
        sourcetype: "cisco:ios",
        syslog_msg:
          "%BGP-5-ADJCHANGE: bgp-65001 [default] neighbor 10.0.0.1 Down - Hold Timer Expired",
      },
      1,
    );
    expect(ev).toMatchObject({
      sourceKind: "sc4s_cisco_ios",
      domain: "bgp",
      category: "BGP",
      severity: 5,
      mnemonic: "ADJCHANGE",
      mnemonicQualified: false,
    });

    const authEv = normalizeSyslogRow(
      {
        _time: 1800000250,
        host: "198.18.131.3",
        sourcetype: "cisco:dc:nexus9k:syslog",
        category: "AUTHPRIV",
        severity_id: "6",
        mnemonics: "LOGIN_SUCCESS",
        syslog_msg: "user admin logged in",
      },
      2,
    );
    expect(authEv).toBeUndefined();
  });

  it("excludes config-change mnemonics both in SPL and client-side", () => {
    const ev = normalizeSyslogRow(
      {
        _time: 1800000300,
        host: "leaf1",
        sourcetype: "cisco:dc:nexus9k:syslog",
        category: "PARSER",
        severity_id: "5",
        mnemonics: "CFGLOG_LOGGEDCMD",
        syslog_msg: "configure terminal",
      },
      0,
    );
    expect(ev).toBeUndefined();

    const spl = buildSyslogStateSearch({
      index: "cisco_dc",
      device: "198.18.131.3",
      includeAci: true,
      maxRows: 256,
    });
    expect(spl).toContain("index=cisco_dc");
    expect(spl).toContain('sourcetype="cisco:ios"');
    expect(spl).toContain('sourcetype="cisco:dc:nexus9k:syslog"');
    expect(spl).toContain('sourcetype="cisco:aci"');
    expect(spl).toContain('host="198.18.131.3"');
    expect(spl).toContain("VSHD_SYSLOG_CONFIG_I");
    expect(spl).toContain("CFGLOG_LOGGEDCMD");
    expect(spl).toContain("AUTHPRIV");
    expect(spl).not.toContain("_raw");
    expect(spl).toContain("| head 257");
  });
});
