# Splunk Ecosystem Network Engineering Expansion — Multi-Agent Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use `superpowers:subagent-driven-development` (recommended) following `docs/OPERATING_MODEL.md` (max 4 concurrent subagent threads, no nesting, disjoint write paths, mandatory read-only `code-reviewer` and `ux-reviewer` gates per wave) or `superpowers:executing-plans`. Steps use checkbox (`- [ ]`) syntax for tracking. Per `AGENTS.md`, **no worker or orchestrator may run `git commit`, `git push`, or merge without explicit human authorization.**

**Goal:** Deliver all 29 researched high-value Network Engineering capabilities across official multi-vendor Splunk Technical Add-Ons (Cisco + Arista, Juniper, Palo Alto, Fortinet, Check Point, VMware NSX, F5, Citrix NetScaler, HAProxy, HPE Aruba/EdgeConnect, Infoblox, Microsoft Windows DNS/DHCP, Cisco ASA, Cisco Secure Access/Umbrella, Zscaler, NGINX, Cloudflare, and AWS/Azure/GCP), the SC4S/SC4SNMP family, and Splunk Distribution of OpenTelemetry Collector (`v0.162–0.165`) — expanding Application Atlas from 13 to 20 protocol lenses (adding `wan_tunnels`, `fabric_congestion`, `optics_hardware`, `network_access`, `remote_sase`, `wireless_rf`, and `evpn_overlay`), adding first-class Splunk Metrics (`| mstats`) support, adding 4 zero-collector war-room diagnostics (Path MTU Audit, Asymmetric/ECMP detection, Certificate Blast Radius, Redacted Config-Change Markers), and updating all repository documentation in lockstep.

**Architecture:** Execute in 5 gated waves orchestrated by the root Cursor agent (`gemini-4-neon-high`). Wave 0 lays down shared infrastructure (`metricsRunner.ts`, `multiVendorSyslog.ts`, Splunk lab `datatype = metric` indexes, official multi-vendor TA static intake in `research/package-manifest.json`, and a synced `ecosystem-worker` agent role) while keeping every wave independently buildable, type-safe, and passing `python3 tools/check_release.py --dist dist`. Waves 1–3 stage-gate each new lens/source registration in the exact wave that implements it, dispatching bounded, file-disjoint `protocol-worker` and `ecosystem-worker` batches (`<= 4` concurrent threads) so every new lens compiles as an independent `<= 64 KiB` gzip optional IIFE asset without inflating `atlas.js`. Wave 4 completes full documentation consolidation, qualification ledger reconciliation, Splunk lab validation, and whole-branch read-only review.

**Tech Stack:** TypeScript 6 / React 18 / Vite 8 / Vitest 5 / Playwright (frontend & browser gates), Splunk Enterprise 10.6.0.5 + Splunk Cloud 10.6 SPL (`search` + `| mstats`), Python 3.13 + Ruff + `unittest` (lab & release tooling), Cursor `.cursor/agents/` synced with Codex `.codex/agents/`.

**Spec / Research Baseline:**
- Interactive Research Catalog: [Splunk Ecosystem Network Engineering Research](/Users/alecchamberlain/.cursor/projects/Users-alecchamberlain-Documents-GitHub-splunk-adm/canvases/network-engineer-ecosystem-research.canvas.tsx)
- Operating Model: `docs/OPERATING_MODEL.md`
- Protocol Lens UX Contract: `docs/superpowers/specs/2026-11-27-protocol-lenses-ux.md`
- Protocol Worker Brief Template: `docs/superpowers/specs/2026-11-27-protocol-worker-brief.md`
- Supplemental & Ecosystem Evidence Contracts: `docs/SUPPLEMENTAL_EVIDENCE_CONTRACT.md`, `docs/ECOSYSTEM_TRAFFIC_EVIDENCE_DESIGN.md`

---

## Global Constraints

1. **Multi-agent governance (`docs/OPERATING_MODEL.md`):** Root Orchestrator (`gemini-4-neon-high`) owns shared SDK (`frontend/src/protocols/shared/`), `frontend/src/data/evidence.ts`, `ProtocolsPage.tsx`, `inputs.ts`, `registry.ts`, `drillIn.ts`, `macros.conf`, `collections.conf`, `transforms.conf`, `savedsearches.conf`, `bin/adm_observer_lib/rest.py`, `metadata/default.meta`, `config/deployment-health.json`, `frontend/src/data/evidenceConfig.ts`, `frontend/src/data/setupClient.ts`, `tools/protocol-lenses.mjs`, `vite.protocols-core.shared.ts`, `tools/package-app.mjs`, `tools/check_release.py`, `tests/splunk/lab_app/`, `tests/splunk/lab.py`, `tests/splunk/test_protocol_lenses.py`, `tests/browser/protocols-harness.tsx`, `tests/browser/protocols.spec.ts`, Vite/package configs, `npm run build`, `npm run package`, Playwright screenshot capture, and Splunk lab runs. Max **4 concurrent subagent threads** per batch; nesting disabled. Every Cursor agent in `.cursor/agents/` must remain byte-synced with `.codex/agents/` and pass `tests/test_agent_definitions.py`.
2. **Worker write isolation, scoped validation & flat-lens layout:** Workers write ONLY inside their brief's allowed paths. Workers never run `git`, `npm run build`, `npm run package`, repo-wide `npm run format`, or repo-wide `npm run lint` during parallel batches (sibling in-flight edits cause cross-worker failures); workers run scoped `npx prettier --write <allowed-dir> && npx eslint <allowed-dir> && npx vitest run <allowed-dir>`, and Orchestrator runs full repo-wide `npm run lint` at each batch/wave integration gate. Workers never execute downloaded vendor scripts under `research/extracted/`. Because `tools/protocol-lenses.mjs` `collectLensFiles()` hashes direct child files of `frontend/src/protocols/lenses/<lens>/` (non-recursive), keep lens source files flat inside `lenses/<lens>/` (matching all 13 existing lenses).
3. **Stage-gated registration (every wave must build & pass `check_release.py --dist dist`):** Never add unimplemented lens IDs to `PROTOCOL_LENS_IDS` / `EXPECTED_PROTOCOL_LENS_IDS` or unimplemented `SupplementalSource` values before the wave that builds them. In each wave: (a) Orchestrator registers that wave's new lens/source IDs, `LENS_FIELD_ALLOWLISTS`, `config/deployment-health.json` entries (both `protocol_<lens>` and supplemental sources), `collections.conf` fields, and fail-closed macros immediately before dispatching workers; (b) workers implement in disjoint directories; (c) Orchestrator wires `registry.ts`, `drillIn.ts`, `tools/protocol-lenses.mjs`, `tools/check_release.py` (using dynamic `len(expected_lens_ids)` instead of hardcoded `13`), `evidenceConfig.ts`, `tests/browser/protocols-harness.tsx`, `tests/browser/protocols.spec.ts`, and `ProtocolsPage.test.tsx`.
4. **Zero searches on page load, bounded SPL & dual-shape metrics contract:** Every lens and panel stays idle until explicit user action (`Investigate` / inspect click). Event queries emit `| head ${maxRows + 1}` BEFORE `| table <allowlisted fields>`, drop `_raw` server-side, and are strictly enforced at `<= MAX_WINDOW_SECONDS` (`3600` s) inside `runBoundedProtocolSearch` so wider metrics windows can NEVER leak into event searches. Metrics (`| mstats`) queries use structured, validated `filters` (never raw SPL strings), validate every `AS <alias>` and `BY` dimension against `isFieldAllowedForLens` BEFORE dispatch (preventing silent stripping by `projectRowToLensAllowlist`), and split into two bounded shapes:
   - **Entity summary (no `span=`):** `| mstats <aggs> WHERE index=<idx> ... BY <dims> | sort 0 - <rank_alias> | head ${maxRows + 1}` — fits up to 256 entities cleanly without time-bucket multiplication or oldest-first truncation.
   - **Top-N sparkline/trend (with `span=`):** Scoped strictly to `<= 8` selected/top-ranked entities (`<= 32` auto-scaled buckets × `<= 8` entities `<= 256` rows).
   - **URL-persisted window mode:** Carry `p_wmode=metrics` in `protocolLink()` / `parseProtocolLink()` / `ProtocolsPage.tsx`, enable `24h` / `7d` presets ONLY for metrics-only profiles, and reset `windowMode` to `"events"` (`<= 3600` s) inside `openLens()` when navigating to an event lens.
5. **Strict privacy & `assertNoForbiddenFieldsInSpl` rules (`frontend/src/protocols/shared/fields.ts`):** Never project `_raw`, `cookie`, `form_data`, `uri_query`, `sql_statement`, `bind_variable_value`, `content`, `community`, `value_raw`, `varbind_list`, `login`, `password`, `passwd`, `authorization`, `raw_packet`, `payload`, `src_content`, `dest_content`, `ssl_session_id`, sFlow `http_url`/`src_user`/`dest_user`, or AAA/auth/config-change syslog categories. **Do NOT add `http_url` globally to `FORBIDDEN_SENSITIVE_FIELDS`** (it collides with `lb_health/adapter.ts:199`'s `F5_SAFE_REX_PATTERN` regex literal inside `| rex`); instead block `http_url` in the sFlow builder & allowlist (or rewrite `F5_SAFE_REX_PATTERN` first with dedicated regression tests). **SPL guard detail:** `assertNoForbiddenFieldsInSpl` strips double-quoted RHS literals only after `=` (`=\s*"..."`), NOT inside `IN ("...")` — never place a forbidden token such as `"LOGIN"` inside an SPL `IN (...)` list. For Cisco ISE (`network_access`), store ALL row-expansion field names **lowercase** in `fields.ts` (matching `isFieldAllowedForLens`'s `.toLowerCase()` lookup) and add per-lens row-expansion support for `network_access` covering every actual TA-extracted ISE identity field from `TA_cisco_catalyst/default/props.conf` & `transforms.conf` (`user`, `user_name`, `user-name`, `src_user_name`, `x_user`, `username`, `originalusername`, `admin`, `adminname`, `portaluser`, plus `src_mac` and `src_ip`) — without breaking `src_mac` in `l2_control` or `endpoint_mobility`.
6. **Official unmodified Splunkbase TA grounding, provenance & fail-closed shipping:**
   - **Zero modified vendor TAs:** Atlas works strictly with official, unmodified Splunkbase TAs installed on the search tier (search-time parsing) and/or Heavy Forwarder (modular inputs), paired with SC4S/SC4SNMP/Stream/OTel collectors.
   - **Static package inspection (`AGENTS.md`):** Before coding field extractions for any newly added vendor TA, download the official archive into ignored `research/packages/`, extract static files into ignored `research/extracted/`, record Splunkbase ID, version, provenance, and SHA-256 in `research/package-manifest.json`, and inspect `default/props.conf` / `transforms.conf` strictly as data (never execute vendor scripts). For any source without an extracted package (pending vendor TAs, SC4S vendor parsers, SC4SNMP `netmetrics`, OTel receiver metrics `yang_grpc`/`gnmi`/`cisco_os`/`*_check`/`ptp`/`ntp`/`chrony`/`OBI`/`k8s_events`, and cloud transit metrics), pin exact primary-source vendor/collector docs and versions in the feature's `FIELDS.md` following `fixtures/raw/FIELDS.md:157-179` and keep the source explicitly labeled unqualified until archive inspection + live readback complete.
   - **Verified TA sourcetypes already inspected in `research/extracted/`:** Meraki (`meraki:devicesuplinkslossandlatency`, `meraki:appliancesdwanstatistics`, `meraki:appliancesdwanstatuses`, `meraki:portstransceiversreadingshistorybyswitch`, `meraki:powermodulesstatusesbydevice`, `meraki:wirelessdevicespacketlossbydevice`, `meraki:switchportsbyswitch`, `meraki:switchportsoverview`, `meraki:wirelessdevicesethernetstatuses`); Intersight (`cisco:intersight:networkobjects` / `networkObjects`, `cisco:intersight:networkelements`, `cisco:intersight:profiles` — note `[cisco:intersight:fabric]` has `rename = cisco:intersight:profiles` with `source IN ("fabricSwitchProfile", "fabricSwitchClusterProfile")`, `cisco:intersight:alarms`, `cisco:intersight:metrics`); Cisco Security Cloud (`cisco:ftd:syslog`, `cisco:sfw:policy`, `cisco:sfw:estreamer`).
   - **Fail-closed defaults & exact ACLs:** Every new optional index macro ships as `index=unconfigured_optional` and every new schema flag ships as `0` (verified in `tests/test_ecosystem_fixtures.py`). Any new KV Store collection or lookup transform MUST declare the exact `VIEWER_ACL` required by `tools/check_release.py:135,2171`: `access = read : [ adm_investigate, adm_viewer, admin, sc_admin ], write : [ admin, sc_admin ]` (whitespace-free `read:[adm_investigate,adm_viewer,admin,sc_admin],write:[admin,sc_admin]`).
7. **Honest evidence, UX & bundle budgets (`tools/check_release.py`, `docs/superpowers/specs/2026-11-27-protocol-lenses-ux.md`):** Status chips strictly distinguish `OK`, `Attention`, `Not covered` (hatch), `None observed` (minus), and `Unknown` (question). Active synthetic probes (`icmp_check`, `dns_check`, `tcp_check`, `tls_check`) carry an explicit **Synthetic Probe** badge and never emit passive dependency edges. Alpha/experimental OTel receivers (`yang_grpc`, `gnmi`, `cisco_os`, `ptp`, `OBI`) carry explicit maturity badges and stay opt-in. Budgets: `atlas.js <= 680 KiB` gzip; `protocols-core.js <= 64 KiB` gzip (`24 KiB` CSS); each `protocol-<id>.js <= 64 KiB` gzip; `ecosystem.js <= 48 KiB` gzip (split into a dedicated optional bundle if multi-vendor flow + cloud transit exceeds 44 KiB gzip rather than raising limits silently); `segmentation.js <= 40 KiB` gzip; `admin.js <= 48 KiB` gzip. Every lens view: `< 60` chrome words, `<= 8` columns, `<= 4` KPI tiles with units & sparklines, verdict within `120 px` above the fold, WCAG 2.2 AA, light & dark themes, zero new chart libraries.
8. **Documentation parity & human authorization (`AGENTS.md`):** Every worker writes/updates its own `docs/operators/<feature>.md` and `FIELDS.md` in lockstep with code. Orchestrator reconciles cross-cutting hub docs at every wave gate and completes a full doc-parity audit in Wave 4. Stop at every Wave Checkpoint for human review; never commit, push, tag, or merge without explicit authorization.

---

## Multi-Vendor Splunkbase TA Matrix (Official, Splunk 10.6-Compatible)

Every non-Cisco network vendor included in this plan uses its official Splunkbase Technical Add-On (verified Splunk Enterprise & Cloud 10.6 compatible as of Nov 2026) alongside SC4S/SC4SNMP/Stream/OTel where appropriate:

| Vendor | Official Splunkbase TA | ID | Verified Version | Flow / Network Evidence Contributed | Atlas Index Macro (Fail-Closed Default) | Target Wave / Surface |
| --- | --- | --- | --- | --- | --- | --- |
| **Arista Networks** | Arista Networks Telemetry For Splunk | `1918` | `2.0.2` | sFlow, interface counters, optical light levels (DOM), LANZ microbursts, hardware table status, syslog | `adm_index_arista` | Wave 1 (`sflow`, `interface_health`), Wave 2 (`optics_hardware`, `qos_icmp`) |
| **Juniper Networks** | Splunk Add-on for Juniper *(Splunk Supported)* | `2847` | `1.7.0` | SRX flow logs & NAT (`juniper:junos:firewall`, `juniper:junos:firewall:structured`, `netscreen:firewall`), `juniper:junos:snmp` | `adm_index_juniper` | Wave 2 (`multiVendorFlows`, `drops`, `state_events`, `routing`) |
| **Palo Alto Networks** | Splunk Add-on for Palo Alto Networks *(Splunk Supported; supersedes legacy `2757`)* | `7523` (and legacy `2757`) | `4.0.0` | `pan:traffic` flows/NAT (v4.0 CIM + legacy 6.x), `pan:system` (BGP/HA/VPN), `pan:config` | `adm_index_pan` *(existing)* | Wave 1 (`state_events`, `wan_tunnels`), Wave 2 (`multiVendorFlows`, `drops`) |
| **Fortinet** | Fortinet FortiGate Add-On for Splunk | `2846` | `1.6.10` | `fortigate_traffic` / `fgt_traffic` flows/NAT, `fortigate_event` / `fgt_event` (SD-WAN SLA, IPsec, HA, BGP/OSPF) | `adm_index_fortigate` *(existing)* | Wave 1 (`state_events`, `wan_tunnels`), Wave 2 (`multiVendorFlows`, `drops`) |
| **Check Point** | CCX Unified Splunk Add-on for Checkpoint | `5402` | `2.1.3` | Check Point Log Exporter / syslog firewall flows, NAT, drops, VPN | `adm_index_checkpoint` | Wave 2 (`multiVendorFlows`, `drops`) |
| **VMware NSX** | VMware NSX add-on + Stream NSX IPFIX | `6805` | `1.0.5` | NSX Distributed Firewall (`dfw`) allow/deny flow logs + `vmware_nsx_ipfix` Stream IPFIX profile | `adm_index_nsx` + `adm_index_netflow` | Wave 1 (`vmware_nsx_ipfix`), Wave 2 (`multiVendorFlows`, `drops`) |
| **F5 Networks** | Splunk Add-on for F5 BIG-IP *(Splunk Supported)* | `2680` | `7.0.1` | LTM iRule legs (`f5:bigip:ltm:*:irule`), system/pool-monitor syslog (`f5:bigip:syslog`), iControl REST metrics/certs | `adm_index_f5` *(existing)* | Wave 1 (`lb_health`, `state_events`) |
| **Citrix / NetScaler** | Splunk Add-on for Citrix NetScaler *(Splunk Supported)* | `2770` | `8.2.5` | AppFlow / IPFIX traffic legs, syslog, NITRO API VIP/service-group health | `adm_index_netscaler` | Wave 1 (`lb_health`) |
| **HAProxy** | Splunk Add-on for HAProxy | `3135` | — | `haproxy:http` proxy legs, backend target vs balancer 5xx (`termination_state`) | `adm_index_haproxy` *(existing, unwired)* | Wave 1 (`lb_health`) |
| **HPE Aruba** | Aruba Networks Add-on (`4668`) + HPE Aruba EdgeConnect SD-WAN (`6302`) | `4668` / `6302` | `1.1.2` / `1.1.2` | Aruba wireless/controller logs + EdgeConnect (Silver Peak) SD-WAN tunnel/flow telemetry | `adm_index_aruba` | Wave 2 (`wan_tunnels`, `state_events`) |
| **Infoblox** | Infoblox App for Splunk + SC4S NIOS | `7473` | `2.0.0` | `infoblox:dns`, `infoblox:dhcp` (scope exhaustion, failover), `infoblox:audit` | `adm_index_infoblox` | Wave 2 (`dns_ops`, `l2_control`) |
| **AWS / Azure / GCP** | Splunk TAs for AWS (`1876`), MSCS (`3110`), GCP (`3088`) | `1876` / `3110` / `3088` | *(existing)* | VPC/VNet flows + ALB/NLB + **Route 53 Resolver, Direct Connect, TGW, ExpressRoute, VWAN, Cloud Router, AWS NATGW** | `adm_index_aws`, `adm_index_azure`, `adm_index_gcp`, `adm_index_cloud_transit` | Wave 2 (`cloudTransit`, `dns_ops`, `drops`, `natSaturation`) |
| **Microsoft Windows** | Splunk Add-on for Microsoft Windows *(Splunk Supported)* | `742` | `12.0.0` | AD/Windows DNS (`dns_ops`) and Windows DHCP scope exhaustion/failover (`l2_control`) | `adm_index_win_ddi` | Wave 2 (`dns_ops`, `l2_control`) |
| **Cisco ASA / AnyConnect** | Splunk Add-on for Cisco ASA *(Splunk Supported)* | `1620` | `6.1.2` | AnyConnect VPN sessions (`remote_sase`), NAT/session exhaustion (`natSaturation`), failover/routing syslog | `adm_index_asa` | Wave 1 (`state_events`), Wave 2 (`remote_sase`, `natSaturation`) |
| **Cisco Secure Access / Umbrella** | Cisco Secure Access Add-on for Splunk *(Cisco Supported)* | `7569` | `1.0.57` | SSE/Zero-Trust DNS, SWG, and private-access policy/tunnel troubleshooting | `adm_index_sase` | Wave 2 (`remote_sase`) |
| **Zscaler** | Zscaler TA (`3865`) / App (`3866`) | `3865` / `3866` | `3.0.22` | ZIA / ZPA remote-access connector health, tunnel drops, policy blocks | `adm_index_sase` | Wave 2 (`remote_sase`) |
| **NGINX** | Splunk Add-on for NGINX *(Splunk Supported)* | `3258` | `3.3.2` | Reverse proxy / ingress upstream 5xx & latency attribution | `adm_index_nginx` | Wave 1 (`lb_health`) |
| **Cloudflare** | Cloudflare App for Splunk | `4501` | `2.3.1` | Edge WAF/CDN blocks, 502 origin timeouts, Zero-Trust network sessions | `adm_index_cloudflare` | Wave 1 (`lb_health`), Wave 2 (`drops`) |

---

## Review Focus

The 5 highest-risk failure modes implied by these 19 features — each pinned by explicit unit, browser, or Splunk lab tests in its owning task:

1. **Counter resets, silent alias stripping, time-bucket truncation & metrics-window leakage (`| mstats`):** Switch reboots reset 64-bit IF-MIB/MDT/gNMI counters; unallowlisted `AS <alias>` names get silently dropped by `projectRowToLensAllowlist`; splitting 60 buckets × all interfaces overflows `MAX_INPUT_ROWS = 256` and drops newest buckets; 7-day metrics windows must persist in URL (`p_wmode=metrics`) and reset to `<= 3600s` on event lenses. → Pinned in Task 0.2 (`metricsRunner.test.ts`, `inputs.test.ts`, `ProtocolsPage.test.tsx`), Task 0.4 (`tests/splunk/lab_app/default/indexes.conf` + `test_protocol_lenses.py`), and Task 1B.1 (`interface_health/adapter.test.ts`).
2. **Cross-sensor double-counting, vendor TA field divergence & scope collision:** The same flow observed simultaneously by NetFlow + sFlow + Arista `1918` + Juniper SRX `2847` + NSX `6805` + PAN `7523`/`2757` + Hubble + OTel OBI must never sum traffic totals, conflate PAN v4 (`7523`) vs legacy (`2757`) actions, or merge unverified observer authorities. → Pinned in Task 1A.3 (`sflowProfile.test.ts`, `test_sflow.py`), Task 2C.1 (`multiVendorFlows.test.tsx`, `test_multi_vendor_flows.py`), Task 3A.2 (`gnmi/adapter.test.ts`), and Task 3A.4 (`otelNetworkAdapters.test.ts`).
3. **Credential / PII leakage across ISE, sFlow, and multi-vendor syslog — plus `lb_health` F5 compatibility:** Actual TA-extracted ISE fields (`user`, `user_name`, `src_user_name`, `x_user`, `UserName`, `User_Name`, `OriginalUserName`, `src_mac`), sFlow `http_url`/`src_user`/`dest_user`, FortiGate admin/SSL-VPN `msg` usernames, ASA auth events, and SNMP communities must never leak into Overview/Matrix SPL or fixtures — WITHOUT breaking `lb_health` F5 `F5_SAFE_REX_PATTERN` (`http_url=`). → Pinned in Task 0.3 (`multiVendorSyslog.test.ts`), Task 0.4 (`fields.test.ts` + `lb_health/adapter.test.ts`), Task 1A.3 (`test_sflow.py`), and Task 2A.2 (`network_access/adapter.test.ts`).
4. **Honest evidence collapse on synthetic probes, syslog-only devices, Intersight renamed sourcetypes & alpha telemetry:** Marking OTel `icmp_check`/`tls_check`/`dns_check` probes as passive traffic, querying renamed `cisco:intersight:fabric` instead of `cisco:intersight:profiles`, marking syslog-only switches green `OK`, or rendering missing optical thresholds as `0 dBm`. → Pinned in Task 1A.1 (`test_intersight_paths.py`), Task 2A.1 (`optics_hardware/adapter.test.ts`), Task 2B.2 (`tcp_tls/adapter.test.ts`), and `tests/browser/protocols.spec.ts`.
5. **Release bundle budgets, asset-hash cache invalidation, `check_release.py` gates, Cursor↔Codex agent drift & doc drift:** Adding 5 lenses + `ecosystem-worker` + multi-vendor flow/transit sources breaching `tools/check_release.py --dist dist` gzip ceilings (`680 / 64 / 64 / 48 / 40 KiB`), stale lens bundle hashes when shared OTel adapters change, missing `config/deployment-health.json` or `VIEWER_ACL` entries, failing `tests/test_agent_definitions.py`, or leaving `README.md`/`SUPPORT_MATRIX.md`/`FEATURE_DELIVERY.md`/`macros.conf` stale. → Pinned in Task 0.1 (`test_agent_definitions.py`), every Wave Integration Gate (`python3 tools/check_release.py --dist dist` + `tests/test_release.py`), Batch 3B (`tools/protocol-lenses.mjs`), and Wave 4 Task 4.2.

---

## Multi-Agent Roster & Wave Topology

| Role | Cursor Agent (`.cursor/agents/`) | Codex Agent (`.codex/agents/`) | Model | Access | Owns |
| --- | --- | --- | --- | --- | --- |
| **Orchestrator** | Root session | Root session | `gemini-4-neon-high` / GPT-6.1 Sol | Workspace | Wave 0 SDK/lab/TA-intake/agent sync, per-wave pre-batch registration, batch dispatch (`<= 4`), integration, builds, Playwright harness/capture, Splunk lab, hub docs |
| **`protocol-worker`** | `protocol-worker.md` *(existing)* | `protocol_worker.toml` *(existing)* | `gemini-4-hydrogen` / GPT-6.1 Terra | Disjoint lens dir | `frontend/src/protocols/lenses/<lens>/` (flat files), `fixtures/protocols/<lens>/`, `docs/operators/protocol-<hyphenated-lens>.md` |
| **`ecosystem-worker`** | `ecosystem-worker.md` *(NEW in Wave 0)* | `ecosystem_worker.toml` *(NEW in Wave 0)* | `gemini-4-hydrogen` / GPT-6.1 Terra | Disjoint feature dir | Non-lens modules (`trace/`, `ecosystem/`, `segmentation/`, `data/`), `fixtures/<source>/`, `tests/splunk/test_<source>.py`, `docs/operators/<guide>.md` |
| **`code-reviewer`** | `code-reviewer.md` *(existing)* | `reviewer.toml` *(existing)* | `claude-opus-5-5-medium` / GPT-6 Astra | Read-only | Mandatory adversarial code, SPL security, privacy, release-gate, and test audit after every wave |
| **`ux-reviewer`** | `ux-reviewer.md` *(existing)* | `ux_reviewer.toml` *(existing)* | `claude-opus-5-5-medium` / GPT-6 Astra | Read-only | Mandatory UI/UX screenshot & WCAG 2.2 AA audit after every wave touching UI |

### Coverage Matrix — All 19 Researched Features → Wave & Task

| # | Feature | Pillar | Target Surface | Wave / Task |
| --- | --- | --- | --- | --- |
| 1 | UCS FI & `vmnic` Physical Pinning (`Splunk_TA_Cisco_Intersight` 7828) | Splunk TAs | Path Trace, Device, Impact | Wave 1 · Batch 1A · Task 1A.1 |
| 2 | WAN / SD-WAN Overlay & Tunnel SLA (`Catalyst` 7538 + `Meraki` 5580 + `Aruba EdgeConnect` 6302) | Splunk TAs | New Lens `wan_tunnels` + Path Trace WAN context | Wave 1 · Task 1A.2 & Wave 2 · Task 2C.3 |
| 3 | Multi-Vendor Switch & Virtual Flows via `stream:sflow` (`1809`) + Arista Telemetry (`1918`) + VMware NSX IPFIX (`6805`) | Splunk TAs | Core V2 Flow Profiles (`sflow_switch`, `vmware_nsx_ipfix`) + `routing` + `interface_health` | Wave 1 · Batch 1A · Task 1A.3 |
| 4 | Fabric Congestion (PFC/ECN), Multi-Site ACI & MDS SAN (`DCN` 2.0.10 7777 + Arista LANZ `1918`) | Splunk TAs | New Lens `fabric_congestion` | Wave 1 · Batch 1A · Task 1A.4 |
| 5 | Campus Assurance, Optical DOM & PoE (`Catalyst` 7538 + `Meraki` 5580 + `Aruba` 4668) | Splunk TAs | `interface_health` + New Lens `optics_hardware` | Wave 1 · Task 1B.1 & Wave 2 · Task 2A.1 |
| 6 | FMC Policy Intent (`CiscoSecurityCloud` 7404) + HAProxy (`3135`) & Citrix NetScaler (`2770`) + F5 (`2680` v7.0.1) LB Parity | Splunk TAs | Segmentation Policy + `lb_health` | Wave 1 · Batch 1B · Tasks 1B.3 & 1B.4 |
| 7 | Hybrid Cloud Transit Backbone (AWS `1876`, Azure `3110`, GCP `3088`) | Splunk TAs | Ecosystem Panel + Path Trace + `dns_ops` | Wave 2 · Batch 2B · Tasks 2B.1 & 2B.4 |
| 8 | Activate SC4SNMP Metrics (`netmetrics` + `| mstats`, `adm_ifmib_capacity`) | SC4S Family | `metricsRunner.ts` + `interface_health` + `macros.conf` | Wave 0 · Task 0.2 & Wave 1 · Task 1B.1 |
| 9 | Predictive Optical DOM & Chassis Hardware Health (SC4SNMP MIBs + Arista `1918` DOM + Meraki) | SC4S Family | New Lens `optics_hardware` + Impact PSU risk | Wave 2 · Batch 2A · Task 2A.1 |
| 10 | Multi-Vendor Topology, BGP/OSPF Polling & SNMP Traps (`sc4snmp:traps`) | SC4S Family | `routing`, `l2_control`, `state_events`, Path Trace LLDP | Wave 2 · Batch 2A · Tasks 2A.3 & 2A.4 |
| 11 | Multi-Vendor Operational Syslog via SC4S (Arista, Juniper, PAN, FGT, F5) | SC4S Family | `multiVendorSyslog.ts` + `state_events`, `routing`, `l2_control`, `lb_health` | Wave 0 · Task 0.3 & Waves 1–2 |
| 12 | 802.1X/NAC Access (`cisco:ise:syslog`) & Infoblox DDI (`7473` + SC4S `infoblox:{dns,dhcp}`) | SC4S Family | New Lens `network_access` + `l2_control` + `dns_ops` | Wave 2 · Tasks 2A.2, 2A.4, 2B.1 |
| 13 | Cisco Streaming MDT via OTel `yang_grpc` — VXLAN EVPN & Sub-Min Metrics | OTel Collector | New Lens `evpn_overlay` + `metricsRunner.ts` | Wave 3 · Batch 3A · Task 3A.1 |
| 14 | Graduate OTel `gnmi` Pilot (`gnmiContext.ts` → Multi-Vendor OpenConfig) | OTel Collector | Path Trace + `interface_health` + `optics_hardware` + `routing` + `qos_icmp` | Wave 3 · Batch 3A · Task 3A.2 & Batch 3B |
| 15 | Agentless Legacy Switch Monitoring via OTel `cisco_os` Receiver | OTel Collector | `otelNetworkAdapters/` + `interface_health` | Wave 3 · Batch 3A · Task 3A.4 & Batch 3B · Task 3B.1 |
| 16 | Distributed Edge Synthetic Probes (`icmp_check`, `dns_check`, `tcp_check`, `tls_check`) | OTel Collector | `dns_ops`, `tcp_tls`, `qos_icmp` (Synthetic badged) | Wave 2 · Batch 2B · Tasks 2B.1–2B.3 |
| 17 | Precision Timing & Clock Sync (`ptp`, `ntp`, `chrony`) Integrity | OTel Collector | `mgmt_plane` + `Admin -> Data Health` clock-skew panel | Wave 3 · Batch 3A · Task 3A.3 |
| 18 | CNI-Agnostic K8s eBPF (`OBI`) + `k8s_events` + Prometheus Network Exporters | OTel Collector | `otelNetworkAdapters/` + `state_events` + `routing` + `dns_ops` | Wave 3 · Batch 3A · Task 3A.4 & Batch 3B |
| 19 | **Multi-Vendor Firewall & Virtual-Fabric Flow TAs** (Juniper `2847`, PAN `7523` v4.0, Fortinet `2846`, Check Point `5402`, VMware NSX `6805`) | Splunk TAs | Ecosystem Traffic Evidence + `drops` + `research/package-manifest.json` | Wave 0 · Task 0.5 & Wave 2 · Batch 2C · Tasks 2C.1 & 2C.2 |

---

## Wave 0 — Shared Architecture, Metrics (`| mstats`) Foundation, Multi-Vendor TA Intake & Multi-Agent Scaffolding

**Owner:** Orchestrator (Root Agent only — sequential prerequisite; zero parallel workers in Wave 0 because every file is shared infrastructure). **Zero new lens IDs or `SupplementalSource` IDs are added in Wave 0**, guaranteeing Wave 0 passes every existing test and `python3 tools/check_release.py --dist dist` cleanly.

### Task 0.1: Add Synced `ecosystem-worker` Agent Role & Align `protocol-worker` Instructions

**Files:**
- Create: `.cursor/agents/ecosystem-worker.md`
- Create: `.codex/agents/ecosystem_worker.toml`
- Create: `docs/superpowers/specs/2026-11-27-ecosystem-worker-brief.md`
- Modify: `.cursor/agents/protocol-worker.md` & `.codex/agents/protocol_worker.toml` (update allowed paths to `frontend/src/protocols/lenses/<lens>/` and hyphenated `docs/operators/protocol-<hyphenated-lens>.md`, and update commands to scoped `npx prettier --write` + `npx eslint` + `npx vitest run` keeping Cursor and Codex instruction text byte-identical)
- Modify: `.codex/config.toml` (register `[agents.ecosystem_worker]`)
- Modify: `tests/test_agent_definitions.py` (add `ecosystem-worker` to `ROLES` and `expected` model map)
- Modify: `docs/OPERATING_MODEL.md` (document `ecosystem-worker` alongside `protocol-worker`)
- Modify: `docs/superpowers/specs/2026-11-27-protocol-worker-brief.md` (update Section 3 to permit `multiVendorSyslog.ts` alongside `nxosSyslog.ts`, and Section 4 worker commands to scoped `npx prettier --write` + `npx eslint` + `npx vitest run`)

**Interfaces:**
- Produces: Synced non-readonly `ecosystem-worker` role (`model: gemini-4-hydrogen` / Codex `gpt-6.1-terra`, medium) with identical instruction body in Cursor and Codex, forbidding edits to `frontend/src/protocols/shared/`, `frontend/src/data/evidence.ts`, `macros.conf`, `collections.conf`, `transforms.conf`, `metadata/default.meta`, `registry.ts`, `config/deployment-health.json`, `evidenceConfig.ts`, `setupClient.ts`, `tools/*`, `tests/browser/*`, `package.json`, and Vite configs.

- [ ] **Step 1: Write failing test update in `tests/test_agent_definitions.py`**
  Add `"ecosystem-worker"` entry to `ROLES` (`cursor: "ecosystem-worker.md"`, `codex: "ecosystem_worker.toml"`, `config_key: "ecosystem_worker"`, `readonly: False`) and `expected["ecosystem-worker"] = "gemini-4-hydrogen"`.
- [ ] **Step 2: Run test to verify failure**
  Run: `python3 -m unittest tests/test_agent_definitions.py`
  Expected: FAIL (`AssertionError` on `every .cursor/agents/*.md file needs a ROLES mapping, and every mapped role needs a file`).
- [ ] **Step 3: Create `.cursor/agents/ecosystem-worker.md`, `.codex/agents/ecosystem_worker.toml`, register in `.codex/config.toml`, create `docs/superpowers/specs/2026-11-27-ecosystem-worker-brief.md`, and update `docs/OPERATING_MODEL.md` + `2026-11-27-protocol-worker-brief.md`**
  Ensure exact instruction-text parity between Cursor markdown body and Codex `developer_instructions`.
- [ ] **Step 4: Run verification**
  Run: `python3 -m unittest tests/test_agent_definitions.py && ruff check tests/test_agent_definitions.py`
  Expected: PASS (all agent sync tests green, 0 ruff errors).

---

### Task 0.2: Build Bounded Dual-Shape Splunk Metrics (`| mstats`) Runner & URL-Persisted Metrics Window Contract

**Files:**
- Create: `frontend/src/protocols/shared/metricsRunner.ts`
- Create: `frontend/src/protocols/shared/metricsRunner.test.ts`
- Modify: `frontend/src/protocols/shared/contract.ts` (export `MAX_METRICS_WINDOW_SECONDS = 7 * 86400`, `ProtocolWindowMode = "events" | "metrics"`; add optional `windowMode?: ProtocolWindowMode` to `ProtocolRequest` and `ProtocolLensComponentProps`)
- Modify: `frontend/src/protocols/inputs.ts` (carry `p_wmode` in `ParsedProtocolLink`, `protocolLink()`, `parseProtocolLink()`, `validateProtocolWindow()`, and `validateProtocolRequest()`, enforcing `<= 3600s` whenever `windowMode !== "metrics"`)
- Modify: `frontend/src/protocols/ProtocolsPage.tsx` (pass `windowMode` to lens props, support `windowMode` in `applyProtocolParamPatch`, and reset `windowMode` to `"events"` + clamp window to `<= 3600s` inside `openLens` when switching to an event-only lens — Review Focus #1)
- Modify: `frontend/src/protocols/shared/runner.ts` (enforce `latest - earliest <= MAX_WINDOW_SECONDS` inside `runBoundedProtocolSearch` so wider metrics windows can NEVER leak into event searches)
- Modify: `frontend/src/protocols/shared/ui/ProtocolLensLayout.tsx` (optional `metricsPresets?: boolean` prop offering `24h` / `7d` window presets ONLY when metrics-only profiles are selected; event-backed profiles remain capped at `15m / 30m / 60m`)
- Modify: `tools/protocol-lenses.mjs` (expose `frontend/src/protocols/shared/metricsRunner` in `PROTOCOLS_CORE_SDK_MODULES`)
- Modify: `frontend/src/protocols/protocols-core-entry.ts` (re-export `metricsRunner` onto `__AtlasProtocolsCore`)

**Interfaces:**
- Consumes: `optionalJobs` (`../../data/optionalJobs`), `literal` (`../../data/evidence`), `SearchClient` (`../../data/searchClient`), `assertNoForbiddenFieldsInSpl`, `isFieldAllowedForLens`, `projectRowToLensAllowlist` (`./fields`), `BoundedSearchResult` (`./runner`).
- Produces:
  - `export const METRIC_NAME_RE = /^[A-Za-z][A-Za-z0-9._:-]{0,127}$/` *(explicitly allows hyphens for `sc4snmp.IF-MIB.*` and `Cisco-IOS-XE-*`, forbids `*` wildcards, and double-quotes hyphenated metric names inside `mstats`!)*
  - `export interface MetricSeriesSpec { metric: string; agg: "avg" | "max" | "min" | "latest" | "rate"; alias: string; }`
  - `export interface MetricFilterClause { field: string; op: "=" | "!=" | "IN"; values: readonly string[]; }` *(structured validated filters — NO raw SPL `whereClause` string!)*
  - `export interface BoundedMetricsSummaryOptions { lens: ProtocolLensId; profile: BaseProtocolProfile; metrics: readonly MetricSeriesSpec[]; dimensions: readonly string[]; filters?: readonly MetricFilterClause[]; rankBy?: string; earliest: number; latest: number; maxRows?: number; signal: AbortSignal; keySuffix?: string; }`
  - `export interface BoundedMetricsTrendOptions extends Omit<BoundedMetricsSummaryOptions, "rankBy"> { entityField: string; entityValues: readonly string[]; spanSeconds?: number; }` *(enforces `entityValues.length <= 8` and `buckets <= 32` so `entityValues × buckets <= 256` never truncates newest buckets!)*
  - `export function autoMetricsSpanSeconds(earliest: number, latest: number, maxBuckets?: number, requestedSpan?: number): number`
  - `export function buildBoundedMstatsSummarySpl(options: Omit<BoundedMetricsSummaryOptions, "signal" | "keySuffix">): string`
  - `export function buildBoundedMstatsTrendSpl(options: Omit<BoundedMetricsTrendOptions, "signal" | "keySuffix">): string`
  - `export function runBoundedMetricsSummary(client: SearchClient, options: BoundedMetricsSummaryOptions): Promise<BoundedSearchResult>`
  - `export function runBoundedMetricsTrend(client: SearchClient, options: BoundedMetricsTrendOptions): Promise<BoundedSearchResult>`
  - `export function clampNonNegativeRate(value: unknown): number | undefined` (returns `undefined` on negative counter-reset artifacts instead of synthetic `0`)

- [ ] **Step 1: Write failing unit tests in `frontend/src/protocols/shared/metricsRunner.test.ts` + extend `inputs.test.ts` & `ProtocolsPage.test.tsx`**
  Pin: (a) strict validation of index/metric/dimension names and structured `MetricFilterClause[]` rejecting raw SPL injection; (b) pre-dispatch fail-fast throwing if any `alias` or `dimension` is missing from `LENS_FIELD_ALLOWLISTS[lens]`; (c) summary SPL omits `span=` and sorts descending before `| head ${maxRows + 1}` (fitting up to 256 entities without time-bucket truncation); (d) trend SPL enforces `<= 8` entities and `<= 32` buckets; (e) `clampNonNegativeRate` returns `undefined` on negative counter-reset values; (f) `protocolLink` / `parseProtocolLink` round-trip `p_wmode=metrics` for a 7-day window while `openLens` resets to `"events"` (`<= 3600s`) when switching to an event lens; (g) `runBoundedProtocolSearch` rejects any event search with `latest - earliest > 3600`.
- [ ] **Step 2: Run test to verify failure**
  Run: `npx vitest run frontend/src/protocols/shared/metricsRunner.test.ts frontend/src/protocols/inputs.test.ts frontend/src/protocols/ProtocolsPage.test.tsx`
  Expected: FAIL (`Cannot find module './metricsRunner'`).
- [ ] **Step 3: Implement `metricsRunner.ts`, `contract.ts` / `inputs.ts` / `ProtocolsPage.tsx` / `runner.ts` / `ProtocolLensLayout.tsx` metrics window support, and register in `tools/protocol-lenses.mjs` + `protocols-core-entry.ts`**
- [ ] **Step 4: Run verification**
  Run: `npx vitest run frontend/src/protocols/shared/metricsRunner.test.ts frontend/src/protocols/shared/runner.test.ts frontend/src/protocols/inputs.test.ts frontend/src/protocols/ProtocolsPage.test.tsx && npm run typecheck`
  Expected: PASS.

---

### Task 0.3: Build Per-Vendor Multi-Vendor SC4S Operational Syslog Adapter Registry

**Files:**
- Modify: `frontend/src/protocols/shared/adapters/nxosSyslog.ts` (widen `NormalizedStateEvent.sourceKind` union to include `"sc4s_arista_eos" | "sc4s_juniper_junos" | "sc4s_pan_system" | "sc4s_fortigate_event" | "sc4s_f5_syslog" | "sc4s_cisco_asa_ftd" | "sc4snmp_trap"` while keeping `ALLOWED_SYSLOG_SOURCETYPES` and `buildSyslogStateSearch` backward-compatible for Cisco IOS/NX-OS/ACI)
- Create: `frontend/src/protocols/shared/adapters/multiVendorSyslog.ts`
- Create: `frontend/src/protocols/shared/adapters/multiVendorSyslog.test.ts`
- Modify: `tools/protocol-lenses.mjs` (expose `multiVendorSyslog` in `PROTOCOLS_CORE_SDK_MODULES`)
- Modify: `frontend/src/protocols/protocols-core-entry.ts` (re-export `multiVendorSyslog`)

**Interfaces:**
- Consumes: `NormalizedStateEvent`, `SyslogOperationalDomain`, `buildSyslogStateSearch`, `normalizeSyslogRow` (`./nxosSyslog`), `assertNoForbiddenFieldsInSpl` (`../fields`).
- Produces:
  - `export const MULTI_VENDOR_SC4S_SOURCETYPES = ["cisco:ios", "cisco:dc:nexus9k:syslog", "cisco:aci", "cisco:dc:aci:syslog", "arista:eos", "juniper:junos:structured", "pan:system", "fortigate_event", "fgt_event", "f5:bigip:syslog", "cisco:asa", "cisco:ftd", "cisco:ftd:syslog"] as const` *(Note: `juniper:junos:firewall` SRX RT_FLOW session logs belong in the Juniper flow adapter in Task 2C.1 / `drops`, NOT operational state syslog.)*
  - **Per-vendor SPL builders (no cross-vendor regex assumptions):**
    - `buildCiscoIosAciSyslogSearch(...)` — delegates directly to `buildSyslogStateSearch` for the 4 Cisco IOS/NX-OS/ACI sourcetypes.
    - `buildAristaEosSyslogSearch(...)` — `sourcetype="arista:eos"` `%FACILITY-SEV-MNEMONIC` extraction excluding `AAA`/`SECURITY`/`CLI`/`CONFIG` categories.
    - `buildCiscoAsaFtdSyslogSearch(...)` — `sourcetype IN ("cisco:asa", "cisco:ftd", "cisco:ftd:syslog")` using an **explicit operational message-ID allowlist** (failover `104*`/`105*`, interface/link `411*`, routing/BGP/OSPF `408*`/`318*`, IPsec site-to-site tunnel state) — NOT category exclusion (since every ASA event carries facility `ASA`!).
    - `buildJuniperJunosSyslogSearch(...)` — `sourcetype="juniper:junos:structured"` filtering to operational daemons (`rpd`, `chassisd`, `l2ald`, `mib2d`) and explicitly excluding `mgd`/`sshd`/`UI_CMDLINE_READ_LINE`.
    - `buildPanSystemSearch(...)` — `sourcetype="pan:system"` filtering `subtype IN ("routing", "ha", "vpn", "general")` and excluding `auth`/`userid`/`globalprotect` user PII.
    - `buildFortigateEventSearch(...)` — `sourcetype IN ("fortigate_event", "fgt_event")` using an **explicit operational `logid` / `logdesc` allowlist** (BGP/OSPF/BFD neighbor, SD-WAN SLA health-check failover, HA cluster state, IPsec tunnel up/down) so admin logins (`subtype="system"`) and SSL-VPN user logins (`subtype="vpn"`) with usernames in `msg` NEVER cross the wire!
    - `buildF5SyslogSearch(...)` — `sourcetype="f5:bigip:syslog"` filtering to `mcpd`/`tmm`/`sod` pool-member up/down, HA failover, and SNAT port exhaustion, excluding `sshd`/`httpd` auth.
  - `export function buildMultiVendorSyslogSearches(options: { index: string; sourcetypes: readonly MultiVendorSyslogSourcetype[]; device?: string; domains?: readonly SyslogOperationalDomain[]; maxRows: number }): Array<{ family: string; spl: string }>`
  - `export function normalizeMultiVendorSyslogRow(row: ProtocolRow, indexInBatch: number): NormalizedStateEvent | undefined`

- [ ] **Step 1: Write failing unit tests in `frontend/src/protocols/shared/adapters/multiVendorSyslog.test.ts`**
  Pin: (a) every per-vendor builder emits bounded SPL (`| head ${maxRows + 1}` before `| table`) that passes `assertNoForbiddenFieldsInSpl`; (b) normalization of Arista EOS `%BGP-5-ADJCHANGE`/`%MLAG-*`/`%TRANSCEIVER-*`, Juniper `rpd`/`chassisd`, PAN `pan:system`, FortiGate operational `logid`s, F5 `f5:bigip:syslog`, and ASA/`cisco:ftd:syslog` operational IDs; (c) strict SPL + client rejection of ASA auth IDs (`113*`/`605*`), FortiGate admin/SSL-VPN user login events, Juniper `mgd` CLI commands, and PAN `auth`/`globalprotect` user events (Review Focus #3).
- [ ] **Step 2: Run test to verify failure**
  Run: `npx vitest run frontend/src/protocols/shared/adapters/multiVendorSyslog.test.ts`
  Expected: FAIL.
- [ ] **Step 3: Update `nxosSyslog.ts`, implement `multiVendorSyslog.ts`, and expose via `PROTOCOLS_CORE_SDK_MODULES` + `protocols-core-entry.ts`**
- [ ] **Step 4: Run verification**
  Run: `npx vitest run frontend/src/protocols/shared/adapters/`
  Expected: PASS.

---

### Task 0.4: Extend Privacy Guard Tests, Stage Splunk Lab Metrics Indexes & Dynamic Release Gate

**Files:**
- Modify: `frontend/src/protocols/shared/fields.test.ts` *(already exists — extend, do not recreate!)*
- Modify: `frontend/src/protocols/shared/fields.ts` (add `src_user`, `dest_user` to `FORBIDDEN_SENSITIVE_FIELDS`; add real ISE identity fields `user`, `user_name`, `src_user_name`, `x_user`, `UserName`, `User_Name`, `OriginalUserName` to a dedicated `ISE_ROW_EXPANSION_ONLY_FIELDS` / `ROW_EXPANSION_ONLY_FIELDS` set; keep `http_url` excluded via allowlists & sFlow guard so `lb_health/adapter.ts:199` F5 `F5_SAFE_REX_PATTERN` never breaks!)
- Modify: `tests/splunk/lab_app/default/indexes.conf` (add `[netmetrics]` and `[network_metrics]` with `datatype = metric`)
- Modify: `tests/splunk/lab_app/default/inputs.conf.template` (append `netmetrics,network_metrics` to `[http://adm-lab]` `indexes = ...`)
- Modify: `tests/splunk/lab.py` (add `ingest_metrics(index, points)` helper posting HEC `"event": "metric"` payloads to the lab HEC endpoint)
- Modify: `tests/test_lab_staging.py` (update staged template assertions for the new metrics indexes if pinned)
- Modify: `tools/check_release.py` (line 1453: format error string dynamically with `len(expected_lens_ids)` instead of hardcoded `"all 13 implemented lenses"`)
- Modify: `splunk_app/splunk_adm/default/macros.conf` (add fail-closed `index=unconfigured_optional` macros + `0` schema flags for `adm_index_intersight`, `adm_index_sflow`, `adm_index_fmc_policy`, `adm_index_netmetrics`, `adm_index_ise`, `adm_index_infoblox`, `adm_index_otel_metrics`, `adm_index_cloud_transit`, `adm_index_arista`, `adm_index_juniper`, `adm_index_checkpoint`, `adm_index_nsx`, `adm_index_netscaler`, `adm_index_aruba`; reuse existing `adm_index_snmp` [`index=netops`] for SC4SNMP traps)
- Modify: `tests/test_ecosystem_fixtures.py` (add fail-closed `index=unconfigured_optional` assertions for all newly added optional macros)

- [ ] **Step 1: Extend `frontend/src/protocols/shared/fields.test.ts`**
  Pin: (a) no `LENS_FIELD_ALLOWLISTS` entry intersects `FORBIDDEN_SENSITIVE_FIELDS`; (b) `assertNoForbiddenFieldsInSpl` blocks `src_user`, `dest_user`, `_raw`, `community`, `password`, and wildcard projections; (c) existing `lb_health` F5 `F5_SAFE_REX_PATTERN` continues to pass `assertNoForbiddenFieldsInSpl` (Review Focus #3).
- [ ] **Step 2: Apply `fields.ts`, Splunk lab metrics staging (`indexes.conf`, `inputs.conf.template`, `lab.py`, `test_lab_staging.py`), `check_release.py`, `macros.conf`, and `test_ecosystem_fixtures.py` changes**
- [ ] **Step 3: Run Wave 0 build & unit validation**
  Run:
  ```sh
  npm run lint && npm test && npm run package
  python3 tools/check_release.py --dist dist
  ruff check tools tests && ruff format --check tools tests
  python3 -m unittest tests/test_agent_definitions.py tests/test_release.py tests/test_ecosystem_fixtures.py tests/test_lab_staging.py
  ```
  Expected: 100% PASS (all 13 existing lenses + `protocols-core.js <= 64 KiB` gzip + `atlas.js <= 680 KiB` gzip).

---

### Task 0.5: Official Multi-Vendor Splunkbase TA Intake & Static Package Provenance

**Files:**
- Modify: `research/package-manifest.json` (record Splunkbase ID, version, download provenance, SHA-256, and static `props.conf`/`transforms.conf` inspection notes — or explicit `pending` intake entry where Splunkbase license acceptance is required — for `1918` Arista, `2847` Juniper, `7523` Palo Alto v4.0, `2846` Fortinet, `5402` Check Point, `6805` VMware NSX, `2680` F5 BIG-IP v7.0.1, `2770` Citrix NetScaler, `3135` HAProxy, `4668` Aruba, `6302` Aruba EdgeConnect, and `7473` Infoblox)
- Ignored local data paths (never committed): `research/packages/` and `research/extracted/`
- Modify: `docs/TA_PACKAGE_ANALYSIS.md` (append static field/sourcetype inspection tables for each acquired multi-vendor TA)

- [ ] **Step 1: Acquire & statically extract approved Splunkbase TA archives (after user license acceptance where required by Splunkbase)**
  Place archives in ignored `research/packages/` and extract regular UTF-8 conf/text files (`<= 5 MiB`, no symlinks, execute bits stripped, zero scripts executed per `AGENTS.md`) into `research/extracted/`.
- [ ] **Step 2: Record SHA-256 checksums, Splunkbase IDs, versions, and static `props.conf` findings in `research/package-manifest.json` & `docs/TA_PACKAGE_ANALYSIS.md`**
  For any archive still awaiting download, record it under `"pending"` with primary-source doc URLs so workers label its fixtures documentation-shaped/unqualified until the archive is inspected.
- [ ] **Step 3: Wave 0 Read-Only Review Gate & Human Checkpoint**
  Dispatch `code-reviewer` (read-only) on Wave 0 diff. Remediate verified findings, rerun Task 0.4 Step 3, and pause for human approval before Wave 1.

---

## Wave 1 — Tier 1 Zero-New-Collector Wins & Multi-Vendor Switch/LB Flow TAs

> **Concurrency:** 2 batches of 4 strictly file-disjoint workers each (`<= 4` concurrent threads).
> **Wave 1 Pre-Batch Orchestrator Prep (before dispatching Batch 1A):**
> - Register `wan_tunnels` and `fabric_congestion` in `frontend/src/data/evidence.ts` (`ProtocolSource`), `frontend/src/protocols/shared/contract.ts` (`PROTOCOL_LENS_IDS`), `frontend/src/protocols/shared/fields.ts` (`LENS_FIELD_ALLOWLISTS`), and `config/deployment-health.json` (`protocol_wan_tunnels`, `protocol_fabric_congestion`).
> - Expand `LENS_FIELD_ALLOWLISTS` for `interface_health` (SC4SNMP `| mstats` aliases + Catalyst/Meraki/sFlow/Arista `1918` fields), `state_events` (multi-vendor SC4S fields), and `lb_health` (HAProxy `3135` + Citrix NetScaler `2770` + F5 `2680` v7.0.1 iControl/syslog).
> - Register `fmc_policy` in `SupplementalSource` (`evidence.ts`), `evidenceConfig.ts`, and `config/deployment-health.json`.

### Batch 1A — 4 Concurrent Workers (All Disjoint Write Paths)

#### Task 1A.1 (`ecosystem-worker`): Feature #1 — UCS Intersight & `vmnic` Physical Pinning
- **Allowed writes:** `frontend/src/trace/intersight/`, `fixtures/intersight/` (including `FIELDS.md`), `tests/splunk/test_intersight_paths.py`, `docs/operators/intersight-evidence.md`
- **Grounding:** `research/extracted/cisco-intersight-add-on-for-splunk_322/Splunk_TA_Cisco_Intersight/default/props.conf` & `constants.py` — exact sourcetypes: `cisco:intersight:networkobjects` / `cisco:intersight:networkObjects` (`source IN ("adapterHostEthInterface", "etherPhysicalPort", "etherPortChannel")`), `cisco:intersight:networkelements`, `cisco:intersight:profiles` (`source IN ("fabricSwitchProfile", "fabricSwitchClusterProfile")` — NEVER query renamed `cisco:intersight:fabric`!), `cisco:intersight:alarms`, `cisco:intersight:metrics`; plus `docs/operators/INTERSIGHT_VMWARE_LAB_SETUP.md`.
- **Produces:**
  - `export function buildIntersightPinSearch(options: { index: string; hostMacs: readonly string[]; earliest: number; latest: number; maxRows: number }): string`
  - `export function attachIntersightFiHops(hops: readonly TraceHop[], rows: readonly unknown[], opts: { scope: string; earliest: number; latest: number }): TraceHop[]` (upgrades inferred UCS FI hops to observed when `adapterHostEthInterface` MAC matches ESXi `vmnic` + `etherPhysicalPort`/`etherPortChannel`; emits single-fabric redundancy flags for Blast Radius Impact)
- **Acceptance checks:**
  - [ ] Scoped lint & unit tests (`npx eslint frontend/src/trace/intersight && npx prettier --check frontend/src/trace/intersight && npx vitest run frontend/src/trace/intersight`) cover dual-fabric (redundant), single-fabric (degraded/outage risk), ambiguous MAC (fails closed), and missing telemetry (`not_covered`).
  - [ ] `tests/splunk/test_intersight_paths.py` validates bounded SPL against TA-grounded synthetic `fixtures/intersight/` events using `cisco:intersight:networkobjects` and `cisco:intersight:profiles` (Review Focus #4).
  - [ ] `docs/operators/intersight-evidence.md` documents HF inputs (`7828` v3.2.2), `adm_index_intersight`, `adm_observer_scope`, and single-fabric failover interpretation.
  - [ ] Handoff proposes `adm_intersight_fi_pin` macro stanza for Orchestrator integration into `macros.conf`, `usePathTrace.ts`, and `impact/`.

#### Task 1A.2 (`protocol-worker`): Feature #2 — New `wan_tunnels` Protocol Lens (SD-WAN & Meraki WAN SLA)
- **Allowed writes:** `frontend/src/protocols/lenses/wan_tunnels/` (flat files), `fixtures/protocols/wan_tunnels/` (including `FIELDS.md`), `docs/operators/protocol-wan-tunnels.md`
- **Grounding:**
  - `research/extracted/cisco-enterprise-networking-add-on-for-splunk_4060/TA_cisco_catalyst/default/props.conf`: `cisco:sdwan:tunnelhealth`, `cisco:sdwan:linkhealth`, `cisco:sdwan:sitehealth`, `cisco:sdwan:ssetunnelhealth`, `cisco:sdwan:ssetunnels`
  - `research/extracted/cisco-meraki-add-on-for-splunk_350/Splunk_TA_cisco_meraki/default/props.conf`: `meraki:devicesuplinkslossandlatency`, `meraki:appliancesdwanstatistics`, `meraki:appliancesdwanstatuses`
  - `multiVendorSyslog.ts`: `pan:system` VPN, `fortigate_event` / `fgt_event` operational SD-WAN/IPsec `logid`s
- **Produces:**
  - `validate.ts` (`validateWanTunnelsExtra`: `sourceKind`, `lossWarnPct`, `latencyWarnMs`, `jitterWarnMs`, `flapWarnCount`)
  - `adapter.ts` (`summarizeWanTunnels`), `WanTunnelsLensPage.tsx`, `index.ts` (Overview, Site × Transport/Tunnel `HeatMatrix`, `SwimlaneTimeline`, Detail Drawer; `< 60` chrome words, `<= 4` KPI tiles)
- **Acceptance checks:**
  - [ ] `npx prettier --write frontend/src/protocols/lenses/wan_tunnels && npx eslint frontend/src/protocols/lenses/wan_tunnels && npx vitest run frontend/src/protocols/lenses/wan_tunnels` passes; SD-WAN TLOC option correlation explicitly excluded and documented in `docs/operators/protocol-wan-tunnels.md`.

#### Task 1A.3 (`ecosystem-worker`): Feature #3 — Multi-Vendor Switch & Virtual Flow Mapping via `stream:sflow` (`1809`), Arista Telemetry TA (`1918`) & VMware NSX IPFIX (`6805`)
- **Allowed writes:** `frontend/src/data/sflowProfile.ts`, `frontend/src/data/sflowProfile.test.ts`, `fixtures/sflow/` (including `FIELDS.md`), `tests/splunk/test_sflow.py`, `docs/operators/sflow-evidence.md`
- **Grounding:** `research/extracted/splunk-app-for-stream_816/splunk_app_stream/default/streams/sflow`, Task 0.5 Arista Telemetry TA (`1918` v2.0.2) static inspection, VMware NSX (`6805`) IPFIX template docs, and `docs/operators/network-stream.md`.
- **Produces:**
  - `export const SFLOW_PROFILE_ID = "sflow_switch" as const` and `export const NSX_IPFIX_PROFILE_ID = "vmware_nsx_ipfix" as const`
  - `export function buildSflowBoundedSearch(...)` (supports `stream:sflow` and Arista Telemetry TA `1918` sFlow records; strictly excludes `http_url`, `src_user`, `dest_user`; retains `sflow_sampling_rate`, `next_hop_address`, `dest_path_as_nums`, `gateway_communities`, `route_local_pref`, `mpls_in_label`, `mpls_out_label`, `dot3_stats_fcs_errs`)
  - `export function normalizeSflowObservation(...)` (labels counts as sampled estimates; never merges with NetFlow/Hubble totals — Review Focus #2)
- **Acceptance checks:**
  - [ ] Scoped lint, unit tests, and `tests/splunk/test_sflow.py` verify sampling attribution, Arista `1918` & `stream:sflow` normalization, BGP AS-path/MPLS extraction, `http_url`/`src_user`/`dest_user` exclusion, and zero cross-sensor summing.
  - [ ] `docs/operators/sflow-evidence.md` documents `streamfwd.conf` `netflowReceiver.N.decoder = sflow`, Arista Telemetry TA (`1918` v2.0.2), VMware NSX IPFIX (`vmware_nsx_ipfix`), and Arista/Juniper/SONiC/Aruba exporter registration in `adm_network_source_scope`.
  - [ ] Handoff supplies exact integration patch specs for Orchestrator across `setupClient.ts`, `macros.conf` (`adm_profile_supported`, health profile rows, source classification, V2 flow ingest), and `tests/test_cisco_fixtures.py`.

#### Task 1A.4 (`protocol-worker`): Feature #4 — New `fabric_congestion` Protocol Lens (DCN 2.0.10 PFC/ECN, MSO, Hyperfabric, MDS SAN + Arista `1918` LANZ)
- **Allowed writes:** `frontend/src/protocols/lenses/fabric_congestion/` (flat files), `fixtures/protocols/fabric_congestion/` (including `FIELDS.md`), `docs/operators/protocol-fabric-congestion.md`
- **Grounding:** `research/extracted/cisco-dc-networking_2010/cisco_dc_networking_app_for_splunk/default/props.conf` (`cisco:dc:nd:congestion`, `cisco:dc:nd:anomalies`, `cisco:dc:nd:advisories`, `cisco:dc:nd:mso`, `cisco:dc:hyperfabric:{inventory,performance,notification}`, `cisco:dc:mds:{congestion,san_analytics,alarm,performance}`), Task 0.5 Arista Telemetry TA (`1918`) LANZ queue-congestion records, and `docs/research/hyperfabric-capabilities.md`.
- **Produces:**
  - `validate.ts` (`validateFabricCongestionExtra`: `sourceKind` including `"arista_lanz"`, `pfcWarnCount`, `ecnWarnCount`, `b2bZeroWarnCount`)
  - `adapter.ts` (`summarizeFabricCongestion`), `FabricCongestionLensPage.tsx`, `index.ts` (Overview + Fabric/Switch × Subsystem Matrix + Congestion Swimlane + Drawer)
- **Acceptance checks:**
  - [ ] Scoped lint & unit tests prove MDS SAN, Hyperfabric, Arista LANZ, and ACI/ND scopes remain strictly isolated (never cross-joined), missing subsystems render `Not covered`, and `docs/operators/protocol-fabric-congestion.md` documents DCN 2.0.10 + Arista `1918` LANZ setup.

---

### Batch 1B — 4 Concurrent Workers (Launched after Batch 1A Completes)

#### Task 1B.1 (`protocol-worker`): Features #8 & #5a — Upgrade `interface_health` with SC4SNMP `| mstats` (`netmetrics`), Campus/Meraki/Arista `1918` Interface Stats & sFlow dot3 PHY Errors
- **Allowed writes:** `frontend/src/protocols/lenses/interface_health/` (flat files), `fixtures/protocols/interface_health/`, `docs/operators/protocol-interface-health.md`
- **Consumes:** `metricsRunner.ts` (`runBoundedMetricsSummary`, `runBoundedMetricsTrend`, `clampNonNegativeRate`) and `ProtocolLensLayout` (`metricsPresets` prop) from Wave 0.
- **Grounding:** SC4SNMP `netmetrics` (`sc4snmp.IF-MIB.{ifHCInOctets,ifHCOutOctets,ifHighSpeed,ifInErrors,ifOutErrors,ifInDiscards,ifOutDiscards}`), Catalyst `cisco:dnac:devicehealth:interface`, Meraki `meraki:switchportsbyswitch` / `meraki:switchportsoverview` / `meraki:wirelessdevicesethernetstatuses`, Arista Telemetry TA (`1918`) interface counters, and `stream:sflow` (`dot3_stats_fcs_errs`, `dot3_stats_symbol_errors`).
- **Acceptance checks:**
  - [ ] Adds `sourceKind` options `"sc4snmp_metrics"`, `"catalyst_interface"`, `"meraki_switch"`, `"arista_telemetry"`, `"sflow_phy"` alongside `"dme"` / `"syslog"` / `"auto"`.
  - [ ] Uses no-`span=` summary query for the interface table (up to 256 ports) and top-8 sparkline trend query for sparklines; enables `24h / 7d` window presets ONLY when metrics-only profiles are selected (`p_wmode=metrics`).
  - [ ] Unit tests cover 64-bit utilization `(rate*8)/(ifHighSpeed*1e6)*100`, counter-reset guard (Review Focus #1), single-poll burst caveat, and `Not covered` for missing directions.
  - [ ] Updates `docs/operators/protocol-interface-health.md`; handoff delivers fail-closed `adm_ifmib_capacity` macro referencing `` `adm_index_netmetrics` ``.

#### Task 1B.2 (`protocol-worker`): Feature #11a — Upgrade `state_events` with Multi-Vendor SC4S Operational Syslog
- **Allowed writes:** `frontend/src/protocols/lenses/state_events/` (flat files), `fixtures/protocols/state_events/`, `docs/operators/protocol-state-events.md`
- **Consumes:** `multiVendorSyslog.ts` from Wave 0.
- **Acceptance checks:**
  - [ ] Supports Arista EOS, Juniper Junos (`juniper:junos:structured`), PAN-OS `pan:system`, FortiGate operational `logid`s, F5 `f5:bigip:syslog`, and Cisco ASA/`cisco:ftd`/`cisco:ftd:syslog` operational IDs on `SwimlaneTimeline` and `Device × Domain` `HeatMatrix`.
  - [ ] Unit tests assert AAA/CLI-audit/config-change/VPN-user events are excluded across every vendor and `docs/operators/protocol-state-events.md` documents SC4S multi-vendor setup + provenance limits.

#### Task 1B.3 (`protocol-worker`): Features #6b & #11b — Upgrade `lb_health` with HAProxy (`3135`), Citrix NetScaler (`2770`) & F5 BIG-IP (`2680` v7.0.1 iControl + `f5:bigip:syslog`)
- **Allowed writes:** `frontend/src/protocols/lenses/lb_health/` (flat files), `fixtures/protocols/lb_health/`, `docs/operators/protocol-lb-health.md`
- **Consumes:** `multiVendorSyslog.ts` (`buildF5SyslogSearch`), Task 0.5 static extractions for `2680` v7.0.1, `2770` v8.2.5 (AppFlow/IPFIX + NITRO + syslog), and `3135` (`haproxy:http`).
- **Acceptance checks:**
  - [ ] Adds `sourceKind` options `"haproxy"`, `"netscaler"`, `"f5_syslog"`, and `"f5_icontrol"` alongside `"f5_ltm"`, `"aws_alb"`, `"aws_nlb"`, `"auto"`.
  - [ ] Preserves existing F5 `F5_SAFE_REX_PATTERN` tests; excludes HAProxy/NetScaler URI queries, cookies, and headers; separates balancer vs backend target errors via HAProxy `termination_state` and NetScaler AppFlow/NITRO status; maps F5 pool-member mark-down/mark-up and SNAT exhaustion into timeline & drawer.
  - [ ] Updates `docs/operators/protocol-lb-health.md` with HAProxy (`3135`), Citrix NetScaler (`2770` v8.2.5), and F5 BIG-IP (`2680` v7.0.1) setup.

#### Task 1B.4 (`ecosystem-worker`): Feature #6a — FMC Firewall Policy Intent (`cisco:sfw:policy`) for Segmentation Policy & Move Groups
- **Allowed writes:** `frontend/src/segmentation/fmcPolicy/`, `fixtures/fmc-policy/` (including `FIELDS.md`), `tests/splunk/test_fmc_policy.py`, `docs/operators/fmc-policy-evidence.md`
- **Grounding:** `research/extracted/cisco-security-cloud_372/CiscoSecurityCloud/default/inputs.conf` (`sbg_sfw_api_input`, `sourcetype=cisco:sfw:policy`)
- **Produces:**
  - `export function buildFmcPolicySearch(...)` and `export function evaluateFmcRuleCoverage(conversations, policyRules)` (flags shadowed/unhit rules, overly broad `Any` rules, and pre-migration wave blockers while labeling policy snapshots strictly as configured intent separate from eStreamer runtime enforcement).
- **Acceptance checks:**
  - [ ] Scoped lint, unit tests, `tests/splunk/test_fmc_policy.py`, and `docs/operators/fmc-policy-evidence.md` pass; handoff details wiring into `frontend/src/segmentation/` (`<= 40 KiB` gzip) and `frontend/src/migration/` (`<= 48 KiB` gzip).

---

### Batch 1C — 4 Concurrent Workers (Zero-Collector War-Room Diagnostics & Edge Proxy/WAF Attribution — Launched after Batch 1B Completes)

#### Task 1C.1 (`ecosystem-worker`): End-to-End Path MTU Audit & Cross-Observer Asymmetric Routing / ECMP Polarization
- **Allowed writes:** `frontend/src/trace/pathDiagnostics/`, `fixtures/path-diagnostics/` (including `FIELDS.md`), `tests/splunk/test_path_diagnostics.py`, `docs/operators/path-diagnostics.md`
- **Produces:**
  - `pathMtuAudit.ts`: Correlates configured MTU across Path Trace hops (NX-OS/ACI DME `l1PhysIf.mtu`, VMware VDS `proxySwitch.mtu`, SC4SNMP `IF-MIB.ifMtu`, OTel `gnmi` MTU) with `stream:tcp` stalls and `stream:icmp` Type 3 Code 4 / ICMPv6 Type 2 to flag **Hop MTU Mismatch** badges.
  - `asymmetricRouting.ts`: Compares forward vs. reverse observer sets across `stream:netflow`, `stream:sflow`, `cisco:sfw:estreamer`, and multi-vendor firewalls to flag asymmetric stateful-firewall paths and ECMP hash polarization (extending `ATLAS_TROUBLESHOOTING_HANDOFF.md` Scenarios A2/A3).

#### Task 1C.2 (`ecosystem-worker`): Certificate Expiration Blast-Radius Correlation
- **Allowed writes:** `frontend/src/impact/certBlastRadius/`, `fixtures/cert-blast-radius/` (including `FIELDS.md`), `docs/operators/cert-blast-radius.md`
- **Produces:** Correlates expiring TLS/mTLS/802.1X certificates (`stream:tcp` `ssl_validity_end`, OTel `tls_check`, F5 iControl `2680`, Cisco ISE) onto the Atlas Dependency Map and Blast Radius Impact view so teams see which business apps and VIPs break before expiration.

#### Task 1C.3 (`protocol-worker`): Redacted Config-Change Marker Overlay on `state_events`
- **Allowed writes:** `frontend/src/protocols/lenses/state_events/` (flat files), `fixtures/protocols/state_events/`, `docs/operators/protocol-state-events.md`
- **Produces:** Overlays redacted *"Config commit / change window"* markers from existing `docs/change-correlation/` adapters, `pan:config` (`7523`), and `snow:change_request` (`1928`) onto `state_events` timelines without ever exposing CLI commands, diffs, or secrets.

#### Task 1C.4 (`protocol-worker`): Edge Reverse-Proxy / WAF / CDN Attribution in `lb_health` (NGINX `3258`, Cloudflare `4501`, Cisco Multicloud Defense)
- **Allowed writes:** `frontend/src/protocols/lenses/lb_health/` (flat files), `fixtures/protocols/lb_health/`, `docs/operators/protocol-lb-health.md`
- **Produces:** Adds `sourceKind` options `"nginx"`, `"cloudflare"`, and `"cisco_mcd"` (`cisco:multicloud:defense:*`, already extracted in `CiscoSecurityCloud` 3.7.2) to separate edge WAF/CDN blocks and NGINX upstream 5xx from internal DC/K8s network faults.

---

### Wave 1 Integration, Documentation & Review Gate (Orchestrator)

- [ ] **Step 1:** Integrate Batch 1A + 1B:
  - Wire `wan_tunnels` & `fabric_congestion` into `frontend/src/protocols/registry.ts`, `frontend/src/protocols/drillIn.ts`, `tools/protocol-lenses.mjs`, and `tools/check_release.py` (`EXPECTED_PROTOCOL_LENS_IDS` → 15 lenses).
  - Wire `sflow_switch` & `vmware_nsx_ipfix` across ALL required V2 flow-profile touchpoints: `frontend/src/data/setupClient.ts`, `frontend/src/data/setupClient.test.ts`, `splunk_app/splunk_adm/default/macros.conf` (`adm_profile_supported`, health profile rows, source classification, and `stream:sflow` in V2 flow ingest), `fixtures/raw-networking/source-profiles.json` + its generator, and `tests/test_cisco_fixtures.py`.
  - Wire `adm_ifmib_capacity` (referencing `` `adm_index_netmetrics` ``), `adm_intersight_fi_pin` (`usePathTrace.ts`, `impact/`), `fmcPolicy` (`segmentation/`, `migration/`), and extend `tests/splunk/test_protocol_lenses.py` with real `| mstats` assertions against the lab's `netmetrics` index.
  - Update `frontend/src/protocols/ProtocolsPage.test.tsx`, `tests/browser/protocols-harness.tsx` (add scenarios for `wan_tunnels`, `fabric_congestion`, metrics-mode `interface_health`), and `tests/browser/protocols.spec.ts`.
- [ ] **Step 2 (Documentation Lockstep):** Update `README.md`, `docs/operators/README.md`, `docs/operators/official-splunkbase-tas.md` (add Arista `1918`, Citrix NetScaler `2770`, F5 `2680` v7.0.1, HAProxy `3135`, Intersight `7828`), `docs/operators/ecosystem-tas.md`, `docs/operators/network-stream.md`, `docs/operators/cisco-enterprise-networking.md`, `docs/operators/segmentation-policy.md`, `docs/DATA_LAYER.md`, and `fixtures/raw/FIELDS.md`.
- [ ] **Step 3 (Build, Package, Unit, Lab & Screenshot Capture):**
  Run:
  ```sh
  npm run lint && npm test && npm run package
  python3 tools/check_release.py --dist dist
  ruff check tools tests && ruff format --check tools tests
  python3 -m unittest tests/test_release.py tests/test_ecosystem_fixtures.py tests/test_cisco_fixtures.py
  tests/splunk/lab.sh up && tests/splunk/lab.sh install
  ADM_LAB=1 python3 tools/lab_lock.py --root . -- sh -c '
    python3 -m unittest discover -s tests/splunk -p "test_protocol_lenses.py" &&
    python3 -m unittest discover -s tests/splunk -p "test_intersight_paths.py" &&
    python3 -m unittest discover -s tests/splunk -p "test_sflow.py" &&
    python3 -m unittest discover -s tests/splunk -p "test_fmc_policy.py"
  '
  tests/splunk/lab.sh purge
  ```
  Capture Playwright screenshots (`1440×900` and `1280×800`, light & dark, plus loading/empty/partial/blocked states) for `wan_tunnels`, `fabric_congestion`, `interface_health`, `state_events`, `lb_health`, and Intersight Path Trace.
- [ ] **Step 4 (Independent Read-Only Review Gates):**
  Launch `code-reviewer` and `ux-reviewer` in parallel (read-only). Fix all verified findings and re-run affected tests.
- [ ] **Step 5 (Human Checkpoint):** Report Wave 1 evidence, measured bundle sizes vs budgets, and review disposition; await human confirmation before Wave 2.

---

## Wave 2 — Multi-Vendor SC4S / SC4SNMP, Multi-Vendor Flow TAs, Enterprise NAC/DDI, Synthetic Probes & Cloud Transit

> **Concurrency:** 3 bounded batches (`<= 4` concurrent threads each — Batch 2A: 4 workers, Batch 2B: 4 workers, Batch 2C: 3 workers — zero overlapping write paths).
> **Wave 2 Pre-Batch Orchestrator Prep (before dispatching Batch 2A):**
> - Register `optics_hardware` and `network_access` in `evidence.ts`, `contract.ts`, `fields.ts` (with lowercase per-lens row-expansion support for `network_access` covering `user`, `user_name`, `user-name`, `src_user_name`, `x_user`, `username`, `originalusername`, `admin`, `adminname`, `portaluser`, `src_mac`, `src_ip`), and `config/deployment-health.json` (`protocol_optics_hardware`, `protocol_network_access`).
> - Expand `LENS_FIELD_ALLOWLISTS` for `routing` and `l2_control` (SC4SNMP MIBs/traps, Infoblox `7473`, PLUS `multiVendorSyslog` FortiGate `logid`/`logdesc`, PAN `subtype`, Juniper daemon fields), `dns_ops`, `tcp_tls`, `qos_icmp` (OTel synthetic probe metrics + explicit OpenConfig QoS queue metric aliases without wildcards), `drops`, and `wan_tunnels` (Juniper `2847` SRX, Check Point `5402`, VMware NSX `6805`, PAN `7523`, Aruba EdgeConnect `6302`).
> - Register `cloud_transit`, `juniper_traffic`, `checkpoint_traffic`, and `nsx_dfw_traffic` in `SupplementalSource` (`evidence.ts`), `evidenceConfig.ts` (`ObserverMapping` + REST `fields` projection at line 267), `splunk_app/splunk_adm/default/collections.conf` (`[adm_observer_scope]`: add `field.subscription_id`, `field.gcp_project_id`, `field.transit_resource_id`), `splunk_app/splunk_adm/default/transforms.conf` (`[adm_observer_scope]` `fields_list`), `splunk_app/splunk_adm/default/savedsearches.conf` (migration `lookup ... OUTPUT` list), `splunk_app/splunk_adm/bin/adm_observer_lib/rest.py` (`OPTIONAL_FIELDS` allowlist), and `config/deployment-health.json` (plus a parity unit test verifying all observer-scope field lists stay in sync).

### Batch 2A — 4 Concurrent Workers

#### Task 2A.1 (`protocol-worker`): Features #9 & #5b — New `optics_hardware` Protocol Lens (SC4SNMP DOM/Chassis + Arista `1918` DOM/Table Scale + Meraki)
- **Allowed writes:** `frontend/src/protocols/lenses/optics_hardware/` (flat files), `fixtures/protocols/optics_hardware/` (including `FIELDS.md`), `docs/operators/protocol-optics-hardware.md`
- **Consumes:** `metricsRunner.ts` (SC4SNMP `ENTITY-SENSOR-MIB` / `CISCO-ENTITY-SENSOR-MIB` / `CISCO-ENVMON-MIB` / `HOST-RESOURCES-MIB` via `netmetrics`) + Arista Telemetry TA (`1918`) optical light levels, power, and hardware table status + Meraki `meraki:portstransceiversreadingshistorybyswitch`, `meraki:powermodulesstatusesbydevice`, `meraki:wirelessdevicespacketlossbydevice` + Catalyst `cisco:dnac:devicehealth` / `cisco:dnac:issue`.
- **Produces:**
  - `validate.ts`, `adapter.ts`, `OpticsHardwareLensPage.tsx`, `index.ts` (Overview sorting degrading Rx/Tx dBm optics, PSU failures, and CPU/memory/TCAM alerts first; `Device × Transceiver/Subsystem` Matrix; Detail Drawer with raw dBm/scale exponent, PSU redundancy impact cue, and `Not covered` when threshold MIBs are absent — Review Focus #4).
- **Acceptance checks:**
  - [ ] Scoped lint & unit tests verify `entSensorScale` exponent conversion, Arista `1918` optical/table-scale parsing, honest `Not covered` threshold display, and `docs/operators/protocol-optics-hardware.md` documents SC4SNMP Smart Profiles, Arista `1918`, and Meraki DOM inputs.

#### Task 2A.2 (`protocol-worker`): Feature #12a — New `network_access` Protocol Lens (802.1X / MAB / RADIUS / NAC)
- **Allowed writes:** `frontend/src/protocols/lenses/network_access/` (flat files), `fixtures/protocols/network_access/` (including `FIELDS.md`), `docs/operators/protocol-network-access.md`
- **Grounding:** SC4S `cisco:ise:syslog` (built-in multi-line aggregation) and `research/extracted/cisco-enterprise-networking-add-on-for-splunk_4060/TA_cisco_catalyst/default/props.conf` & `transforms.conf` (`cisco:ise:syslog`, `cisco:ise:monitoring`, `cisco:ise:pxgrid`, `cisco:ise:endpoint_context`, `cisco:ise:sgtbindings`).
- **Produces:**
  - `validate.ts`, `adapter.ts`, `NetworkAccessLensPage.tsx`, `index.ts` (Overview aggregating 802.1X/MAB/EAP/cert failures by NAS switch, port, and `FailureReason`; `Switch × Failure Reason / Auth Profile` Matrix; Detail Drawer with explicit opt-in single-row expansion ONLY for actual TA-extracted identity fields `user`, `user_name`, `src_user_name`, `x_user`, `UserName`, `User_Name`, `OriginalUserName`, and `src_mac` — Review Focus #3).
- **Acceptance checks:**
  - [ ] Static SPL & runtime tests using real ISE event fixtures prove `user`, `user_name`, `src_user_name`, `x_user`, `UserName`, `User_Name`, `OriginalUserName`, and `src_mac` NEVER appear in Overview/Matrix SPL or table cells.
  - [ ] `docs/operators/protocol-network-access.md` documents SC4S `netauth` ISE aggregation and privacy boundaries.

#### Task 2A.3 (`protocol-worker`): Features #10a & #11c — Upgrade `routing` Lens (SC4SNMP BGP/OSPF MIBs & Traps + SC4S Multi-Vendor + sFlow BGP Context)
- **Allowed writes:** `frontend/src/protocols/lenses/routing/` (flat files), `fixtures/protocols/routing/`, `docs/operators/protocol-routing.md`
- **Consumes:** `metricsRunner.ts` (`sc4snmp.BGP4-MIB.bgpPeerState`, `sc4snmp.OSPF-MIB.ospfNbrState`) + `multiVendorSyslog.ts` (Arista/Juniper/PAN/FortiGate) + `sc4snmp:traps` (`bgpBackwardTransition`, `ospfNbrStateChange`) + `stream:sflow` AS-path context.
- **Acceptance checks:**
  - [ ] Multi-vendor BGP/OSPF/BFD peers render cleanly in Overview, `AdjacencyOverlay`, and `HeatMatrix`; SNMP-polled vs trap-driven vs syslog-only rows honestly mark missing prefix counts as `Not covered`.
  - [ ] `docs/operators/protocol-routing.md` adds SC4SNMP BGP/OSPF profile, trap `securityEngineId`, and multi-vendor SC4S sections.

#### Task 2A.4 (`protocol-worker`): Features #10b & #12b — Upgrade `l2_control` Lens (SC4SNMP LLDP/BRIDGE-MIB + SC4S Arista/Juniper + Infoblox `7473` DHCP)
- **Allowed writes:** `frontend/src/protocols/lenses/l2_control/` (flat files), `fixtures/protocols/l2_control/`, `docs/operators/protocol-l2-control.md`
- **Consumes:** `metricsRunner.ts` (`LLDP-MIB`, `BRIDGE-MIB`, `Q-BRIDGE-MIB`), `multiVendorSyslog.ts` (Arista MLAG/STP/LACP, Juniper `l2ald`), and Infoblox TA (`7473` v2.0.0) + SC4S `infoblox:dhcp` (DHCP pool exhaustion `no free leases`, failover peer sync).
- **Acceptance checks:**
  - [ ] Adds TAP-free Infoblox DHCP health to `l2_control` alongside `stream:dhcp`, plus vendor-neutral STP/LLDP coverage; updates `docs/operators/protocol-l2-control.md`.

---

### Batch 2B — 4 Concurrent Workers (Launched after Batch 2A Completes)

#### Task 2B.1 (`protocol-worker`): Features #12c, #7a & #16a — Upgrade `dns_ops` Lens (Infoblox `7473` DNS + Route 53 Resolver + OTel `dns_check` Synthetic Probes)
- **Allowed writes:** `frontend/src/protocols/lenses/dns_ops/` (flat files), `fixtures/protocols/dns_ops/`, `docs/operators/protocol-dns-ops.md`
- **Consumes:** `metricsRunner.ts` (OTel `dns_check` metrics), Infoblox TA (`7473`) + SC4S `infoblox:dns`, AWS `aws:route53:resolver`.
- **Acceptance checks:**
  - [ ] Synthetic `dns_check` rows carry an explicit **Synthetic Probe** badge and never mix with passive `stream:dns`/`infoblox:dns` query counts; updates `docs/operators/protocol-dns-ops.md`.

#### Task 2B.2 (`protocol-worker`): Feature #16b — Upgrade `tcp_tls` Lens (OTel `tls_check` & `tcp_check` Active Synthetic Probes)
- **Allowed writes:** `frontend/src/protocols/lenses/tcp_tls/` (flat files), `fixtures/protocols/tcp_tls/`, `docs/operators/protocol-tcp-tls.md`
- **Consumes:** `metricsRunner.ts` (`tls_check` certificate expiry/protocol/cipher + `tcp_check` SYN connect latency).
- **Acceptance checks:**
  - [ ] Enables TAP-free proactive TLS certificate expiration & TCP reachability monitoring across enclaves while keeping passive `stream:tcp` and **Synthetic Probe** rows strictly separated (Review Focus #4); updates `docs/operators/protocol-tcp-tls.md`.

#### Task 2B.3 (`protocol-worker`): Feature #16c — Upgrade `qos_icmp` Lens (OTel `icmp_check` Sub-ms RTT/Loss & OpenConfig QoS Queue Drops)
- **Allowed writes:** `frontend/src/protocols/lenses/qos_icmp/` (flat files), `fixtures/protocols/qos_icmp/`, `docs/operators/protocol-qos-icmp.md`
- **Consumes:** `metricsRunner.ts` (`icmp_check` double-precision RTT & packet loss + `openconfig.qos.interfaces.*.queues.*`).
- **Acceptance checks:**
  - [ ] Surfaces gateway/next-hop sub-ms ICMP RTT & loss probes (badged **Synthetic Probe**) and hardware QoS tail-drop metrics alongside NetFlow DSCP and `stream:icmp`; updates `docs/operators/protocol-qos-icmp.md`.

#### Task 2B.4 (`ecosystem-worker`): Feature #7 — Hybrid Cloud Transit Backbone Evidence (AWS `1876`, Azure `3110`, GCP `3088`)
- **Allowed writes:** `frontend/src/ecosystem/cloudTransit/`, `fixtures/cloud-transit/` (including `FIELDS.md`), `tests/splunk/test_cloud_transit.py`, `docs/operators/cloud-transit-evidence.md`
- **Grounding:** Splunk TA for AWS (`1876`), MSCS (`3110`), GCP (`3088`) transit metrics/logs; `docs/ECOSYSTEM_TRAFFIC_EVIDENCE_DESIGN.md`; `adm_observer_scope` (`account_id`, `subscription_id`, `gcp_project_id`, `region`, `transit_resource_id`).
- **Produces:**
  - Bounded transit evidence adapter & supplemental panel correlating DX/ExpressRoute/Cloud Router BGP status, TGW blackhole drops, and NAT Gateway port exhaustion.
- **Acceptance checks:**
  - [ ] Scoped lint, unit tests, `tests/splunk/test_cloud_transit.py`, and `docs/operators/cloud-transit-evidence.md` pass.

---

### Batch 2C — 3 Concurrent Workers (Multi-Vendor Flow & WAN TAs — Launched after Batch 2B Completes)

#### Task 2C.1 (`ecosystem-worker`): Feature #19a — Multi-Vendor Firewall & Virtual-Fabric Flow TAs (Juniper `2847`, Check Point `5402`, VMware NSX `6805`, Palo Alto `7523` v4.0, Fortinet `2846` v1.6.10)
- **Allowed writes:** `frontend/src/ecosystem/multiVendorFlows/`, `fixtures/multi-vendor-flows/` (including `FIELDS.md`), `tests/splunk/test_multi_vendor_flows.py`, `docs/operators/multi-vendor-flow-tas.md`
- **Grounding:** Task 0.5 static extractions for `Splunk Add-on for Juniper` (`2847` v1.7.0 — `juniper:junos:firewall`, `juniper:junos:firewall:structured`, `netscreen:firewall`), `CCX Unified Splunk Add-on for Checkpoint` (`5402` v2.1.3), `VMware NSX add-on` (`6805` v1.0.5 — DFW allow/deny flows), `Splunk Add-on for Palo Alto Networks` (`7523` v4.0.0 CIM alignment alongside legacy `2757`), and `Fortinet FortiGate Add-On` (`2846` v1.6.10).
- **Produces:**
  - Bounded traffic-evidence adapters & receipt checks following `docs/ECOSYSTEM_TRAFFIC_EVIDENCE_DESIGN.md`: single-device allow/deny verdict + same-event NAT translation (never creating dependency edges or summing across sensors — Review Focus #2) for `juniper_traffic`, `checkpoint_traffic`, `nsx_dfw_traffic`, plus PAN-OS `7523` v4.0 compatibility helper.
- **Acceptance checks:**
  - [ ] Scoped lint, unit tests, `tests/splunk/test_multi_vendor_flows.py`, and `docs/operators/multi-vendor-flow-tas.md` pass; handoff checks `ecosystem.js` gzip headroom (`<= 48 KiB` — if `cloudTransit` + `multiVendorFlows` approaches `44 KiB`, handoff recommends splitting into a dedicated optional bundle rather than breaching `MAX_ECOSYSTEM_GZIP_BYTES`).

#### Task 2C.2 (`protocol-worker`): Feature #19b — Upgrade `drops` Lens with Multi-Vendor Flow TAs (Juniper SRX `2847`, Check Point `5402`, VMware NSX DFW `6805`, PAN `7523` v4.0)
- **Allowed writes:** `frontend/src/protocols/lenses/drops/` (flat files), `fixtures/protocols/drops/`, `docs/operators/protocol-drops.md`
- **Grounding:** Same official vendor TA sourcetypes as Task 2C.1 (`juniper:junos:firewall`, `juniper:junos:firewall:structured`, `netscreen:firewall`, Check Point drop logs, VMware NSX DFW drops, PAN `7523` v4.0).
- **Acceptance checks:**
  - [ ] Preserves each vendor's native enforcer label (`Juniper SRX`, `Check Point`, `VMware NSX DFW`, `PAN-OS`, `FortiGate`, `FTD`, `Hubble`, `ND`, `ACI`) and native policy/rule/zone/drop-reason without conflating semantics; updates `docs/operators/protocol-drops.md`.

#### Task 2C.3 (`protocol-worker`): Feature #2b — Upgrade `wan_tunnels` Lens with HPE Aruba EdgeConnect SD-WAN (`6302`) & Aruba (`4668`) Multi-Vendor WAN/Branch TAs
- **Allowed writes:** `frontend/src/protocols/lenses/wan_tunnels/` (flat files), `fixtures/protocols/wan_tunnels/`, `docs/operators/protocol-wan-tunnels.md`
- **Grounding:** Task 0.5 static inspection of `HPE Aruba Networking EdgeConnect SD-WAN` (`6302` v1.1.2) and `Aruba Networks Add-on` (`4668` v1.1.2).
- **Acceptance checks:**
  - [ ] Adds `sourceKind: "aruba_edgeconnect"` alongside Catalyst SD-WAN, Meraki MX, PAN/FortiGate; preserves strict vendor authority boundaries; updates `docs/operators/protocol-wan-tunnels.md`.

---

### Batch 2D — 4 Concurrent Workers (Remote Access/SASE, Wireless RF, IPv6 NDP & NAT/Session Saturation — Launched after Batch 2C Completes)

#### Task 2D.1 (`protocol-worker`): New `remote_sase` Protocol Lens (Cisco Secure Access `7569`, Zscaler `3865`/`3866`, Cisco ASA `1620`, PAN GlobalProtect `7523`, Cisco NVM)
- **Allowed writes:** `frontend/src/protocols/lenses/remote_sase/` (flat files), `fixtures/protocols/remote_sase/` (including `FIELDS.md`), `docs/operators/protocol-remote-sase.md`
- **Produces:** `validate.ts`, `adapter.ts`, `RemoteSaseLensPage.tsx`, `index.ts` — troubleshoots remote/hybrid user connectivity (SASE/Zero-Trust policy blocks, VPN gateway latency/drops, split-tunnel issues, NVM process-to-flow attribution) with strict lowercase per-lens row-expansion privacy for user identifiers (never in Overview/Matrix).

#### Task 2D.2 (`protocol-worker`): New `wireless_rf` Protocol Lens (Catalyst 9800 WLC, Catalyst Center `7538` v4.0.70, Meraki `5580`, HPE Aruba `4668`)
- **Allowed writes:** `frontend/src/protocols/lenses/wireless_rf/` (flat files), `fixtures/protocols/wireless_rf/` (including `FIELDS.md`), `docs/operators/protocol-wireless-rf.md`
- **Produces:** `validate.ts`, `adapter.ts`, `WirelessRfLensPage.tsx`, `index.ts` — troubleshoots co-channel interference, channel utilization, DFS radar switches, 802.11r/4-way handshake roaming failures, sticky clients, and AP disconnects.

#### Task 2D.3 (`protocol-worker`): IPv6 NDP, RA-Guard & Dual-Stack Mobility Upgrade in `endpoint_mobility` (plus Windows DHCP/DHCPv6 in `l2_control` & Windows DNS in `dns_ops` & IPv6 Happy Eyeballs in `tcp_tls`)
- **Allowed writes:** `frontend/src/protocols/lenses/endpoint_mobility/` (flat files), `fixtures/protocols/endpoint_mobility/`, `docs/operators/protocol-endpoint-mobility.md`
- **Produces:** Adds IPv6 Neighbor Discovery (`NDP`), RA Guard violations, ICMPv6 NS/NA spikes, and SC4SNMP `IP-MIB.ipNetToPhysicalTable` alongside ARP mobility/conflict detection. *(Companion Batch 2A/2B tasks fold Windows DHCP `742` + DHCPv6 into `l2_control`, Windows DNS `742` into `dns_ops`, IPv6 Happy Eyeballs `AAAA`/IPv6 SYN fallback into `tcp_tls`, and Cloudflare/MCD WAF blocks into `drops`.)*

#### Task 2D.4 (`ecosystem-worker`): NAT / CGNAT Port Exhaustion & Firewall Session-Table Saturation
- **Allowed writes:** `frontend/src/ecosystem/natSaturation/`, `fixtures/nat-saturation/` (including `FIELDS.md`), `tests/splunk/test_nat_saturation.py`, `docs/operators/nat-session-exhaustion.md`
- **Produces:** Correlates NAT/SNAT port exhaustion and firewall connection-table saturation across Cisco ASA (`1620`)/FTD, PAN-OS (`7523`), FortiGate (`2846`), F5 BIG-IP (`2680`), AWS NAT Gateway (`1876` `ErrorPortAllocation`), and SC4SNMP session-table MIBs (`netmetrics` `| mstats`).

---

### Wave 2 Integration, Documentation & Review Gate (Orchestrator)

- [ ] **Step 1:** Wire `optics_hardware` and `network_access` into `registry.ts`, `drillIn.ts`, `tools/protocol-lenses.mjs`, and `tools/check_release.py` (→ 17 lenses); wire `sc4snmp:traps` (`linkDown`/`linkUp`/`topologyChange`/`bgpBackwardTransition`, using existing `adm_index_snmp`) into `state_events`, `LLDP-MIB` into vendor-neutral Path Trace topology, PSU redundancy loss from `optics_hardware` into `impact/`, and `cloudTransit` + `multiVendorFlows` into `frontend/src/ecosystem/` (verifying `ecosystem.js <= 48 KiB` gzip or splitting a sibling optional bundle if needed); update `ProtocolsPage.test.tsx`, `tests/browser/protocols-harness.tsx`, and `tests/browser/protocols.spec.ts`.
- [ ] **Step 2 (Documentation Lockstep):**
  - Create dedicated `docs/operators/sc4s-sc4snmp-guide.md` covering SC4S multi-vendor/ISE/Infoblox setup, SC4SNMP `netmetrics` + `netops` (`adm_index_snmp`) traps + SNMPv3 `securityEngineId`, and Smart Profiles.
  - Update `README.md`, `docs/operators/README.md`, `docs/operators/official-splunkbase-tas.md` (complete official multi-vendor TA install/search-time guide covering Juniper `2847`, PAN `7523`/`2757`, Fortinet `2846`, Check Point `5402`, VMware NSX `6805`, Aruba `4668`/`6302`, Infoblox `7473`), `docs/operators/ecosystem-tas.md`, `docs/ECOSYSTEM_TRAFFIC_EVIDENCE_DESIGN.md`, `docs/SUPPLEMENTAL_EVIDENCE_CONTRACT.md`, `docs/DATA_LAYER.md`, `docs/operators/SUPPORT_MATRIX.md`, and `fixtures/raw/FIELDS.md`.
- [ ] **Step 3:** Run full lint, Vitest, `npm run package`, `python3 tools/check_release.py --dist dist`, Ruff, `tests/test_release.py`, Splunk lab:
  ```sh
  tests/splunk/lab.sh up && tests/splunk/lab.sh install
  ADM_LAB=1 python3 tools/lab_lock.py --root . -- sh -c '
    python3 -m unittest discover -s tests/splunk -p "test_protocol_lenses.py" &&
    python3 -m unittest discover -s tests/splunk -p "test_cloud_transit.py" &&
    python3 -m unittest discover -s tests/splunk -p "test_multi_vendor_flows.py"
  '
  tests/splunk/lab.sh purge
  ```
  (including real `| mstats` execution against the lab's `netmetrics` index!), and capture Playwright light/dark screenshots (`1440×900` & `1280×800`).
- [ ] **Step 4:** Dispatch read-only `code-reviewer` and `ux-reviewer`; remediate findings; rerun affected checks.
- [ ] **Step 5 (Human Checkpoint):** Present Wave 2 evidence and await human confirmation before Wave 3.

---

## Wave 3 — Strategic Next-Gen Splunk OTel Collector Telemetry (MDT EVPN, gNMI, `cisco_os`, PTP/NTP, eBPF OBI)

> **Concurrency:** Batch 3A (4 workers) → Batch 3B (4 workers) + 1 brief follow-up (`Task 3B.5`) — strictly `<= 4` concurrent threads, 1 lens per `protocol-worker`, zero write collisions.
> **Wave 3 Pre-Batch Orchestrator Prep (before dispatching Batch 3A):** Register `evpn_overlay` in `evidence.ts`, `contract.ts`, `fields.ts`, and `config/deployment-health.json` (`protocol_evpn_overlay`); expand `mgmt_plane`, `interface_health`, `optics_hardware`, `routing`, `state_events`, `dns_ops` allowlists for `ptp`/`ntp`/`chrony`, `cisco_os`, `gnmi` DOM/BGP, `k8s_events`, and Prometheus FRR/CoreDNS metrics.

### Batch 3A — 4 Concurrent Workers (New OTel Lens + Core Adapters)

#### Task 3A.1 (`protocol-worker`): Feature #13 — New `evpn_overlay` Protocol Lens (Cisco Streaming MDT via OTel `yang_grpc` + OpenConfig EVPN)
- **Allowed writes:** `frontend/src/protocols/lenses/evpn_overlay/` (flat files), `fixtures/protocols/evpn_overlay/` (including `FIELDS.md`), `docs/operators/protocol-evpn-overlay.md`
- **Consumes:** `metricsRunner.ts` (`Cisco-IOS-XE-nve-oper`, `evpn-oper`, `bgp-oper`, `Cisco-NX-OS-device` NVE/BGP/VNI metrics via `| mstats`).
- **Produces:**
  - `validate.ts`, `adapter.ts`, `EvpnOverlayLensPage.tsx`, `index.ts` (Overview of NVE tunnel peers, VNI/VRF state, BGP EVPN route scale & hold-time anomalies; `VTEP × VNI/Peer` `HeatMatrix` + `AdjacencyOverlay`; Detail Drawer with explicit alpha receiver notice and literal Splunk `mstats` drilldown link).
- **Acceptance checks:**
  - [ ] Scoped lint & unit tests cover NVE peer down, EVPN route scale surge, VNI-to-VRF mismatch, and `Not covered` when `yang_grpc` metrics absent.
  - [ ] `docs/operators/protocol-evpn-overlay.md` includes a hardened `splunk-otel-collector` `yang_grpc` YAML config (`allowed_clients`, `rate_limiting`, TLS, `splunk_hec` metrics index).

#### Task 3A.2 (`ecosystem-worker`): Feature #14 — Graduate & Expand OTel `gnmi` Pilot (`gnmiContext.ts` → Multi-Vendor OpenConfig Streaming)
- **Allowed writes:** `frontend/src/trace/gnmi/`, `frontend/src/trace/gnmiContext.ts`, `frontend/src/trace/gnmiContext.test.ts`, `fixtures/otel-gnmi/` (including `FIELDS.md`), `tests/splunk/test_otel_gnmi.py`, `docs/operators/otel-streaming-telemetry.md`
- **Grounding:** Existing `frontend/src/trace/gnmiContext.ts` + `splunk-otel-collector` `v0.163.1+` `gnmi` receiver (`yang_modules` auto-typing + `gnmireverse` router dial-out).
- **Produces:**
  - Graduated OpenConfig streaming adapter supporting `/interfaces/interface/state/counters`, `/network-instances/.../bgp`, `/components/component/transceiver` (DOM), and `/qos/interfaces/.../queues` via `| mstats`, preserving fail-closed ambiguity/staleness guards (`maxSampleAge`, TLS required in prod).
- **Acceptance checks:**
  - [ ] Existing `gnmiContext.test.ts` cases stay green + new tests verify `gnmireverse` multi-vendor Arista/Juniper/Nokia/SONiC/Cisco samples, DOM/BGP/QoS extraction, and `tests/splunk/test_otel_gnmi.py`.
  - [ ] `docs/operators/otel-streaming-telemetry.md` documents both `gnmi` (`yang_modules` + `gnmireverse`) and `yang_grpc` MDT collector deployments, maturity labels, and TLS hardening.

#### Task 3A.3 (`protocol-worker`): Feature #17 — Precision Timing (`ptp`, `ntp`, `chrony`) Hygiene & Clock-Skew Assurance in `mgmt_plane`
- **Allowed writes:** `frontend/src/protocols/lenses/mgmt_plane/` (flat files), `fixtures/protocols/mgmt_plane/`, `docs/operators/protocol-mgmt-plane.md`
- **Consumes:** `metricsRunner.ts` (OTel `ptp`, `ntp`, `chrony` metrics from `splunk-otel-collector` `v0.163.1+`).
- **Produces:**
  - Extends `mgmt_plane` with `sourceKind: "clock_sync"` (alongside `auto`): tracks PTP grandmaster lock/failover, nanosecond offset & path delay, NTP/chrony stratum & drift, and flags hosts whose offset threatens Atlas's 1-second `adm_handoff_window`.
  - Handoff includes a compact `ClockSkewSummary` helper contract for Orchestrator to surface in `Admin -> Data Health`.
- **Acceptance checks:**
  - [ ] Scoped lint & unit tests cover PTP grandmaster unlock, chrony drift exceeding `clockSkewWarnMs`, experimental `ptp` badge, and clean separation from "device down"; updates `docs/operators/protocol-mgmt-plane.md`.

#### Task 3A.4 (`ecosystem-worker`): Features #15 & #18 — Agentless OTel `cisco_os` Metrics Adapter + CNI-Agnostic K8s eBPF (`OBI`), `k8s_events` & Prometheus Network Exporters
- **Allowed writes:** `frontend/src/data/otelNetworkAdapters/`, `fixtures/otel-network/` (including `FIELDS.md`), `tests/splunk/test_otel_network.py`, `docs/operators/otel-network-collectors.md`
- **Grounding:** `splunk-otel-collector` `v0.164+` `cisco_os` receiver (SSH key-file scraping), `OBI` Helm subchart (`opentelemetry-ebpf-instrumentation`), `k8s_events`, and `prometheus` scraping of FRR/BIRD/MetalLB/CoreDNS/Envoy.
- **Produces:**
  - `ciscoOsAdapter.ts` (maps OTel `cisco.device.up`, `system.cpu/memory.utilization`, `system.network.*` into normalized interface/device rows)
  - `obiFlowAdapter.ts` (normalizes OBI eBPF spans/metrics for non-Cilium K8s clusters while preventing double-counting when Hubble is also active — Review Focus #2)
  - `k8sNetEventsAdapter.ts` (normalizes `NetworkNotReady`, CNI IPAM, DNS `k8s_events`, plus FRR/MetalLB BGP & CoreDNS Prometheus metrics)
- **Acceptance checks:**
  - [ ] Scoped lint, unit tests, and `tests/splunk/test_otel_network.py` verify deduplication boundaries between OBI and Hubble, zero plaintext SSH password handling, and Prometheus metric cardinality limits.
  - [ ] `docs/operators/otel-network-collectors.md` provides copy-pasteable Helm/collector configs for `cisco_os` (key-file auth), `OBI` subchart (alpha/kernel-capability review checklist), `k8s_events`, and FRR/CoreDNS/Envoy scrape configs.

---

### Batch 3B — Wiring Batch 3A OTel Adapters into Existing Lenses (4 Concurrent `protocol-worker`s + 1 Follow-Up)

**Pre-Batch 3B Orchestrator Prep (Cache-Invalidation Guarantee — Review Focus #5):**
Update `vite.protocols-core.shared.ts` (`protocolsCoreAssetVersion()`) to include any shared OTel adapter paths (`frontend/src/data/otelNetworkAdapters/`, `frontend/src/trace/gnmi/`) exposed through `PROTOCOLS_CORE_SDK_MODULES` (verifying `protocols-core.js <= 64 KiB` gzip), OR include their exact source paths in `protocolLensAssetVersion()` in `tools/protocol-lenses.mjs` so editing an adapter ALWAYS updates the served bundle version hash and prevents stale browser caches!

- [ ] **Task 3B.1 (`protocol-worker` — `interface_health`):** Wire OTel `gnmi` interface counters + OTel `cisco_os` SSH-scraped interface metrics into `frontend/src/protocols/lenses/interface_health/` + `docs/operators/protocol-interface-health.md`.
- [ ] **Task 3B.2 (`protocol-worker` — `optics_hardware`):** Wire OTel `gnmi` `/components/component/transceiver` optical DOM metrics into `frontend/src/protocols/lenses/optics_hardware/` + `docs/operators/protocol-optics-hardware.md`.
- [ ] **Task 3B.3 (`protocol-worker` — `routing`):** Wire OTel `gnmi` BGP neighbor state + Prometheus FRR/BIRD/MetalLB BGP peer metrics into `frontend/src/protocols/lenses/routing/` + `docs/operators/protocol-routing.md`.
- [ ] **Task 3B.4 (`protocol-worker` — `state_events`):** Wire `k8s_events` (`NetworkNotReady` / CNI IPAM) into `frontend/src/protocols/lenses/state_events/` + `docs/operators/protocol-state-events.md`.
- [ ] **Task 3B.5 (`protocol-worker` — `dns_ops`, run right after 3B.1–3B.4):** Wire CoreDNS Prometheus metrics into `frontend/src/protocols/lenses/dns_ops/` + `docs/operators/protocol-dns-ops.md` (keeping strictly 1 lens per worker).

---

### Wave 3 Integration, Documentation & Review Gate (Orchestrator)

- [ ] **Step 1:** Wire `evpn_overlay` into `registry.ts`, `drillIn.ts`, `tools/protocol-lenses.mjs`, and `tools/check_release.py` (→ 18 lenses); wire `ClockSkewSummary` into `frontend/src/admin/` (`Admin -> Data Health`, keeping `admin.js <= 48 KiB` gzip); wire `obiFlowAdapter` into K8s service-call correlation behind an explicit opt-in toggle; update `ProtocolsPage.test.tsx`, `tests/browser/protocols-harness.tsx`, and `tests/browser/protocols.spec.ts`.
- [ ] **Step 2 (Documentation Lockstep):** Update `docs/operators/kubernetes-platform.md` (add `OBI` opt-in, `k8s_events`, Prometheus FRR/CoreDNS scraping), `docs/operators/ingest-processors.md` (add Splunk Edge Processor & SC4S pre-filtering pipeline guidance for high-volume network telemetry), `docs/DEPLOYMENT_HEALTH.md` (clock-skew & alpha receiver health checks), `docs/DATA_LAYER.md`, `docs/SECURITY.md` (SSH key-file auth, `yang_grpc` CIDR/rate limiting, gNMI TLS, OBI kernel eBPF security boundary), and `docs/UPGRADES.md`.
- [ ] **Step 3:** Run full lint, Vitest, `npm run package`, `python3 tools/check_release.py --dist dist`, Ruff, `tests/test_release.py`, Splunk lab:
  ```sh
  tests/splunk/lab.sh up && tests/splunk/lab.sh install
  ADM_LAB=1 python3 tools/lab_lock.py --root . -- sh -c '
    python3 -m unittest discover -s tests/splunk -p "test_protocol_lenses.py" &&
    python3 -m unittest discover -s tests/splunk -p "test_otel_gnmi.py" &&
    python3 -m unittest discover -s tests/splunk -p "test_otel_network.py"
  '
  tests/splunk/lab.sh purge
  ```
  and capture Playwright light/dark screenshots (`1440×900` & `1280×800`).
- [ ] **Step 4:** Dispatch read-only `code-reviewer` and `ux-reviewer`; remediate findings; rerun affected checks.
- [ ] **Step 5 (Human Checkpoint):** Present Wave 3 evidence and await human confirmation before Wave 4.

---

## Wave 4 — Documentation Consolidation, Qualification Evidence & Final Whole-Branch Release Gate

**Owner:** Orchestrator + Parallel Read-Only Reviewers (`code-reviewer` + `ux-reviewer`).

### Task 4.1: Complete Cross-Cutting Documentation Update Matrix

Every document below must be updated and verified against the implemented code so no operator guide, matrix, demo script, packaged doc, or validation ledger lags behind the 19 new capabilities:

- [ ] `README.md` — Update "What you can do" (18 protocol lenses, multi-vendor flow TAs [Arista `1918`, Juniper `2847`, PAN `7523`, Fortinet `2846`, Check Point `5402`, VMware NSX `6805`, NetScaler `2770`, Aruba `4668`/`6302`, Infoblox `7473`], SC4S/SC4SNMP/sFlow, Intersight observed FI hop, streaming MDT/gNMI/EVPN, synthetic probes, OBI eBPF), update Data Sources table (replace Intersight "Not consumed yet"; add multi-vendor TAs, SC4SNMP `netmetrics`/traps, sFlow, SC4S multi-vendor/ISE/Infoblox, OTel `yang_grpc`/`gnmi`/`cisco_os`/probes/`ptp`/`OBI`), refresh README screenshots for new lenses.
- [ ] `docs/operators/README.md` — Update Data-Source Matrix, Team Handouts (link `sc4s-sc4snmp-guide.md`, `multi-vendor-flow-tas.md`, `otel-streaming-telemetry.md`, `otel-network-collectors.md`, `intersight-evidence.md`, `sflow-evidence.md`, `fmc-policy-evidence.md`, `cloud-transit-evidence.md`), Source-Scope Profile Registration (`sflow_switch`, `vmware_nsx_ipfix`), Minimum Data Checklist, and the 18-lens Protocol Workbenches table.
- [ ] `docs/operators/official-splunkbase-tas.md` & `docs/operators/ecosystem-tas.md` — Complete official unmodified Splunkbase TA matrix (Splunkbase ID, Splunk 10.6 version, HF vs search-head placement, SC4S pairing, fail-closed macro & schema flag) across Cisco + all non-Cisco network vendors.
- [ ] `docs/operators/SUPPORT_MATRIX.md`, `docs/FEATURE_QUALIFICATION.json` & `docs/FEATURE_DELIVERY.md` — Record honest qualification status for every new feature (synthetic lab-qualified vs live-verified vs alpha/experimental opt-in), keeping `FEATURE_QUALIFICATION.json` and `FEATURE_DELIVERY.md` strictly paired.
- [ ] `docs/DATA_LAYER.md` — Document the new `| mstats` Splunk Metrics layer (`metricsRunner.ts`, `netmetrics`, `network_metrics`, `adm_ifmib_capacity`, counter-reset handling, dual-shape summary/trend queries, `p_wmode=metrics` URL persistence), all new fail-closed index macros, and `sflow_switch` / `vmware_nsx_ipfix` / Intersight / OBI identity boundaries.
- [ ] `docs/SUPPLEMENTAL_EVIDENCE_CONTRACT.md` & `docs/ECOSYSTEM_TRAFFIC_EVIDENCE_DESIGN.md` — Add `cloud_transit`, `fmc_policy`, `juniper_traffic`, `checkpoint_traffic`, `nsx_dfw_traffic`, `netscaler`, `haproxy`, PAN `7523` v4.0 compatibility, and synthetic probe separation contracts.
- [ ] `docs/operators/splunk-setup-guide.md`, `docs/operators/deployment-options.md`, `docs/operators/troubleshooting.md`, `docs/UPGRADES.md` — Add step-by-step Splunk **Metrics** index creation (`indexes.conf` `datatype = metric` / Splunk Cloud ACS metrics index), multi-vendor TA search-head vs HF placement, macro enablement, and troubleshooting for `mstats` empty/capped/stale states.
- [ ] `docs/DEPLOYMENT_HEALTH.md` & `docs/SECURITY.md` — Document Data Health receipt checks for metrics/traps/clock skew/multi-vendor TAs and security boundaries for ISE NAC row expansion, OTel `cisco_os` SSH keys, `yang_grpc` CIDR/rate limits, gNMI TLS, and OBI eBPF.
- [ ] `docs/BROWSER_PERFORMANCE.md` — Record measured gzip bundle sizes for all 18 `protocol-<id>.js` assets, `protocols-core.js`, `ecosystem.js`, `segmentation.js`, `admin.js`, and `atlas.js` against `tools/check_release.py` ceilings.
- [ ] `tools/package-app.mjs` & `tests/test_release.py` — Verify any newly required packaged contract docs are staged consistently and pass `python3 tools/check_release.py --dist dist` without shipping internal evidence docs (`INTERNAL_EVIDENCE_DOCS`).
- [ ] `docs/validation/` (`ui-scenario-inventory.json`, `backend-contract-inventory.json`, `coverage-matrix.json`, `COVERAGE.md`, `COLLECTION_PREREQUISITES.md`) — Register all 5 new lenses, new SPL/`| mstats` contracts, and multi-vendor TA collection prerequisites.
- [ ] `fixtures/raw/FIELDS.md` + every new `fixtures/protocols/<lens>/FIELDS.md` + `docs/demos/NETWORKING_SE.md` & `docs/demos/SPLUNK_SE.md` — Sync field provenance references and update SE presenter scripts with multi-vendor TA, WAN/SD-WAN, optical DOM, NAC, and EVPN streaming storylines.

### Task 4.2: Automated Verification, Full Lab Run & Whole-Branch Read-Only Sign-Off

- [ ] **Step 1: Verify documentation integrity**
  Verify every markdown link across `README.md` and `docs/operators/*.md` resolves to an existing file, every lens registered in `frontend/src/protocols/registry.ts` has an existing `docs/operators/${lens.operatorDoc}` file (hyphenated, e.g. `protocol-wan-tunnels.md`) and `fixtures/protocols/${lens.id}/FIELDS.md`, every macro documented in `docs/DATA_LAYER.md` exists in `splunk_app/splunk_adm/default/macros.conf`, every vendor TA in `docs/operators/official-splunkbase-tas.md` is tracked in `research/package-manifest.json`, and every collection/transform has the exact `VIEWER_ACL` (or `ADMIN_ACL` per `ADMIN_ONLY_METADATA` in `tools/check_release.py`) in `splunk_app/splunk_adm/metadata/default.meta`.
- [ ] **Step 2: Run complete frontend, Python, release, browser, and Splunk lab validation**
  ```sh
  npm run lint
  npm test
  npm run test:browser
  npm run package
  python3 tools/check_release.py --dist dist
  ruff check tools tests && ruff format --check tools tests
  python3 -m unittest discover -s tests
  tests/splunk/lab.sh up && tests/splunk/lab.sh install
  ADM_LAB=1 python3 tools/lab_lock.py --root . -- python3 -m unittest discover -s tests/splunk
  tests/splunk/lab.sh purge
  ```
  Expected: 100% green across every suite, zero release-budget or metadata-ACL violations, and zero Cursor↔Codex agent-definition drift.
- [ ] **Step 3: Whole-branch independent read-only review**
  Dispatch fresh `code-reviewer` and `ux-reviewer` subagents over the complete integrated diff and full light/dark screenshot set (`1440×900` & `1280×800`). Remediate any verified findings and re-verify.
- [ ] **Step 4: Final Human Handoff**
  Deliver complete operational evidence summary (role/model assignments, changed paths, command outcomes, bundle budgets, review findings & remediation, and documentation coverage) and await explicit human authorization before any `git commit`, `git push`, or PR creation.
