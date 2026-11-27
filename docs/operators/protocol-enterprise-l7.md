# Operator Guide: Enterprise L7 (`enterprise_l7`)

**Status:** Staged

The **Enterprise L7** lens inspects enterprise file, directory, AAA, and VoIP protocol health across **SMB**, **NFS**, **LDAP**, **RADIUS**, and **SIP/RTP/RTCP** without projecting credentials, file contents, or raw packet payloads.

## 1. Supported Data Sources

| Protocol | Sourcetype(s) | Collector | Coverage |
| --- | --- | --- | --- |
| SMB | `stream:smb` | Splunk Stream (`Splunk_TA_stream` / `splunk_app_stream` 8.1.6+) | SMBv1 dialect detection (`dialect`), NT error rate (`nt_status`), latency (`response_time` / `time_taken` µs), bytes. |
| NFS | `stream:nfs` | Splunk Stream 8.1.6+ | Non-OK status rate (`status`), p95 latency (`time_taken` µs), NFS version (`version` -> `nfs_version`). |
| LDAP | `stream:ldap` | Splunk Stream 8.1.6+ | Cleartext non-SASL simple binds (`contains_sasl` -> `auth_type`, `message_type`, `dest_port`), response latency, optional extracted `result_code`. |
| RADIUS | `stream:radius` | Splunk Stream 8.1.6+ | Access-Reject spikes per NAS IP (`code`, `status`, `nas_ip` -> `nas_ip_address`), transaction latency. |
| VoIP (SIP/RTP/RTCP) | `stream:sip`, `stream:rtp`, `stream:rtcp` | Splunk Stream 8.1.6+ | SIP signaling errors/latency (`reply_code` -> `response_code`), RTP MOS (`mos_session` -> `mos`) and loss (`lost`), RTCP jitter (`rr_jitter`/`sr_jitter`) and fraction lost (`rr_fcnlost`/`sr_fcnlost`). |

## 2. Enabling Splunk Stream (`smb`, `nfs`, `ldap`, `radius`, `sip`, `rtp`, `rtcp`)

In Splunk App for Stream 8.1.6, `streams/smb`, `streams/nfs`, `streams/ldap`, `streams/radius`, `streams/sip`, `streams/rtp`, and `streams/rtcp` ship with `enabled: true` and `statsOnly: true` (**Estimate mode**). In Estimate mode, Stream writes volume estimates into `_internal` (`sourcetype="stream:stats"`) but does **not** index protocol event rows.

1. Confirm a capture interface (`sniffer.captures`) is attached to `streamfwd` on your tap/SPAN host or universal forwarder.
2. In Splunk App for Stream (**Configuration → Configure Streams**), switch each required stream (`smb`, `nfs`, `ldap`, `radius`, `sip`, `rtp`, `rtcp`) from **Estimate** (`statsOnly: true`) to **Enabled** (`statsOnly: false`) and assign the target index (for example `stream_l7`).
3. **Disable sensitive capture fields in Stream:** Do not enable or retain `login` (`smb`, `radius`), `content` (`nfs`), or `proxy_authorization` (`sip`) if your policy prohibits storing them in Splunk. Application Atlas enforces a strict privacy allowlist in SPL and client projection regardless.
4. Any protocol whose stream is not configured or not enabled renders explicitly as **Not covered** (hatched chip) in Overview and Matrix rather than green `OK` or `—`.

### On-Demand Estimate-Mode Check

Application Atlas never runs searches on page load. Only when an operator clicks **Investigate** and the configured streams return 0 rows, or clicks **Check Stream mode** in the banner, does Atlas inspect `index=_internal sourcetype="stream:stats"` for `smb`, `nfs`, `ldap`, `radius`, `sip`, `rtp`, and `rtcp` to report whether any stream is stuck in Estimate mode.

## 3. Privacy Allowlist & Row-Expansion Policy

- **Never collected or projected (`FORBIDDEN_SENSITIVE_FIELDS`):** `login`, `password`, `passwd`, `content`, `src_content`, `dest_content`, `cookie`, `form_data`, `uri_query`, `payload`, `authorization`, `_raw`. Blocked by `assertNoForbiddenFieldsInSpl`, `buildAllowedFieldsClause` (`| table ...`), and `projectRowToLensAllowlist`.
- **Restricted to single-row expansion (`ROW_EXPANSION_ONLY_FIELDS`):** `user_id` (`stream:smb`, `stream:sip`) and `calling_station_id` (`stream:radius`). These fields are **never** included in Overview SPL, Matrix SPL, Overview table columns, or Matrix cells. They are queried only when an operator opens a single SMB or RADIUS Detail Drawer and explicitly clicks **Load user_id** / **Load calling_station_id**.

## 4. Profile Configuration (`adm_protocol_profiles`)

Configure one or more profiles for `lens: "enterprise_l7"` under your scope:

```json
{
  "id": "enterprise-l7-dc1",
  "source": "protocol_enterprise_l7",
  "lens": "enterprise_l7",
  "scope": "prod:dc1",
  "index": "stream_l7",
  "observer": "stream-fwd-01",
  "validFrom": 1799990000,
  "validUntil": 1805000000,
  "extra": {
    "sourcetypes": ["stream:smb", "stream:nfs", "stream:ldap", "stream:radius", "stream:sip", "stream:rtp", "stream:rtcp"],
    "smbErrorWarnPct": 5,
    "nfsLatencyWarnMs": 50,
    "nfsErrorWarnPct": 2,
    "ldapErrorWarnPct": 5,
    "radiusRejectWarnCount": 5,
    "voipMosWarnMin": 3.5,
    "voipJitterWarnMs": 30,
    "voipLossWarnPct": 1
  }
}
```

### Validated `extra` Keys (Fail-Closed)

| Key | Type | Default | Allowed Range |
| --- | --- | --- | --- |
| `sourcetype` | single supported sourcetype | all 7 streams | Exact enum (mutually exclusive with `sourcetypes`) |
| `sourcetypes` | non-empty unique array | all 7 streams | Subset of the 7 `stream:*` sourcetypes above |
| `smbErrorWarnPct` | number (%) | `5` | `[0, 100]` |
| `nfsLatencyWarnMs` | number (ms) | `50` | `(0, 60000]` |
| `nfsErrorWarnPct` | number (%) | `2` | `[0, 100]` |
| `ldapErrorWarnPct` | number (%) | `5` | `[0, 100]` |
| `radiusRejectWarnCount` | integer (count / NAS) | `5` | `[1, 100000]` |
| `voipMosWarnMin` | number (MOS) | `3.5` | `[1, 5]` |
| `voipJitterWarnMs` | number (ms) | `30` | `(0, 5000]` |
| `voipLossWarnPct` | number (%) | `1` | `(0, 100]` |

Unknown keys or out-of-range values fail closed at profile validation time.

## 5. Verification Checklist

1. Confirm enabled Stream events are indexed without `login`/`content` projections:
   `index=<index> (sourcetype="stream:smb" OR sourcetype="stream:nfs" OR sourcetype="stream:ldap" OR sourcetype="stream:radius" OR sourcetype="stream:sip" OR sourcetype="stream:rtp" OR sourcetype="stream:rtcp") | head 5 | table _time sourcetype src_ip dest_ip dialect nt_status status code`
2. Open **Application Atlas → Protocols → Enterprise L7**, select the scope and UTC window, and click **Investigate**.
3. Confirm:
   - Flagged services sort first; healthy rows sit behind **Show all (n)**.
   - Overview and Matrix never display `user_id` or `calling_station_id`.
   - Unconfigured protocols appear as **Not covered** in the Matrix, and missing sub-metrics appear as **Not covered** rather than `—`.
   - Selecting any row opens the Detail Drawer with **Status** first, findings in `<ul className="pl-kv-list">`, `<CopyableIp>` controls, and a bounded **Open raw events in Splunk** link.

## PseudoCo Live Validation

- **Verdict:** **Lab only**
- **Notes:** Splunk Stream L7 wire streams (`smb`, `nfs`, `ldap`, `radius`, `sip`, `rtp`, `rtcp`) remain in Estimate mode on PseudoCo (no capture NIC / 80% daily license cap). Verified via unit and Playwright fixture tests.

