# `enterprise_l7` Synthetic Fixture Field Grounding

All fields in `fixtures/protocols/enterprise_l7/` are grounded in the extracted Splunk Stream 8.1.6 stream definitions under `research/extracted/splunk-app-for-stream_816/splunk_app_stream/default/streams/`:

- `streams/smb` (`stream:smb`, `statsOnly: true` default)
- `streams/nfs` (`stream:nfs`, `statsOnly: true` default)
- `streams/ldap` (`stream:ldap`, `statsOnly: true` default)
- `streams/radius` (`stream:radius`, `statsOnly: true` default)
- `streams/sip` (`stream:sip`, `statsOnly: true` default)
- `streams/rtp` (`stream:rtp`, `statsOnly: true` default)
- `streams/rtcp` (`stream:rtcp`, `statsOnly: true` default)

## 1. `stream_smb_nfs.ndjson` (`stream:smb`, `stream:nfs`)

| Stream | Field | TA Type / Units | Meaning in `enterprise_l7` |
| --- | --- | --- | --- |
| `stream:smb` | `_time`, `host`, `sourcetype` | epoch s, string | Event timestamp, forwarder host, `stream:smb` |
| `stream:smb` | `src_ip`, `dest_ip`, `src_port`, `dest_port` | IPv4/IPv6, int | Client (`flow.c-ip`) and SMB server (`flow.s-ip`) |
| `stream:smb` | `command` | string | SMB command (`smb.command`, e.g. `NEGOTIATE`, `SESSION_SETUP`, `READ`) |
| `stream:smb` | `dialect` | string | SMB protocol dialect (`smb.dialect`, e.g. `NT LM 0.12`, `SMB 3.1.1`) |
| `stream:smb` | `nt_status` | string | NT status code (`smb.nt-status`, e.g. `STATUS_SUCCESS`, `STATUS_LOGON_FAILURE`) |
| `stream:smb` | `time_taken`, `response_time` | microseconds (µs) | Flow/response duration (`/ 1000` -> ms) |
| `stream:smb` | `bytes_in`, `bytes_out` | bytes | Client/server byte counts |
| `stream:nfs` | `command` | string | NFS procedure (`nfs.command`, e.g. `READ`, `WRITE`, `GETATTR`) |
| `stream:nfs` | `status` | string | NFS reply status (`nfs.status`, e.g. `NFS3_OK`, `NFS3ERR_ACCES`, `NFS4ERR_STALE`) |
| `stream:nfs` | `nfs_version` (from Stream `version`) | string | NFS protocol version (`nfs.version`, aliased via SPL `eval` into allowlisted `nfs_version`) |
| `stream:nfs` | `time_taken` | microseconds (µs) | NFS operation duration (`/ 1000` -> ms) |

## 2. `stream_ldap_radius.ndjson` (`stream:ldap`, `stream:radius`)

| Stream | Field | TA Type / Units | Meaning in `enterprise_l7` |
| --- | --- | --- | --- |
| `stream:ldap` | `src_ip`, `dest_ip`, `dest_port` | IP, int | Client and directory server (`389` cleartext, `636` LDAPS) |
| `stream:ldap` | `message_type` | string | LDAP operation (`ldap.message-type`, e.g. `bindRequest`, `searchRequest`) |
| `stream:ldap` | `auth_type` (from Stream `contains_sasl`) | string | Mapped via SPL `eval` from `ldap.contains-sasl` (`true` -> `sasl`, `false` -> `simple`) |
| `stream:ldap` | `result_code` | string / int | Optional normalized/extracted LDAP result code (`0` = success; Stream 8.1.6 nests `resultCode` inside `ldap.elements` and omits top-level `result_code` unless extracted) |
| `stream:ldap` | `response_time` | microseconds (µs) | Server response latency (`/ 1000` -> ms) |
| `stream:radius` | `code`, `status` | string | RADIUS packet code (`radius.code`, e.g. `Access-Accept`, `Access-Reject`) and `radius.status` |
| `stream:radius` | `nas_ip_address` (from Stream `nas_ip`) | string (IP) | NAS IP (`radius.nas-ip`, aliased via SPL `eval` into allowlisted `nas_ip_address`) |
| `stream:radius` | `time_taken` | microseconds (µs) | RADIUS transaction latency (`/ 1000` -> ms) |

## 3. `stream_voip.ndjson` (`stream:sip`, `stream:rtp`, `stream:rtcp`)

| Stream | Field | TA Type / Units | Meaning in `enterprise_l7` |
| --- | --- | --- | --- |
| `stream:sip` | `method` | string | SIP method (`sip.method`, e.g. `INVITE`, `REGISTER`) |
| `stream:sip` | `response_code` (from Stream `reply_code`) | int | SIP reply code (`sip.reply-code`, aliased via SPL `eval` into allowlisted `response_code`) |
| `stream:sip` | `call_id` | string | SIP Call-ID (`sip.call-id`) |
| `stream:sip` | `response_time`, `time_taken` | microseconds (µs) | Signaling latency (`/ 1000` -> ms) |
| `stream:rtp` | `mos` (from Stream `mos_session`) | float (`1.0–5.0`) | Mean Opinion Score (`rtp.mos-session`, aliased into `mos`) |
| `stream:rtp` | `codec` (from Stream `codec_name`) | string | Audio codec (`rtp.codec-name`, aliased into `codec`) |
| `stream:rtp` | `packets_lost` (from Stream `lost`), `packets_in`, `packets_out` | count | Lost packet counter (`rtp.lost`) and total packet counts |
| `stream:rtcp` | `rtcp_jitter` (from `rr_jitter`/`sr_jitter`) | ms (note below) | Interarrival jitter; RFC 3550 reports timestamp units whereas normalized feeds emit ms — unit normalization should be verified against a live Stream VoIP feed |
| `stream:rtcp` | `packet_loss_pct` / `packet_loss` (from `rr_fcnlost`) | % (`0–100`) | Packet loss percentage (`rr_fcnlost` in raw RFC 3550 is `x/256`; normalized feeds emit percentage) |

## 4. Security & Privacy Exclusions

- **Globally forbidden (`FORBIDDEN_SENSITIVE_FIELDS`):** `login` (SMB/RADIUS), `content` (NFS), `password`, `passwd`, `cookie`, `form_data`, `uri_query`, `payload`, `src_content`, `dest_content`, `_raw`. Never projected in SPL or stored in fixtures.
- **Row-expansion only (`ROW_EXPANSION_ONLY_FIELDS`):** `user_id` (`stream:smb`, `stream:sip`) and `calling_station_id` (`stream:radius`). Excluded from Overview/Matrix SPL and tables; fetched only on explicit single-row Detail Drawer expansion.
