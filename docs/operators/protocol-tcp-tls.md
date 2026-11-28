# Operator Guide: TCP Health & TLS (`tcp_tls`)

The **TCP Health & TLS** lens inspects TCP round-trip latency, duplicate/missing-packet retransmits, TCP resets (`tcp_status=1`, `canceled`, `refused`), and TLS version/certificate posture per `client → server` pair across a bounded UTC window.

## 1. Supported Data Sources

| Priority | Sourcetype | Collector | Coverage |
| --- | --- | --- | --- |
| Primary | `stream:tcp` | Splunk Stream (`Splunk_TA_stream` / `splunk_app_stream` 8.1.6+) | Full coverage: `client_rtt` / `server_rtt` (µs), `duplicate_packets_*`, `missing_packets_*`, `tcp_status`, `canceled`/`refused`, `ssl_version`, `ssl_cipher_name`, `ssl_subject`, `ssl_issuer`, `ssl_validity_end`, `ssl_cert_self_signed`. |
| Fallback | `stream:netflow` | Splunk Stream NetFlow (`streamfwd` NetFlow receiver) | Flow pair volume and ports only (`total_bytes`, `total_packets`, `dest_port`). RTT, retransmits, resets, and TLS posture explicitly report **Not covered** (never synthetic zeros or green OK). |

## 2. Enabling `stream:tcp` (Estimate Mode vs. Enabled)

In Splunk App for Stream 8.1.6, `streams/tcp` ships with `enabled: true` and `statsOnly: true` (**Estimate mode**). In Estimate mode, Stream reports volume estimates into `_internal` (`sourcetype="stream:stats"`) but does **not** index `stream:tcp` events.

1. Confirm a capture interface (`sniffer.captures`) is attached to `streamfwd` on your tap/SPAN host or universal forwarder.
2. In Splunk App for Stream (**Configuration → Configure Streams → tcp**), switch `tcp` from **Estimate** (`statsOnly: true`) to **Enabled** (`statsOnly: false`) and select the target index (for example `netflow` or `stream`).
3. Leave payload capture fields (`src_content`, `dest_content`) disabled. Application Atlas blocks payload fields in both SPL construction (`| table ...`) and client-side row projection (`FORBIDDEN_SENSITIVE_FIELDS`).
4. Monitor daily Splunk license volume before enabling `stream:tcp` on high-throughput links; apply Stream content filters or host scoping if daily license utilization approaches 80%.

### On-Demand Estimate-Mode Check

Application Atlas never runs searches on page load. When an operator clicks **Investigate** and `stream:tcp` completes with 0 rows, or clicks **Check Stream mode** in the banner, Atlas inspects `index=_internal sourcetype="stream:stats"` (parsing `senders{}.streams{}.id` and `senders{}.streams{}.stats_only`) and tells you directly whether `tcp` is still in Estimate mode.

## 3. Profile Configuration (`adm_protocol_profiles`)

Create one or more profiles for `lens: "tcp_tls"` under a scope (for example `dc-east`):

```json
{
  "id": "tcp-tls-primary",
  "lens": "tcp_tls",
  "scope": "dc-east",
  "index": "netflow",
  "label": "Stream TCP (dc-east)",
  "extra": {
    "sourcetype": "stream:tcp",
    "rttWarnMs": 50,
    "retransmitWarnPct": 2,
    "certExpiryWarnDays": 30
  }
}
```

Add an optional fallback profile with `"sourcetype": "stream:netflow"` under the same scope; it runs only when the primary `stream:tcp` profile returns zero events.

### Validated `extra` Keys (Fail-Closed)

| Key | Type | Default | Allowed Range |
| --- | --- | --- | --- |
| `sourcetype` | `"stream:tcp" \| "stream:netflow"` | `"stream:tcp"` | Exact enum only |
| `rttWarnMs` | number (ms) | `50` | `(0, 60000]` |
| `retransmitWarnPct` | number (%) | `2` | `[0, 100]` |
| `certExpiryWarnDays` | integer (days) | `30` | `[1, 365]` |

Unknown keys or out-of-range values fail closed at profile validation time.

## 4. Field Grounding & Security Boundaries

- **TA source:** `research/extracted/splunk-app-for-stream_816/splunk_app_stream/default/streams/tcp`
- **Units:** `client_rtt` and `server_rtt` are in microseconds (µs); Atlas divides by `1000` to render milliseconds. Rows with `client_rtt=0` and `client_rtt_packets=0` (or `server_rtt=0` and `server_rtt_packets=0`) are treated as unmeasured rather than `0 ms`.
- **Resets:** `tcp_status=1` (RESET), `canceled=true`, or `refused=true` increments TCP reset count; `tcp_status=0` (OK) and `tcp_status=2` (IGNORED) do not.
- **Legacy TLS:** Flags `SSLv2`, `SSLv3`, `TLSv1`, `TLSv1.0`, `TLSv1.1` (never flags `TLSv1.2` or `TLSv1.3`).
- **Server-side projection:** All searches emit `| head <maxRows + 1> | table <allowlisted fields>`, bounding rows at the indexers and dropping `_raw` before results leave Splunk.
- **Role scoping:** Per `splunk_app/splunk_adm/metadata/default.meta`, the `adm_protocol_profiles` KV Store collection is readable by `adm_investigate`, `adm_viewer`, `admin`, and `sc_admin`, and writable only by `admin` and `sc_admin`.

## 5. Verification Checklist

1. Verify `stream:tcp` events are landing in the configured index:
   `index=<index> sourcetype="stream:tcp" | head 5 | table _time src_ip dest_ip server_rtt duplicate_packets_in tcp_status ssl_version ssl_validity_end`
2. Open **Application Atlas → Protocols → TCP Health & TLS**, select the configured scope and UTC window, and click **Investigate**.
3. Confirm:
   - Flagged pairs sort to the top of Overview and highlight in Matrix.
   - Selecting any pair opens the Detail drawer with RTT p50/p95, retransmits/resets, TLS certificate details, and a bounded **View raw events** link.
   - If only `stream:netflow` is present, pairs display **Not covered** (never green `OK`) and flow volume / destination ports remain visible.

## PseudoCo Live Validation

- **Verdict:** **Live verified** (`stream:tcp` primary + `stream:netflow` fallback)
- **Observed (as `se_demo_readonly`, scope `pseudoco-dc1`):** Scoped independent `streamfwd` capture (`atlas-streamfwd-wire.service` on `ens160`, BPF excluding NetFlow/syslog/HEC, payload fields disabled) feeds `stream:tcp` into `index=netflow` at ~`0.37 MiB/hr`: live `Server RTT p95`, `Client RTT p95`, TCP resets, and TLS posture (`TLS 1.2 · expired` on the 6 Nexus 9000 switches, `TLS 1.2 · 191d` on valid external endpoints, **Not covered** on cleartext `0.0` flows). Drawer **Focus flow** pivot (skipping ephemeral ports `> 32767`) isolates bidirectional pairs (`A↔B`) cleanly. NetFlow-only fallback mode also verified (`Source`/`Destination` headers, port truncation, **Not covered** RTT & TLS).

