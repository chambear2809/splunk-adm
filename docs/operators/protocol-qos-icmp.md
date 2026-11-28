# Operator Guide: QoS/DSCP & ICMP (`qos_icmp`)

**Status:** Staged (synthetic fixture-verified; not yet qualified against a live deployed feed)

The **QoS/DSCP & ICMP** lens correlates NetFlow ToS/DSCP markings across exporters, ICMP control/error events (including PMTUD candidates), and Cisco Nexus Dashboard fabric packet drops across a bounded UTC window.

## 1. Supported Data Sources

| Priority | Sourcetype | Collector | Coverage |
| --- | --- | --- | --- |
| Primary (QoS) | `stream:netflow` | Splunk Stream (`streamfwd` NetFlow receiver) | Per-exporter `tos` (`DSCP = (tos >> 2) & 0x3f`, `ECN = tos & 3`), `min_ttl`, 5-tuple, and `exporter_ip`. Detects DSCP remarking of the same 5-tuple across ≥ 2 exporters and unexpected DSCP codepoints. |
| Primary (ICMP) | `stream:icmp` | Splunk Stream (`Splunk_TA_stream` / `splunk_app_stream` 8.1.6+) | Numeric `type`/`code` (`icmp_type`/`icmp_code`), `src_ip`, `dest_ip`, `bytes`, `time_taken`. Flags Type 3 Code 4 (IPv4 Fragmentation Needed) and Type 2 (ICMPv6 Packet Too Big) as **PMTUD candidates**, plus TTL Exceeded and Destination Unreachable spikes. |
| Primary (Fabric Drops) | `cisco:dc:nd:flows` | Cisco DC Networking App (`cisco_dc_nd_collector.py`) | Flow 5-tuple (`srcIp`, `dstIp`, `srcPort`, `dstPort`, `protocolName`), `stats[].dropPktCount`, `stats[].dropReasons`, `stats[].nodeNames`, `fabricName`, `nd_host`. |

## 2. Enabling `stream:icmp` (Estimate Mode vs. Enabled)

In Splunk App for Stream 8.1.6 (`default/streams/icmp`), `icmp` ships with `enabled: true` and `statsOnly: true` (**Estimate mode**). In Estimate mode, Stream writes volume estimates into `_internal` (`sourcetype="stream:stats"`) without indexing `stream:icmp` events.

1. Confirm a capture interface (`sniffer.captures`) is attached to `streamfwd` on your tap/SPAN host or universal forwarder.
2. In Splunk App for Stream (**Configuration → Configure Streams → icmp**), switch `icmp` from **Estimate** (`statsOnly: true`) to **Enabled** (`statsOnly: false`) and assign the target index (for example `netflow` or `stream`).
3. Leave `icmp.data` (`data`) disabled; Application Atlas only projects numeric `type`/`code`, addresses, counters, and timing.

### On-Demand Estimate-Mode Check

Application Atlas never runs searches on page load. When an operator clicks **Investigate** and `stream:icmp` completes with 0 rows, or clicks **Check Stream mode** in the banner, Atlas inspects `index=_internal sourcetype="stream:stats"` (`senders{}.streams{}.id` and `senders{}.streams{}.stats_only`) and reports whether `icmp` is still in Estimate mode.

## 3. NetFlow `tos` Export & Nexus Dashboard Flow Telemetry

- **NetFlow v9 / IPFIX (`stream:netflow`):** Ensure switches export the IP ToS / DSCP field (`tos`, `ip.tos`) and minimum TTL (`min_ttl`, optional) in their NetFlow v9 / IPFIX flow records so `streamfwd` populates `tos` and `exporter_ip`.
- **Cisco Nexus Dashboard (`cisco:dc:nd:flows`):** Enable the Nexus Dashboard **Flows** modular input in Cisco DC Networking App (`1.2.2` / `2.0.10+`). Nested JSON fields (`stats[].dropPktCount`, `stats[].dropReasons`, `stats[].nodeNames`) are extracted at search time with `| spath` after `| head` and projected into flat allowlisted fields (`dropPktCount`, `dropReasons`, `nodeName`).

## 4. Profile Configuration (`adm_protocol_profiles`)

Configure either one `auto` profile (when all sourcetypes share an index) or separate source-scoped profiles under the same `scope`:

```json
{
  "id": "qos-icmp-netflow",
  "source": "protocol_qos_icmp",
  "lens": "qos_icmp",
  "scope": "dc-east",
  "index": "netflow",
  "observer": "stream-fwd-01",
  "validFrom": 1764243000,
  "validUntil": 1764250200,
  "extra": {
    "sourceKind": "stream_netflow",
    "icmpUnreachableWarnCount": 5,
    "icmpTtlExceededWarnCount": 5,
    "dropPktWarnCount": 1,
    "unexpectedDscpValues": [8]
  }
}
```

### Validated `extra` Keys (Fail-Closed)

| Key | Type | Default | Allowed Range |
| --- | --- | --- | --- |
| `sourceKind` | `"stream_netflow" \| "stream_icmp" \| "nd_flows" \| "auto"` | `"auto"` | Exact enum only |
| `icmpUnreachableWarnCount` | integer | `5` | `[1, 100000]` |
| `icmpTtlExceededWarnCount` | integer | `5` | `[1, 100000]` |
| `dropPktWarnCount` | integer | `1` | `[1, 1000000]` |
| `unexpectedDscpValues` | `number[]` | `[]` | Up to 64 integers in `[0, 63]` |

Unknown keys or out-of-range values fail closed during profile parsing.

## 5. Evidence Semantics & Security Boundaries

- **PMTUD wording:** Type 3 Code 4 (`Fragmentation Needed`) and ICMPv6 Type 2 (`Packet Too Big`) are always reported as **PMTUD candidate** (never "MTU blackhole confirmed"), because observed ICMP error packets cannot prove downstream silent packet drops.
- **Not covered vs. None observed:** Missing sources render `<StatusChip status="not_covered" />` in table columns and KPI tiles rather than synthetic zeros.
- **Server-side projection:** Searches emit `| head <maxRows + 1>` before `| table <allowlisted fields>`, bounding rows at the indexers and dropping `_raw` before results leave Splunk.

## 6. Verification Checklist

1. Verify NetFlow `tos`, `stream:icmp`, and `cisco:dc:nd:flows` events in Splunk:
   - `index=<netflow_index> sourcetype="stream:netflow" | head 5 | table _time exporter_ip src_ip dest_ip protoid tos min_ttl`
   - `index=<icmp_index> sourcetype="stream:icmp" | head 5 | table _time src_ip dest_ip type code bytes`
   - `index=<nd_index> sourcetype="cisco:dc:nd:flows" | head 5 | spath path=stats{}.dropPktCount output=_nd_drop_pkts | table _time srcIp dstIp protocolName _nd_drop_pkts`
2. Open **Application Atlas → Protocols → QoS/DSCP & ICMP**, choose the scope and UTC window, and click **Investigate**.
3. Confirm remarked flows, PMTUD candidates, and ND fabric drops appear first in Overview, highlight in the Exporter × DSCP Matrix, and open with `literal()`-quoted raw-event links in the Detail drawer.

## PseudoCo Live Validation

- **Verdict:** **Live verified** (NetFlow DSCP + `stream:icmp`)
- **Observed (as `se_demo_readonly`, scope `pseudoco-dc1`):** `247` flows healthy across live `stream:netflow` (DSCP consistency) and scoped `stream:icmp` (`0` ICMP errors); ND fabric drops truthfully marked **Not covered**. Use the **Source**, **Dest**, **Port**, and **A↔B** bidirectional filters (or **Focus flow** in the drawer) to isolate a specific conversation below the row cap.

