#!/usr/bin/env python3
"""Generate TA-shaped synthetic ecosystem traffic fixtures.

Writes HEC /event envelopes to fixtures/raw-ecosystem/. Each event is the exact
_raw text the producer writes (firewall syslog, F5 iRule HSL message, AWS ELB
access-log line, Azure VNet flow log record, GCP VPC Flow Logs LogEntry), so
the add-on's own search-time extraction or Atlas's extraction sees realistic
input. Field grounding and source versions are recorded in
fixtures/raw/FIELDS.md ("Ecosystem firewall traffic" and "Ecosystem load
balancer and cloud flow logs"). Values are synthetic documentation addresses.
Output is deterministic; --check compares against the committed files.
"""

from __future__ import annotations

import argparse
import json
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
OUT = ROOT / "fixtures" / "raw-ecosystem"

# Splunk_TA_paloalto 6.2.0 (commit 23b114c5a9494b4a855310ff472b1817739f53e0)
# default/transforms.conf [extract_traffic] FIELDS, in order.
PAN_TRAFFIC_FIELDS = (
    "future_use1",
    "receive_time",
    "serial_number",
    "type",
    "log_subtype",
    "version",
    "generated_time",
    "src_ip",
    "dest_ip",
    "src_translated_ip",
    "dest_translated_ip",
    "rule",
    "src_user",
    "dest_user",
    "app",
    "vsys",
    "src_zone",
    "dest_zone",
    "src_interface",
    "dest_interface",
    "log_forwarding_profile",
    "future_use3",
    "session_id",
    "repeat_count",
    "src_port",
    "dest_port",
    "src_translated_port",
    "dest_translated_port",
    "session_flags",
    "transport",
    "action",
    "bytes",
    "bytes_out",
    "bytes_in",
    "packets",
    "start_time",
    "duration",
    "http_category",
    "future_use4",
    "sequence_number",
    "action_flags",
    "src_location",
    "dest_location",
    "future_use5",
    "packets_out",
    "packets_in",
    "session_end_reason",
    "devicegroup_level1",
    "devicegroup_level2",
    "devicegroup_level3",
    "devicegroup_level4",
    "vsys_name",
    "dvc_name",
    "action_source",
    "src_vm",
    "dest_vm",
    "tunnel_id",
    "tunnel_monitor_tag",
    "tunnel_session_id",
    "tunnel_start_time",
    "tunnel_type",
)

# FortiOS 7.6.0 Log Message Reference, LOG_ID_TRAFFIC_STAT field table, and the
# raw traffic example on the "Log message fields" page.
FORTIOS_TRAFFIC_KEYS = (
    "date",
    "time",
    "devname",
    "devid",
    "eventtime",
    "tz",
    "logid",
    "type",
    "subtype",
    "level",
    "vd",
    "srcip",
    "srcport",
    "srcintf",
    "srcintfrole",
    "dstip",
    "dstport",
    "dstintf",
    "dstintfrole",
    "sessionid",
    "proto",
    "action",
    "policyid",
    "policytype",
    "service",
    "trandisp",
    "transip",
    "transport",
    "tranip",
    "tranport",
    "duration",
    "sentbyte",
    "rcvdbyte",
    "sentpkt",
    "rcvdpkt",
)
QUOTED_FORTIOS_KEYS = {
    "devname",
    "devid",
    "tz",
    "logid",
    "type",
    "subtype",
    "level",
    "vd",
    "srcintf",
    "srcintfrole",
    "dstintf",
    "dstintfrole",
    "action",
    "policytype",
    "service",
    "trandisp",
}

BASE = datetime(2026, 11, 26, 15, 0, 0, tzinfo=timezone.utc)
PAN_HOST = "pa-fw-01"
PAN_SERIAL = "012801000001"
FORTI_HOST = "fgt-edge-01"
FORTI_SERIAL = "FGVM02TM00000001"
HEC_SOURCE_SYSLOG = "udp:514"


def _pan_time(value: datetime) -> str:
    return value.strftime("%Y/%m/%d %H:%M:%S")


def _epoch(value: datetime) -> int:
    return int(value.timestamp())


def pan_event(**values: str) -> str:
    unknown = set(values) - set(PAN_TRAFFIC_FIELDS)
    if unknown:
        raise ValueError(f"ungrounded PAN fields: {sorted(unknown)}")
    return ",".join(values.get(field, "") for field in PAN_TRAFFIC_FIELDS)


def pan_records() -> list[dict]:
    """Four sessions: SNAT allow, policy deny, silent drop and DNAT start."""

    def common(generated: datetime, start: datetime, subtype: str) -> dict:
        return {
            "future_use1": "1",
            "receive_time": _pan_time(generated + timedelta(seconds=1)),
            "serial_number": PAN_SERIAL,
            "type": "TRAFFIC",
            "log_subtype": subtype,
            "version": "1",
            "generated_time": _pan_time(generated),
            "start_time": _pan_time(start),
            "vsys": "vsys1",
            "vsys_name": "vsys1",
            "dvc_name": PAN_HOST,
            "repeat_count": "1",
            "devicegroup_level1": "0",
            "devicegroup_level2": "0",
            "devicegroup_level3": "0",
            "devicegroup_level4": "0",
            "action_flags": "0x0",
            "log_forwarding_profile": "atlas-forward",
        }

    rows = []
    generated = BASE + timedelta(seconds=65)
    start = BASE + timedelta(seconds=50)
    rows.append(
        (
            generated,
            pan_event(
                **common(generated, start, "end"),
                src_ip="10.20.1.15",
                dest_ip="198.51.100.20",
                src_translated_ip="203.0.113.5",
                dest_translated_ip="198.51.100.20",
                rule="allow-web-egress",
                app="ssl",
                src_zone="trust",
                dest_zone="untrust",
                src_interface="ethernet1/2",
                dest_interface="ethernet1/1",
                session_id="21001",
                src_port="51514",
                dest_port="443",
                src_translated_port="40123",
                dest_translated_port="443",
                session_flags="0x400053",
                transport="tcp",
                action="allow",
                bytes="5200",
                bytes_out="1200",
                bytes_in="4000",
                packets="20",
                duration="15",
                sequence_number="7021",
                src_location="10.0.0.0-10.255.255.255",
                dest_location="198.51.100.0-198.51.100.255",
                packets_out="10",
                packets_in="10",
                session_end_reason="tcp-fin",
            ),
        )
    )
    generated = BASE + timedelta(seconds=80)
    rows.append(
        (
            generated,
            pan_event(
                **common(generated, generated, "deny"),
                src_ip="10.20.1.15",
                dest_ip="192.0.2.44",
                src_translated_ip="0.0.0.0",
                dest_translated_ip="0.0.0.0",
                rule="block-rdp",
                app="ms-rdp",
                src_zone="trust",
                dest_zone="dmz",
                src_interface="ethernet1/2",
                dest_interface="ethernet1/3",
                session_id="21002",
                src_port="51520",
                dest_port="3389",
                src_translated_port="0",
                dest_translated_port="0",
                session_flags="0x0",
                transport="tcp",
                action="deny",
                bytes="74",
                bytes_out="74",
                bytes_in="0",
                packets="1",
                duration="0",
                sequence_number="7022",
                packets_out="1",
                packets_in="0",
                session_end_reason="policy-deny",
            ),
        )
    )
    generated = BASE + timedelta(seconds=95)
    rows.append(
        (
            generated,
            pan_event(
                **common(generated, generated, "drop"),
                src_ip="10.20.1.15",
                dest_ip="192.0.2.45",
                src_translated_ip="0.0.0.0",
                dest_translated_ip="0.0.0.0",
                rule="interzone-default",
                app="not-applicable",
                src_zone="trust",
                dest_zone="dmz",
                src_interface="ethernet1/2",
                dest_interface="",
                session_id="0",
                src_port="51530",
                dest_port="23",
                src_translated_port="0",
                dest_translated_port="0",
                session_flags="0x0",
                transport="tcp",
                action="drop",
                bytes="60",
                bytes_out="60",
                bytes_in="0",
                packets="1",
                duration="0",
                sequence_number="7023",
                packets_out="1",
                packets_in="0",
                session_end_reason="policy-deny",
            ),
        )
    )
    generated = BASE + timedelta(seconds=110)
    rows.append(
        (
            generated,
            pan_event(
                **common(generated, generated, "start"),
                src_ip="198.51.100.77",
                dest_ip="203.0.113.80",
                src_translated_ip="0.0.0.0",
                dest_translated_ip="10.20.1.15",
                rule="publish-portal",
                app="ssl",
                src_zone="untrust",
                dest_zone="trust",
                src_interface="ethernet1/1",
                dest_interface="ethernet1/2",
                session_id="21004",
                src_port="60000",
                dest_port="443",
                src_translated_port="0",
                dest_translated_port="8443",
                session_flags="0x400000",
                transport="tcp",
                action="allow",
                bytes="66",
                bytes_out="66",
                bytes_in="0",
                packets="1",
                duration="0",
                sequence_number="7024",
                packets_out="1",
                packets_in="0",
                session_end_reason="n/a",
            ),
        )
    )
    return [
        {
            "time": _epoch(generated),
            "host": PAN_HOST,
            "source": HEC_SOURCE_SYSLOG,
            "sourcetype": "pan:traffic",
            "index": "pan",
            "event": raw,
        }
        for generated, raw in rows
    ]


def forti_event(**values: str) -> str:
    unknown = set(values) - set(FORTIOS_TRAFFIC_KEYS)
    if unknown:
        raise ValueError(f"ungrounded FortiOS keys: {sorted(unknown)}")
    pairs = []
    for key in FORTIOS_TRAFFIC_KEYS:
        if key not in values:
            continue
        value = values[key]
        pairs.append(
            f'{key}="{value}"' if key in QUOTED_FORTIOS_KEYS else f"{key}={value}"
        )
    return " ".join(pairs)


def forti_records() -> list[dict]:
    """SNAT close, policy deny, DNAT accept and a client reset."""

    def common(logged: datetime, subtype: str = "forward") -> dict:
        return {
            "date": logged.strftime("%Y-%m-%d"),
            "time": logged.strftime("%H:%M:%S"),
            "devname": FORTI_HOST,
            "devid": FORTI_SERIAL,
            "eventtime": str(_epoch(logged) * 10**9),
            "tz": "+0000",
            "logid": "0000000013",
            "type": "traffic",
            "subtype": subtype,
            "level": "notice",
            "vd": "root",
            "policytype": "policy",
        }

    rows = []
    logged = BASE + timedelta(seconds=70)
    rows.append(
        (
            logged,
            "fortigate_traffic",
            forti_event(
                **common(logged),
                srcip="10.30.1.25",
                srcport="51514",
                srcintf="port2",
                srcintfrole="lan",
                dstip="198.51.100.20",
                dstport="443",
                dstintf="port1",
                dstintfrole="wan",
                sessionid="8058",
                proto="6",
                action="close",
                policyid="1",
                service="HTTPS",
                trandisp="snat",
                transip="203.0.113.6",
                transport="40772",
                duration="15",
                sentbyte="1850",
                rcvdbyte="39898",
                sentpkt="25",
                rcvdpkt="37",
            ),
        )
    )
    logged = BASE + timedelta(seconds=85)
    rows.append(
        (
            logged,
            "fortigate_traffic",
            forti_event(
                **common(logged),
                srcip="10.30.1.25",
                srcport="51522",
                srcintf="port2",
                srcintfrole="lan",
                dstip="192.0.2.44",
                dstport="3389",
                dstintf="port3",
                dstintfrole="dmz",
                sessionid="8059",
                proto="6",
                action="deny",
                policyid="7",
                service="RDP",
                trandisp="noop",
                duration="0",
                sentbyte="0",
                rcvdbyte="0",
                sentpkt="0",
                rcvdpkt="0",
            ),
        )
    )
    logged = BASE + timedelta(seconds=100)
    rows.append(
        (
            logged,
            "fortigate_traffic",
            forti_event(
                **common(logged),
                srcip="198.51.100.77",
                srcport="60001",
                srcintf="port1",
                srcintfrole="wan",
                dstip="203.0.113.81",
                dstport="443",
                dstintf="port2",
                dstintfrole="lan",
                sessionid="8060",
                proto="6",
                action="accept",
                policyid="12",
                service="HTTPS",
                trandisp="dnat",
                tranip="10.30.1.25",
                tranport="8443",
                duration="20",
                sentbyte="2100",
                rcvdbyte="9100",
                sentpkt="14",
                rcvdpkt="16",
            ),
        )
    )
    logged = BASE + timedelta(seconds=115)
    rows.append(
        (
            logged,
            "fgt_traffic",
            forti_event(
                **common(logged),
                srcip="10.30.1.25",
                srcport="51540",
                srcintf="port2",
                srcintfrole="lan",
                dstip="198.51.100.30",
                dstport="443",
                dstintf="port1",
                dstintfrole="wan",
                sessionid="8061",
                proto="6",
                action="client-rst",
                policyid="1",
                service="HTTPS",
                trandisp="snat",
                transip="203.0.113.6",
                transport="40790",
                duration="4",
                sentbyte="600",
                rcvdbyte="300",
                sentpkt="6",
                rcvdpkt="4",
            ),
        )
    )
    return [
        {
            "time": _epoch(logged),
            "host": FORTI_HOST,
            "source": HEC_SOURCE_SYSLOG,
            "sourcetype": sourcetype,
            "index": "fortigate",
            "event": raw,
        }
        for logged, sourcetype, raw in rows
    ]


# Splunk Add-on for F5 BIG-IP 7.0.x, "Configure iRules for LTM": the
# Splunk-iRule-HTTP HSL::send key order. LB_FAILED sends the keys through
# bytes_in. Quoted values are those the iRule wraps in \".
F5_IRULE_KEYS = (
    "f5_irule",
    "src_ip",
    "vip",
    "http_method",
    "http_host",
    "http_uri",
    "http_url",
    "http_version",
    "http_user_agent",
    "http_content_type",
    "http_referrer",
    "req_start_time",
    "cookie",
    "user",
    "virtual_server",
    "bytes_in",
    "res_start_time",
    "node",
    "node_port",
    "http_status",
    "req_elapsed_time",
    "bytes_out",
)
F5_LB_FAILED_KEYS = F5_IRULE_KEYS[: F5_IRULE_KEYS.index("bytes_in") + 1]
F5_QUOTED_KEYS = {"http_user_agent", "http_referrer", "cookie", "virtual_server"}

# AWS "Access logs for your Application Load Balancer", fields 1-36 in order.
ALB_FIELDS = (
    "type",
    "time",
    "elb",
    "client:port",
    "target:port",
    "request_processing_time",
    "target_processing_time",
    "response_processing_time",
    "elb_status_code",
    "target_status_code",
    "received_bytes",
    "sent_bytes",
    "request_line",
    "user_agent",
    "ssl_cipher",
    "ssl_protocol",
    "target_group_arn",
    "trace_id",
    "domain_name",
    "chosen_cert_arn",
    "matched_rule_priority",
    "request_creation_time",
    "actions_executed",
    "redirect_url",
    "error_reason",
    "target:port_list",
    "target_status_code_list",
    "classification",
    "classification_reason",
    "conn_trace_id",
    "transformed_host",
    "transformed_uri",
    "request_transform_status",
    "ip_address",
    "target_error_code",
    "elb_error_code",
)
ALB_QUOTED_FIELDS = {
    "request_line",
    "user_agent",
    "trace_id",
    "domain_name",
    "chosen_cert_arn",
    "actions_executed",
    "redirect_url",
    "error_reason",
    "target:port_list",
    "target_status_code_list",
    "classification",
    "classification_reason",
    "transformed_host",
    "transformed_uri",
    "request_transform_status",
}

# AWS "Access logs for your Network Load Balancer", version 3.0 fields in order.
NLB_FIELDS = (
    "type",
    "version",
    "time",
    "elb",
    "listener",
    "client_port",
    "destination_port",
    "connection_time",
    "tls_handshake_time",
    "received_bytes",
    "sent_bytes",
    "incoming_tls_alert",
    "chosen_cert_arn",
    "chosen_cert_serial",
    "tls_cipher",
    "tls_protocol_version",
    "tls_keyexchange",
    "domain_name",
    "alpn_fe_protocol",
    "alpn_be_protocol",
    "alpn_client_preference_list",
    "tls_connection_creation_time",
    "tls_verify_status",
    "leaf_client_cert_subject",
    "leaf_client_cert_validity",
    "leaf_client_cert_serial_number",
)

# Microsoft "Virtual network flow logs" log format: record keys and the
# comma-separated flow tuple (13 fields; version 5 adds three).
AZURE_RECORD_KEYS = (
    "time",
    "flowLogVersion",
    "flowLogGUID",
    "macAddress",
    "category",
    "flowLogResourceID",
    "targetResourceID",
    "operationName",
    "flowRecords",
)
AZURE_TUPLE_FIELDS = (
    "time_stamp",
    "source_ip",
    "destination_ip",
    "source_port",
    "destination_port",
    "protocol",
    "flow_direction",
    "flow_state",
    "flow_encryption",
    "packets_sent",
    "bytes_sent",
    "packets_received",
    "bytes_received",
)
AZURE_V5_TUPLE_FIELDS = AZURE_TUPLE_FIELDS + (
    "pls_link_identifier",
    "source_nat_ip",
    "source_nat_port",
)

# Google "VPC Flow Logs records": the base fields and metadata used here.
GCP_PAYLOAD_KEYS = {
    "connection",
    "reporter",
    "start_time",
    "end_time",
    "bytes_sent",
    "packets_sent",
    "rtt_msec",
    "disposition",
    "drop_reason",
    "bytes_dropped",
    "packets_dropped",
    "src_instance",
    "dest_instance",
    "src_vpc",
    "dest_vpc",
}
GCP_CONNECTION_KEYS = {
    "src_ip",
    "src_port",
    "dest_ip",
    "dest_port",
    "protocol",
    "nat_ip",
    "nat_port",
}
GCP_LOG_ENTRY_KEYS = {
    "insertId",
    "jsonPayload",
    "logName",
    "receiveTimestamp",
    "resource",
    "timestamp",
}

F5_HOST = "bigip-01"
AWS_HOST = "aws-ta-hf"
AZURE_HOST = "mscs-hf"
GCP_HOST = "gcp-ta-hf"
AWS_ACCOUNT = "123456789012"
AZURE_SUBSCRIPTION = "00000000-0000-0000-0000-000000000000"
GCP_PROJECT = "atlas-demo-project"


def f5_event(keys: tuple[str, ...] = F5_IRULE_KEYS, **values: str) -> str:
    unknown = set(values) - set(keys)
    if unknown:
        raise ValueError(f"ungrounded F5 iRule keys: {sorted(unknown)}")
    parts = []
    for key in keys:
        value = values.get(key, "")
        parts.append(f'{key}="{value}"' if key in F5_QUOTED_KEYS else f"{key}={value}")
    return "<190>," + ",".join(parts) + "\r\n"


def _f5_clock(value: datetime, offset_hours: int) -> str:
    return (value + timedelta(hours=offset_hours)).strftime("%Y/%m/%d %H:%M:%S")


def f5_records() -> list[dict]:
    """HTTP request, route-domain 503, LB_FAILED, and an injected User-Agent."""
    rows = []
    request = BASE + timedelta(seconds=60)
    response = request + timedelta(seconds=1)
    common = {
        "http_method": "GET",
        "http_uri": "/orders",
        "http_version": "1.1",
        "http_content_type": "",
        "http_referrer": "",
        "cookie": "",
        "user": "",
    }
    # BIG-IP clock in UTC-5: the iRule's [clock format] writes local time.
    rows.append(
        (
            response,
            f5_event(
                f5_irule="Splunk-iRule-HTTP",
                src_ip="198.51.100.10",
                vip="203.0.113.80",
                http_host="shop.example.com:443",
                http_url="shop.example.com:443/orders",
                http_user_agent="Mozilla/5.0 (X11; Linux x86_64) Gecko, like Firefox",
                req_start_time=_f5_clock(request, -5),
                virtual_server="/Common/pool_web 0.0.0.0 0",
                bytes_in="0",
                res_start_time=_f5_clock(response, -5),
                node="10.40.1.15",
                node_port="8080",
                http_status="200",
                req_elapsed_time="840",
                bytes_out="5120",
                **common,
            ),
        )
    )
    request = BASE + timedelta(seconds=90)
    rows.append(
        (
            request,
            f5_event(
                f5_irule="Splunk-iRule-HTTP",
                src_ip="10.50.0.9%2",
                vip="10.60.0.10%2",
                http_host="api.internal:80",
                http_url="api.internal:80/orders",
                http_user_agent="curl/8.5.0",
                req_start_time=_f5_clock(request, 0),
                virtual_server="/Tenant/pool_api",
                bytes_in="128",
                res_start_time=_f5_clock(request, 0),
                node="10.40.1.15%2",
                node_port="8080",
                http_status="503",
                req_elapsed_time="12",
                bytes_out="0",
                **common,
            ),
        )
    )
    request = BASE + timedelta(seconds=120)
    rows.append(
        (
            request,
            f5_event(
                F5_LB_FAILED_KEYS,
                f5_irule="Splunk-iRule-LB_FAILED",
                src_ip="198.51.100.11",
                vip="203.0.113.80",
                http_host="shop.example.com:443",
                http_url="shop.example.com:443/orders",
                http_user_agent="curl/8.5.0",
                req_start_time=_f5_clock(request, 0),
                virtual_server="/Common/pool_web",
                bytes_in="0",
                **common,
            ),
        )
    )
    request = BASE + timedelta(seconds=150)
    rows.append(
        (
            request,
            f5_event(
                f5_irule="Splunk-iRule-HTTP",
                src_ip="198.51.100.12",
                vip="203.0.113.80",
                http_host="shop.example.com:443",
                http_url="shop.example.com:443/orders",
                http_user_agent='x",node=10.40.1.15,node_port=22,"',
                req_start_time=_f5_clock(request, 0),
                virtual_server="/Common/pool_web",
                bytes_in="0",
                res_start_time=_f5_clock(request, 0),
                node="10.40.1.16",
                node_port="8080",
                http_status="200",
                req_elapsed_time="5",
                bytes_out="10",
                **common,
            ),
        )
    )
    return [
        {
            "time": _epoch(when),
            "host": F5_HOST,
            "source": HEC_SOURCE_SYSLOG,
            "sourcetype": (
                "f5:bigip:ltm:lb:failed:irule"
                if "LB_FAILED" in raw
                else "f5:bigip:ltm:http:irule"
            ),
            "index": "f5",
            "event": raw,
        }
        for when, raw in rows
    ]


def _iso(value: datetime, fraction: bool = True, zone: bool = True) -> str:
    text = value.strftime("%Y-%m-%dT%H:%M:%S")
    if fraction:
        text += f".{value.microsecond:06d}"
    return text + ("Z" if zone else "")


def alb_line(count: int = len(ALB_FIELDS), **values: str) -> str:
    fields = ALB_FIELDS[:count]
    unknown = set(values) - set(fields)
    if unknown:
        raise ValueError(f"ungrounded ALB fields: {sorted(unknown)}")
    return " ".join(
        f'"{values.get(field, "-")}"'
        if field in ALB_QUOTED_FIELDS
        else values.get(field, "-")
        for field in fields
    )


def nlb_line(**values: str) -> str:
    unknown = set(values) - set(NLB_FIELDS)
    if unknown:
        raise ValueError(f"ungrounded NLB fields: {sorted(unknown)}")
    return " ".join(values.get(field, "-") for field in NLB_FIELDS)


def aws_records() -> list[dict]:
    """ALB forward (36 fields), ALB fixed 503 without target, ALB 29-field log, NLB TLS."""
    alb = "app/atlas-web/50dc6c495c0c9188"
    target_group = (
        f"arn:aws:elasticloadbalancing:us-east-2:{AWS_ACCOUNT}"
        ":targetgroup/atlas-web/73e2d6bc24d8a067"
    )
    rows = []
    created = BASE + timedelta(seconds=60, microseconds=364000)
    done = created + timedelta(milliseconds=186)
    rows.append(
        (
            done,
            alb_line(
                type="https",
                time=_iso(done),
                elb=alb,
                **{
                    "client:port": "198.51.100.10:2817",
                    "target:port": "10.40.1.20:8443",
                },
                request_processing_time="0.086",
                target_processing_time="0.048",
                response_processing_time="0.037",
                elb_status_code="200",
                target_status_code="200",
                received_bytes="512",
                sent_bytes="2048",
                request_line="GET https://shop.example.com:443/orders HTTP/1.1",
                user_agent="curl/8.5.0",
                ssl_cipher="ECDHE-RSA-AES128-GCM-SHA256",
                ssl_protocol="TLSv1.2",
                target_group_arn=target_group,
                trace_id="Root=1-58337281-1d84f3d73c47ec4e58577259",
                domain_name="shop.example.com",
                chosen_cert_arn=f"arn:aws:acm:us-east-2:{AWS_ACCOUNT}:certificate/12345678-1234-1234-1234-123456789012",
                matched_rule_priority="1",
                request_creation_time=_iso(created),
                actions_executed="forward",
                **{
                    "target:port_list": "10.40.1.20:8443",
                    "target_status_code_list": "200",
                },
                conn_trace_id="TID_1234abcd5678ef90",
                ip_address="10.0.0.5",
            ),
        )
    )
    created = BASE + timedelta(seconds=90)
    rows.append(
        (
            created,
            alb_line(
                type="http",
                time=_iso(created),
                elb=alb,
                **{"client:port": "198.51.100.11:40100"},
                request_processing_time="-1",
                target_processing_time="-1",
                response_processing_time="-1",
                elb_status_code="503",
                received_bytes="120",
                sent_bytes="320",
                request_line="GET http://shop.example.com:80/orders HTTP/1.1",
                user_agent="curl/8.5.0",
                target_group_arn=target_group,
                matched_rule_priority="0",
                request_creation_time=_iso(created),
                actions_executed="forward",
                conn_trace_id="TID_2234abcd5678ef90",
                ip_address="10.0.0.6",
            ),
        )
    )
    created = BASE + timedelta(seconds=120)
    done = created + timedelta(milliseconds=3)
    rows.append(
        (
            done,
            alb_line(
                29,
                type="http",
                time=_iso(done),
                elb=alb,
                **{"client:port": "10.30.1.25:51000", "target:port": "10.40.1.20:8080"},
                request_processing_time="0.000",
                target_processing_time="0.002",
                response_processing_time="0.000",
                elb_status_code="200",
                target_status_code="200",
                received_bytes="90",
                sent_bytes="400",
                request_line="GET http://10.0.0.30:80/health HTTP/1.1",
                user_agent="kube-probe/1.29",
                target_group_arn=target_group,
                trace_id="Root=1-58337364-23a8c76965a2ef7629b185e3",
                matched_rule_priority="0",
                request_creation_time=_iso(created),
                actions_executed="forward",
                **{
                    "target:port_list": "10.40.1.20:8080",
                    "target_status_code_list": "200",
                },
            ),
        )
    )
    created = BASE + timedelta(seconds=140)
    done = BASE + timedelta(seconds=150)
    rows.append(
        (
            done,
            nlb_line(
                type="tls",
                version="3.0",
                time=_iso(done, fraction=False, zone=False),
                elb="net/atlas-tls/c6e77e28c25b2234",
                listener="g3d4b5e8bb8464cd",
                client_port="198.51.100.10:51341",
                destination_port="203.0.113.90:443",
                connection_time="10000",
                tls_handshake_time="2",
                received_bytes="98",
                sent_bytes="246",
                chosen_cert_arn=f"arn:aws:acm:us-east-2:{AWS_ACCOUNT}:certificate/2a108f19-aded-46b0-8493-example4a99",
                tls_cipher="ECDHE-RSA-AES128-SHA",
                tls_protocol_version="tlsv12",
                domain_name="atlas-tls-c6e77e28c25b2234.elb.us-east-2.amazonaws.com",
                tls_connection_creation_time=_iso(created, fraction=False, zone=False),
                tls_verify_status="Success",
                leaf_client_cert_subject='"-"',
            ),
        )
    )
    return [
        {
            "time": round(when.timestamp(), 6),
            "host": AWS_HOST,
            "source": f"s3://atlas-elb-logs/AWSLogs/{AWS_ACCOUNT}/elasticloadbalancing/us-east-2/2026/11/26/",
            "sourcetype": "aws:elb:accesslogs",
            "index": "aws",
            "event": raw,
        }
        for when, raw in rows
    ]


def azure_tuple(fields: tuple[str, ...] = AZURE_TUPLE_FIELDS, **values: str) -> str:
    unknown = set(values) - set(fields)
    if unknown:
        raise ValueError(f"ungrounded Azure tuple fields: {sorted(unknown)}")
    return ",".join(values.get(field, "") for field in fields)


def azure_record(version: int, logged: datetime, flows: list[dict]) -> dict:
    record = {
        "time": logged.strftime("%Y-%m-%dT%H:%M:%S.") + f"{logged.microsecond:06d}0Z",
        "flowLogVersion": version,
        "flowLogGUID": "66aa66aa-bb77-cc88-dd99-00ee00ee00ee",
        "macAddress": "00224879A1B2",
        "category": "FlowLogFlowEvent",
        "flowLogResourceID": (
            f"/SUBSCRIPTIONS/{AZURE_SUBSCRIPTION}/RESOURCEGROUPS/NETWORKWATCHERRG"
            "/PROVIDERS/MICROSOFT.NETWORK/NETWORKWATCHERS/NETWORKWATCHER_EASTUS2/FLOWLOGS/ATLASVNETFLOW"
        ),
        "targetResourceID": (
            f"/subscriptions/{AZURE_SUBSCRIPTION}/resourceGroups/atlas"
            "/providers/Microsoft.Network/virtualNetworks/atlas-vnet"
        ),
        "operationName": "FlowLogFlowEvent",
        "flowRecords": {"flows": flows},
    }
    unknown = set(record) - set(AZURE_RECORD_KEYS)
    if unknown:
        raise ValueError(f"ungrounded Azure record keys: {sorted(unknown)}")
    return record


def _ms(value: datetime) -> str:
    return str(int(value.timestamp() * 1000))


def azure_records() -> list[dict]:
    """Bare v4 record (allow + deny), one-element v5 array (PLS SNAT), two-record array."""
    acl = "00aa00aa-bb11-cc22-dd33-44ee44ee44ee"
    logged = BASE + timedelta(seconds=120, microseconds=562508)
    begin = BASE + timedelta(seconds=60)
    end = BASE + timedelta(seconds=75)
    deny = BASE + timedelta(seconds=80)
    v4 = azure_record(
        4,
        logged,
        [
            {
                "aclID": acl,
                "flowGroups": [
                    {
                        "rule": "DefaultRule_AllowInternetOutBound",
                        "flowTuples": [
                            azure_tuple(
                                time_stamp=_ms(begin),
                                source_ip="10.40.1.15",
                                destination_ip="198.51.100.20",
                                source_port="23956",
                                destination_port="443",
                                protocol="6",
                                flow_direction="O",
                                flow_state="B",
                                flow_encryption="NX",
                            ),
                            azure_tuple(
                                time_stamp=_ms(end),
                                source_ip="10.40.1.15",
                                destination_ip="198.51.100.20",
                                source_port="23956",
                                destination_port="443",
                                protocol="6",
                                flow_direction="O",
                                flow_state="E",
                                flow_encryption="NX",
                                packets_sent="22",
                                bytes_sent="2217",
                                packets_received="33",
                                bytes_received="32466",
                            ),
                        ],
                    }
                ],
            },
            {
                "aclID": acl,
                "flowGroups": [
                    {
                        "rule": "BlockHighRiskTCPPortsFromInternet",
                        "flowTuples": [
                            azure_tuple(
                                time_stamp=_ms(deny),
                                source_ip="192.0.2.10",
                                destination_ip="10.40.1.15",
                                source_port="55188",
                                destination_port="22",
                                protocol="6",
                                flow_direction="I",
                                flow_state="D",
                                flow_encryption="NX",
                                packets_sent="0",
                                bytes_sent="0",
                                packets_received="0",
                                bytes_received="0",
                            )
                        ],
                    }
                ],
            },
        ],
    )
    pls = BASE + timedelta(seconds=100)
    v5 = azure_record(
        5,
        logged,
        [
            {
                "aclID": acl,
                "flowGroups": [
                    {
                        "rule": "AllowPrivateLinkInbound",
                        "flowTuples": [
                            azure_tuple(
                                AZURE_V5_TUPLE_FIELDS,
                                time_stamp=_ms(pls),
                                source_ip="10.70.0.4",
                                destination_ip="10.40.1.15",
                                source_port="50557",
                                destination_port="8443",
                                protocol="6",
                                flow_direction="I",
                                flow_state="E",
                                flow_encryption="NX",
                                packets_sent="3",
                                bytes_sent="705",
                                packets_received="4",
                                bytes_received="4569",
                                pls_link_identifier="822134362",
                                source_nat_ip="10.26.252.5",
                                source_nat_port="4890",
                            )
                        ],
                    }
                ],
            }
        ],
    )
    rows = [
        (logged, v4),
        (logged, {"records": [v5]}),
        (logged, {"records": [v4, v5]}),
    ]
    return [
        {
            "time": round(when.timestamp(), 6),
            "host": AZURE_HOST,
            "source": "insights-logs-flowlogflowevent",
            "sourcetype": "mscs:vnet:flow",
            "index": "azure",
            "event": json.dumps(body, sort_keys=True, separators=(",", ":")),
        }
        for when, body in rows
    ]


def gcp_entry(received: datetime, payload: dict) -> dict:
    unknown = set(payload) - GCP_PAYLOAD_KEYS
    unknown |= set(payload.get("connection", {})) - GCP_CONNECTION_KEYS
    if unknown:
        raise ValueError(f"ungrounded GCP VPC Flow Logs fields: {sorted(unknown)}")
    entry = {
        "insertId": f"atlas{int(received.timestamp())}",
        "jsonPayload": payload,
        "logName": f"projects/{GCP_PROJECT}/logs/compute.googleapis.com%2Fvpc_flows",
        "receiveTimestamp": _iso(received),
        "resource": {
            "labels": {
                "location": "us-central1-c",
                "project_id": GCP_PROJECT,
                "subnetwork_id": "4884528796030499819",
                "subnetwork_name": "default",
            },
            "type": "gce_subnetwork",
        },
        "timestamp": _iso(received),
    }
    assert set(entry) <= GCP_LOG_ENTRY_KEYS
    return entry


def gcp_records() -> list[dict]:
    """SRC record with Cloud NAT (Pub/Sub data wrapper), DEST firewall drop (bare LogEntry)."""
    vm = {
        "project_id": GCP_PROJECT,
        "region": "us-central1",
        "vm_name": "atlas-orders-1",
        "zone": "us-central1-c",
    }
    vpc = {
        "project_id": GCP_PROJECT,
        "subnetwork_name": "default",
        "vpc_name": "default",
    }
    start = BASE + timedelta(seconds=60, microseconds=594437)
    end = BASE + timedelta(seconds=65, microseconds=614528)
    received = BASE + timedelta(seconds=70)
    nat = gcp_entry(
        received,
        {
            "connection": {
                "src_ip": "10.40.1.15",
                "src_port": 44114,
                "dest_ip": "198.51.100.20",
                "dest_port": 443,
                "protocol": 6,
                "nat_ip": "203.0.113.7",
                "nat_port": 40321,
            },
            "reporter": "SRC",
            "start_time": _iso(start),
            "end_time": _iso(end),
            "bytes_sent": "5300",
            "packets_sent": "40",
            "rtt_msec": "12",
            "src_instance": vm,
            "src_vpc": vpc,
        },
    )
    drop_start = BASE + timedelta(seconds=80)
    drop_end = BASE + timedelta(seconds=81)
    drop_received = BASE + timedelta(seconds=90)
    drop = gcp_entry(
        drop_received,
        {
            "connection": {
                "src_ip": "192.0.2.10",
                "src_port": 55188,
                "dest_ip": "10.40.1.15",
                "dest_port": 22,
                "protocol": 6,
            },
            "reporter": "DEST",
            "start_time": _iso(drop_start),
            "end_time": _iso(drop_end),
            "disposition": "DROPPED",
            "drop_reason": "FIREWALL_DENY",
            "bytes_dropped": "120",
            "packets_dropped": "2",
            "dest_instance": vm,
            "dest_vpc": vpc,
        },
    )
    rows = [(received, {"data": nat}), (drop_received, drop)]
    return [
        {
            "time": round(when.timestamp(), 6),
            "host": GCP_HOST,
            "source": f"projects/{GCP_PROJECT}/subscriptions/atlas-vpc-flows",
            "sourcetype": "google:gcp:compute:vpc_flows",
            "index": "gcp",
            "event": json.dumps(body, sort_keys=True, separators=(",", ":")),
        }
        for when, body in rows
    ]


def render() -> dict[str, str]:
    return {
        name: "".join(json.dumps(event, sort_keys=True) + "\n" for event in events)
        for name, events in (
            ("pan_traffic.ndjson", pan_records()),
            ("fortigate_traffic.ndjson", forti_records()),
            ("f5_ltm_http.ndjson", f5_records()),
            ("aws_elb_access.ndjson", aws_records()),
            ("azure_vnet_flow.ndjson", azure_records()),
            ("gcp_vpc_flow.ndjson", gcp_records()),
        )
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output-dir", type=Path, default=OUT)
    parser.add_argument(
        "--check",
        action="store_true",
        help="fail if committed fixtures differ from generated output",
    )
    args = parser.parse_args(argv)
    rendered = render()
    if args.check:
        stale = [
            name
            for name, text in rendered.items()
            if not (args.output_dir / name).is_file()
            or (args.output_dir / name).read_text(encoding="utf-8") != text
        ]
        if stale:
            print("stale ecosystem fixtures: " + ", ".join(stale), file=sys.stderr)
            return 1
        return 0
    args.output_dir.mkdir(parents=True, exist_ok=True)
    for name, text in rendered.items():
        (args.output_dir / name).write_text(text, encoding="utf-8")
        print(f"{name}: {text.count(chr(10))}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
