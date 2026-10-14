# Isovalent Enterprise Hubble export sample

A real Hubble flow export from an ephemeral Isovalent Enterprise lab, shared on 2026-10-14. Unlike `fixtures/raw*/`, these events are not synthetic. They validate `adm_flows_hubble` against the Enterprise export format (`tests/splunk/test_hubble_enterprise.py`) and are never loaded by the scenario suites.

| Property | Value |
| --- | --- |
| Emitter | Hubble `1.19.5-cee.1+g683ceb6f` |
| Node | `k8s-01/k8s-01-wkr-02` (one node) |
| Window | 2026-10-14T15:28:37.602Z → 15:30:09.479Z (92 s) |
| Records | 1,589 JSON lines, `{"flow":{…},"node_name":"<cluster>/<node>","time":…}` |
| Original SHA-256 | `3ad2dbe268ae0eed77446fa6c4e1fd9a8c72e9dfc35c86d907fa2bdeb0a3daa8` |
| Redacted SHA-256 (this file) | `47aedf2208e5966fa4b9b8885344bdc651b7bad2761948627024244a8262b764` |

## Changes from the original

The file was renamed from `enterprise-hubble.log` to `.ndjson`; it was already one JSON object per line. The values of the 15 HTTP `Authorization: Basic` headers (Elasticsearch calls in `tenant-jobs`) were replaced with `Basic [REDACTED]` by exact text substitution. No other byte was changed, so field extraction matches the original. The parser does not read `Authorization`.

## What the sample establishes

- **Format.** The Enterprise export uses the same JSON-lines envelope and `flow.proto` field names as the open-source exporter that `adm_flows_hubble` parses.
- **Event types.** `event_type.type` is 4 for traces, and `sub_type` is the observation point: TO_NETWORK 11, TO_STACK 3, TO_PROXY 1. The `sub_type` is omitted when it is 0 (TO_ENDPOINT), so parsing must use `trace_observation_point`. Other types: L7 is 129 with no `sub_type`, policy drops are 1/133 (`POLICY_DENIED`), policy verdicts are 5, and socket traces (`Type` SOCK) are 7.
- **L7 direction.** L7 REQUEST and RESPONSE are both `INGRESS`; `is_reply` separates them. These pod-to-pod requests carry no `X-Forwarded-For` and no `trace_context`, so `adm_flows_hubble` drops them by design.
- **SNAT.** None of the 453 TO_NETWORK traces has `IP.source_xlated`. This window holds no NodePort or SNAT traffic, so SNAT trace export and aggregation remain unconfirmed.
- **Bytes.** No flow carries byte counts.
- **Replies.** Every TO_ENDPOINT flow has `is_reply`; 43 of the 600 forwarded ones are replies.

## Splunk lab validation

The real redacted lines are wrapped unchanged as HEC event bodies with sourcetype `cilium:hubble:flow` and index `cilium_hubble`. All 1,589 events index successfully. `adm_flows_hubble` returns 557 `conv` records, zero `xlate` and zero `l7`, matching the Python reference classifier. Conversation 5-tuples and JSON field counts match the sample; observer is `k8s-01-wkr-02` and cluster scope observer is `k8s-01`.

The sample's nanosecond `flow.time` values parse into `adm_start` within 1 ms using the existing `adm_iso_time`; no timestamp parser change was needed. `adm_flows_hubble_enterprise` now points to `adm_flows_hubble`. The combined `adm_flows` search already includes Enterprise records through that shared parser; do not append the alias separately.

Still unconfirmed: Enterprise SNAT `TO_NETWORK` traces with `IP.source_xlated`, including monitor aggregation behavior, and Envoy L7 IPs/X-Forwarded-For. There is no NodePort, SNAT, Gateway or Ingress traffic in this window.
