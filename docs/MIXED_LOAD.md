# Mixed-source load correctness

`tools/mixed_pipeline.py` loads deterministic HEC envelopes through the real
local Splunk lab, then runs the installed normalizer, identity/service
builders, conversation rollup, replay, and graph search. It requires
`--reset-lab`; preflight runs before the reset, and a failed preflight cannot
mutate the lab. Failures, incomplete searches, quality warnings, dropped
normalized rows, and attribution mismatches produce a nonzero exit status.

The bounded cases submit 96 flows for `smoke`, 16,000 for `baseline`, and
80,000 for `scale`:

```sh
python3 tools/mixed_pipeline.py --reset-lab --case smoke
python3 -m unittest tests/test_mixed_pipeline.py
```

Each synthetic conversation has four source observations: Stream NetFlow,
Nexus Dashboard flows, FTD eStreamer, and Cilium Hubble, with configurable
observer copies. ND events carry 250 ingress and 250 egress bytes; the
normalizer must use the 250 ingress counter once rather than the TA's raw
`bytes` alias that would double it. FTD carries 120 initiator and 80 responder
bytes. Hubble carries no byte counters.

The graph must retain all source and observer attribution while counting each
distinct client port connection once across observers and replays. Graph bytes
use the largest observer total per edge rather than summing duplicate
observers. NetFlow supplies that maximum in this corpus: 300 bytes multiplied
by the records per pair. ACI
traffic uses Nexus Dashboard flow records; ACL logs are policy observations
with permit/drop counts and no traffic bytes.
