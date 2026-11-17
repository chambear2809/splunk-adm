# Sanitized source replay sample

This fixture contains a bounded head sample of four Hubble flow rows and four
pod rows observed in a source session. It is transformed, not untouched source
data: identifiers and addresses are consistently replaced, fields outside an
allowlist are omitted, and timestamps are shifted together. Documentation
address ranges do not preserve routing or address-class semantics. The
manifest records the sample digest, selection bounds, transformation review,
and the source-session observations; it does not establish the origin or
version of the upstream emitters.

Run `python3 -m unittest tests.test_source_replay_fixture` to revalidate the
profile and replay the rows through the production Hubble normalizer and pod
shape parser. The checks compare observation payloads and independently inspect
tuples, clocks, observer, protocol, verdict, direction and reply flags. They
also verify that altered provenance, observer, cluster and clocks are excluded.
Paired pod condition values and repeated pseudonymous UIDs are shape evidence,
not proof of complete ownership intervals or an association with a flow.

The head sample has unknown completeness and is not representative coverage or
a qualified dependency baseline. No identity graph or cross-source association
is fabricated from it. This parser-level replay does not qualify protected case
capture, source continuity, maintenance readiness, application health, physical
paths, incident causation, selected-client handoff, or installed production
behavior. See the manifest for the recorded limitations.

The sanitizer's observation-point enum allowlist was checked against the
[upstream Hubble protobuf contract](https://raw.githubusercontent.com/cilium/cilium/main/api/v1/flow/flow.proto)
on 2026-11-17 UTC. This is a source-contract reference, not verification of the
deployed emitter version.
