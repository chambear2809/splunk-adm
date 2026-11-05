# ACI spine path evidence

Spines cannot export NetFlow. Atlas therefore never marks a spine "Seen"; spine hops are inferred and annotated with evidence.

## Why spines have no NetFlow (APIC 6.1)

| Attach point | Exists on | Notes |
| --- | --- | --- |
| Bridge domain (`fvRsBDToNetflowMonitorPol`) | Leaf | Tenant traffic |
| Leaf access policy group (`infraRsNetflowMonitorPol`) | Leaf | |
| L3Out logical interface profile | Leaf | No L3Out on a spine |
| Spine access port group (`infraSpAccPortGrp`) | — | No NetFlow relation |
| Exporter node relation | Leaf `topSystem` only | Spines carry no `topRtExporterToTopSystem` |

Source: APIC on-box model (`/doc/jsonmeta`). Not cross-checked against the Cisco configuration guide (unreachable from the lab).

## What Atlas uses instead

| Evidence | Class / source | Meaning |
| --- | --- | --- |
| Overlay adjacency | `isisAdjEp` (`operSt=up`), peer resolved via `fabricLink` | The leaf–spine link is up |
| COOP record | `coopEpRec` on spines | The spine knows the destination endpoint's leaf TEP |
| Topology | `fabricLink`, `lldpAdjEp`, `topSystem` | Candidate spines (ECMP) |

Rules (`adm_fabric_path_evidence`, `pathTrace.ts`):

- Same leaf or vPC pair at both ends: no spine hop.
- Different leaves: spine hop shown as "inferred". Narrowed to spines with an up adjacency from the source leaf **and** a COOP record for the destination MAC. If none qualify, all candidates stay with a note.
- ECMP chooses the spine per flow. Only iTraceroute names it, and its results are deleted with the policy (`freq=one-shot`). A continuous classInfo input cannot collect them.

## Enable

Add `isisAdjEp coopEpRec` to HF `classInfo_adm`; keep `fabricLink lldpAdjEp`. Procedure: [ACI_VMM_ADJACENCY_CLASSES](ACI_VMM_ADJACENCY_CLASSES.md).

## Optional: on-demand iTraceroute

Operator-run only, for a single disputed flow. Create `trEp` / `trEpExt` policies, read `tracerouteRsltTn` / `traceroutePath` / `tracerouteNode` on the leaf, then delete the policies and confirm the counts return to 0. Atomic counters (`dbgacEpToEp`, `dbgacEpgToEp`) are leaf-only and never name a spine.

## Lab record (2026-11-03)

- No NetFlow change made. Existing monitor is bound to two BDs only; `nodecontrol-default` (`featureSel=netflow`) is bound to leaf and spine policy groups. No spine exporters seen in `stream:netflow`, as expected.
- iTraceroute, endpoint pair on one vPC: path is local to each leaf — no spine hop. Atlas must not mark spines for such flows.
- iTraceroute, endpoint to external: from the non-border leaf the internal hop was a spine; from the border leaf it was local.
- Both temporary policies deleted; nothing to roll back.
