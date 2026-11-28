# ADM customer meeting field guide

Use one user action per walkthrough. Before the meeting, test the saved view in the target ADM installation with its qualified scope and time window. Open the evidence panel and check that its data still loads for the saved scope and time. Capture the selected evidence in ADM for offline use. Label each screenshot with its recorded window. If a saved view has lost its source data, keep the screenshot labeled as recorded evidence and use a fresh, verified link when available. Keep customer screenshots and evidence in the approved workspace for that deployment.

## Did the Save reach the database?

A user opens an invoice, edits it and clicks **Save**. In **Trace**, follow the browser to the web proxy, the selected application instance, the database proxy and PostgreSQL. Select the routed leg and compare the request and reply observations. Select the commit and confirm that the detail identifies an independently observed database write. Proxy logs can connect distinct sockets to one request. Save a separate Trace link for each TCP leg with its absolute window, scope, and both ports. Open each link and confirm it selects the intended evidence. The route is verified only at the points with matching evidence.

Use the committed Save as the acceptance check for maintenance. Capture the routed leg and the selected commit detail.

## Who was talking through the leaf?

A network engineer checks a leaf after a user reports slow responses. Open **Explore → Device**, choose the exporter and set a short window with recent indexed records. Read the peer addresses, direction and available ingress and egress interfaces. Preserve unknown interfaces where the exporter omitted them.

Choose a conversation the network team can investigate in Trace. Capture the device summary and the displayed conversations.

## What should the application owner check before maintenance?

An application owner clicks **Save** on an invoice draft. Open **Services** for that observation window. Select the Save handler and follow its database calls through the database proxy to shared PostgreSQL. Inspect each edge for the same-trace spans and matching sockets that support it.

A separate form-read map can show dependencies for opening the invoice. Use the recorded Save in **Trace** to verify browser ingress, observed forwarding and the database commit.

Confirm which other application instances need testing when a shared backend changes. Capture the map, its scope and the selected edge.

## Did security policy block the connection, or did the application fail?

A user reports a timeout. Trace the failing tuple and a known-good control in their respective windows. Select the enforcement or endpoint response and confirm the location and reason. A positive policy denial supports escalation to the policy owner. A rejected HTTP request after verified TLS supports escalation to the application owner.

Capture the control and the relevant selected detail. Label any unverified application response in the caption.

If the lab has a qualified Cisco Nexus Smart Switch replay, start with a user reporting an SSH timeout. Open the saved **Trace** and select the DPU observation labeled **SYN returned**. The network team can verify that the exact connection attempt reached the DPU. The application team still needs evidence of the server response, and the security team needs a matching enforcement record to assign a verdict. Capture the selected DPU observation and label the SSH response as unverified when the evidence ends at the returned SYN.

## Can users still save if a leaf goes out of service?

A billing analyst saves an invoice during a recorded test window. Open **Impact → If this fails** with the qualified Save cohort. Select one leaf, record the counts, then add the second leaf. Read exposed samples, confirmed remaining samples and samples with incomplete evidence. Use the recording of actual maintenance to show whether a Save committed during the controlled isolation.

Choose what to validate in the maintenance window. Capture both selections with the same cohort and scope.

## Which conversations should the engineer inspect first?

A network engineer opens **Device** for a busy exporter and sorts the displayed conversations by **Flows**. Read the selected time window, the number of records sampled and any result cap. Choose a high-count conversation and open it in Trace.

Use the ranked sample to prioritize inspection. Capture the sorted table with the window and cap visible.

## Is it a transport, TLS, routing, or application issue? (Protocols hub)

Open **Protocols** to see **Multicast / IGMP** alongside 13 scoped, on-demand protocol workbenches (zero searches run on page load). Click **Load traffic mix** for an on-demand protocol and IPv4/IPv6 share breakdown, then open the lens matching the symptom:

- **TCP Health & TLS** for Client vs Server RTT p95, retransmits, resets, and expired or legacy TLS posture (`stream:tcp`, or truthful **Not covered** NetFlow fallback).
- **Routing Control Plane**, **L2 Control Plane**, **Interface & Link Health**, and **State-Change Timeline** for BGP/OSPF/BFD adjacencies, STP/LACP/LLDP state, admin/oper link mismatches and windowed RMON deltas, and deduplicated switch faults/syslog.
- **HTTP & DB Transactions** for HTTP and SQL golden signals from Splunk Stream or OpenTelemetry (`otel:traces`) without ever projecting SQL query text or cookies.

Use each lens's URL-synced filter bar (`Source IP`, `Dest IP`, `Port`, `A↔B`, `Device`, `Interface`), instant client-side table search, `15m`/`30m`/`60m` UTC window presets, and drawer **Focus flow** pivot to narrow busy scopes below the per-search row cap. Switch to **Matrix** to view `Client × Server` or `Device × Peer` grids with adjacency overlays.

## Kubernetes topology reference

When the demo includes a Kubernetes workload, show the client-facing Gateway and the serving nodes alongside their physical attachments. Label HTTPRoute backends as configured dependencies. Use matching firewall, host or Hubble observations to confirm individual segments for the selected request. Mark where coverage ends and record any translation boundary where the tuple changes. [Kubernetes telemetry setup and verification](../operators/kubernetes-platform.md)

For a Kubernetes health request, open the request and reply Traces side by side.
Select the last verified switch in each direction and compare its ingress and
egress ports. Use the first unverified handoff in the direction that matches
the reported symptom to decide where to collect next.
