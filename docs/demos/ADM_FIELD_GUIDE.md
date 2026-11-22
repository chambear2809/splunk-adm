# ADM customer meeting field guide

Use one user action per walkthrough. Before the meeting, test the saved view in the target ADM installation with its qualified scope and time window. Capture the selected evidence in ADM for offline use. Label each screenshot with its recorded window, and use a fresh view for current traffic when the original source has expired. Keep customer screenshots and evidence in the approved workspace for that deployment.

## Did the Save reach the database?

A user opens an invoice, edits it and clicks **Save**. In **Trace**, follow the browser to the web proxy, the selected application instance, the database proxy and PostgreSQL. Select the routed leg and compare the request and reply observations. Select the commit and confirm that the detail identifies an independently observed database write. Proxy logs can connect distinct sockets to one request. The route is verified only at the points with matching evidence.

Use the committed Save as the acceptance check for maintenance. Capture the routed leg and the selected commit detail.

## Who was talking through the leaf?

A network engineer checks a leaf after a user reports slow responses. Open **Explore → Device**, choose the exporter and set a short window with recent indexed records. Read the peer addresses, direction and available ingress and egress interfaces. Preserve unknown interfaces where the exporter omitted them.

Choose a conversation the network team can investigate in Trace. Capture the device summary and the displayed conversations.

## What should the application owner check before maintenance?

An application owner opens the invoice form. Open its **Services** map and select the entry service and the downstream database dependency. Identify shared backends and inspect each edge’s evidence. Where a database proxy stands between the app and database, compare the application spans with independently correlated sockets.

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

## Kubernetes topology reference

When the demo includes a Kubernetes workload, show the client-facing Gateway and the serving nodes alongside their physical attachments. Label HTTPRoute backends as configured dependencies. Use matching firewall, host or Hubble observations to confirm individual segments for the selected request. Mark where coverage ends and record any translation boundary where the tuple changes. [Kubernetes telemetry setup and verification](../operators/kubernetes-platform.md)
