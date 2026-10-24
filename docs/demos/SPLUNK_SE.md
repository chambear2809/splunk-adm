# Splunk SE demo: turn indexed evidence into an investigation

**Audience:** Splunk platform owners, observability teams and technical evaluators. **Time:** 25 minutes. **Outcome:** show application discovery, transparent evidence contracts, explicit exports, optional endpoint/DNS investigation and a realistic path to a scoped pilot.

Complete the [presenter setup](README.md#presenter-setup), including the second server for the endpoint/DNS segment. Start at the [ACI application catalog](http://127.0.0.1:5173/applications?mode=demo&scenario=aci). Keep the [data contract](../DATA_LAYER.md), [operator setup sequence](../operators/splunk-setup-guide.md) and [DNS operations](../operators/dns-evidence.md) open for technical discussion.

## Establish the question and data boundary — 0:00–2:00

**Say:** “The question is which systems communicate with an application, how we know, and what evidence the next team needs. Atlas runs in Splunk and combines indexed traffic with time- and scope-aware identity. Today's application views replay synthetic search results; the later endpoint view uses a mocked search client. No customer data or live Splunk queries are involved.”

**Ask:** “Which of your existing traffic, Kubernetes, trace or controller feeds could help answer that question today, and where does the handoff between teams break down?”

## Discover and inspect an application — 2:00–7:00

| Do | Expected result | Say |
| --- | --- | --- |
| Show **Applications** and locate the `frontend` row. | Environment `demo`, cluster `demo-cluster`, namespace `shop`, two bound pods; catalog columns include last completed hour. | “Application identity comes from retained bindings. Catalog metrics describe the row's completed hour, not an arbitrary current map window.” |
| Enter `10.20.30.40` in **Find an address, EPG, or device** and click **Find**. Inspect the captured matching application result. | One match: `checkout`. Its **Open map for checkout** button is disabled because this ACI dataset only includes a `frontend` map capture. Use the next step to open that capture. | “Find can start with a known address or network context when application bindings support the relationship. It is not an unrestricted asset search.” |
| Return to the ACI start bookmark and click **Open map for frontend**. | Synthetic map for October 7, 2026, 11:45–12:00 UTC: five services, 17 conversations, one external and one blocked. | “The selected namespace defines the map's application boundary. These displayed counts come from this captured graph; do not add catalog counts or separate exporter observations to them.” |
| Select **Services**, then **Network**. Select `orders-db-01` (`10.20.30.40`) and inspect Details. Use **Table** for the accessible conversation list. | Service/application context, VM dependency and individual conversations can be inspected from the same graph. | “Identity and traffic are complementary. Unknown or ambiguous identity remains visible instead of being guessed from an address.” |
| Return to an unselected Network view or reopen the map. Under **Blocked conversation**, click **Show path**. | `win-client-01 → orders-db-01`, with an ACI drop at `pod-1/node-103`. | “A finding links back to its evidence. The separate collected-policy finding has a different meaning from a recorded drop.” |

**Open in Search** is deliberately disabled for synthetic captures. Explain the live drilldown purpose without clicking into an unrelated Splunk instance or claiming a native search ran.

## Explain the Splunk implementation — 7:00–11:00

Use the data contract as a reference beside the map. This is a source/architecture explanation, not a live search exercise:

| Layer | Explain | Show or reference |
| --- | --- | --- |
| Raw data | Customers own collector configuration, indexes, routing mappings, retention and access. A supported source must supply the fields the contract requires. | [Source/operator guides](../operators/README.md); fixture field provenance in `fixtures/raw-aci/FIELDS.md`. |
| History and summaries | Scheduled jobs maintain scoped identity/binding history and conversation summaries. Time-valid ownership prevents a reused pod IP from becoming a permanent identity. | [Data layer](../DATA_LAYER.md); `splunk_app/splunk_adm/default/savedsearches.conf`. |
| On-demand map | `adm_graph(service, environment, cluster, namespace)` returns node, edge and metadata rows; `adm_topology` supplies collected inventory for candidate paths. Client validation rejects broken graph contracts. | [Macro definitions](../../splunk_app/splunk_adm/default/macros.conf) and [captured ACI rows](../../fixtures/demo-rows-aci.json). |
| Application discovery | The catalog and Find use retained bindings and observed relationships. Traffic alone need not populate the application catalog. | The catalog window label and matching Find result just shown. |
| Endpoint investigation | A separate bounded scoped-IP query can start without trace/Kubernetes application entry points. It needs configured summaries, verified scope and caller access. | The optional endpoint segment below. DNS is supplemental and is not a prerequisite for its traffic table. |

**Say:** “A graph snapshot identifier identifies a client capture. It is not an atomic Splunk snapshot across all searches. Source timestamps, observation intervals and retrieval times remain meaningful independently.”

If asked for runnable SPL, use the exact active-contract query documented for a separately prepared, authorized lab and its recorded synthetic window. Do not paste the V1 macro into an unverified V2 deployment or run a broad raw-data search during this captured demo. The [pilot guide](../PILOT.md) describes lab preparation and its lock; starting it is not part of this script.

## Compare and export evidence — 11:00–14:00

1. On the ACI map, open **Changes → Compare previous window**. The ACI fixture includes an earlier 11:30–11:45 UTC capture. Expect one connection added, zero removed and 12 changed. Point out the comparison result without equating added/removed observations with a configuration change or a causal diagnosis. Click **Close changes** before continuing. Other demos need not have a previous capture.
2. Open **Export → Required flows (CSV)**. Explain one row per conversation for review, rather than firewall enforcement.
3. Reopen **Export → Map data (JSON)**; the menu closes after each CSV/JSON download. Explain that it contains the full loaded graph, before visual filters and focus. A PNG communicates the visible Network/Services view; JSON preserves structured evidence.
4. Explain **Saved views** as browser-local scope and display preferences. They do not retain a Splunk data snapshot or DNS evidence. Do not promise that reopening a view reproduces the same live results after retention or source changes.

**Say:** “The handoff is useful because its scope, time and evidence basis are explicit. A convenient picture is not a substitute for those details.”

## Scoped endpoint and optional DNS — 14:00–19:00

Run the [five-minute endpoint/DNS sequence](README.md#optional-endpoint-and-dns-segment--5-minutes) exactly as written: prefilled `192.0.2.10` in scope `prod` → **Investigate** → one-hop table → **Inspect DNS evidence** → limitations → explicit export → simulated denied source.

Emphasize these Splunk-specific points while the results are visible:

- The Stream DNS row and Hubble traffic row are different evidence types. The harness's Hubble DNS adapter is unselected. Do not describe it as a two-source DNS demo.
- Source `complete` means a retrieval completed under its envelope; the visible unqualified schema/clock/answer relationships still restrict interpretation.
- DNS query names do not create application ownership, server membership, backend selection or a successful connection. Genuine retries and search-suffix queries must not be collapsed as duplicate exports.
- DNS is on demand; there is no scheduled DNS history builder. Its failure or absence leaves valid traffic evidence available.
- Endpoint and DNS downloads are deliberate separate artifacts. DNS is not silently appended to map exports, saved views or copied URLs.

Use `?fault=dns-only` instead of the denied variant if the audience is likely to confuse resolution with traffic; use `?fault=cap&theme=dark` if the discussion is about completeness. These are mocked outcomes, not measured native job behavior.

## Operational controls and qualification — 19:00–23:00

Return to the normal captured demo tab and open **Data health**. Expect synthetic/unknown health; do not present the capture as a green production readiness check. Show **Setup** only to explain the intended operator workflow; do not attempt to save settings in demo mode.

**Say:** “Core pipeline readiness and optional DNS diagnostics are separate. Collection is customer-owned. Operators enable only the feeds and jobs needed for their chosen questions, and settings writes depend on a qualified deployment.”

Use this checklist to answer technical evaluation questions:

| Topic | Presenter explanation and follow-up |
| --- | --- |
| Access | Searches use the caller's permissions. Routing scope provides attribution, not tenant isolation. DNS names and shared configuration visibility require security review. The shared selector read currently requires `search` plus the broader `list_conf_objects` capability on the tested Enterprise target; a search-only viewer cannot use that selector-dependent endpoint workflow. Do not grant capabilities during the demo. See [DNS prerequisites](../operators/dns-evidence.md#prerequisites-and-access). |
| Safe selectors/drilldowns | New queries compile validated literal configuration and inputs; shared app configuration must not be replaced by user-private macro/lookup shadows. Explain the boundary rather than executing a synthetic exact-source link. |
| V1/V2 | The configured active traffic contract determines summary readers. V2 attachment and traffic-observation context does not silently replace core counts. Accepted quality is required; nonauthoritative observations remain separate. Activation follows the [migration procedure](../CISCO_CONTRACT_MIGRATION.md). |
| Budgets and completeness | Caps, partial results, server deadlines, caller quotas and cancellation/expiry need target checks. A fast browser harness and a 64-row display limit do not establish distributed completion or indexer cost. |
| Enablement | Use the [operator setup sequence](../operators/splunk-setup-guide.md). For DNS, qualify real samples, source authority, verified mappings, clocks, selectors and viewer permissions before selecting a source. Shipped schema flags remain unqualified until that review passes. |
| Recovery | Settings use the supported persistence/ledger contract. Disable optional sources before rollback, preserve the ledger and confirm older-build schema compatibility; follow [DNS rollback](../operators/dns-evidence.md#enable-disable-upgrade-and-rollback) and [upgrades](../UPGRADES.md). |
| Support claims | Historical synthetic Enterprise 10.6.0.5 results apply to their exact packages. Genuine DNS feeds, production capacity, Cloud and distributed DNS qualification remain open. The current working-tree corrections are newer than the existing 0.4.0 archive; see [candidate qualification](../DNS_EVIDENCE_QUALIFICATION.md). |

## Close — 23:00–25:00

**Say:** “We connected indexed evidence to a scoped investigation, kept uncertainty visible, and exported a reviewable result. A useful pilot now needs a specific question, a representative window and named source owners.”

Agree on one application or scoped endpoint, the required traffic/identity sources, a viewer role, and an acceptance criterion such as identifying a database dependency with provenance. Add DNS only if resolution context helps that decision and a source owner can supply sanitized samples and target evidence.

Do not promise a production date or support envelope from the synthetic demo. Record missing feeds, permissions and platform gates as pilot prerequisites.

## Five-minute version and recovery

For a short meeting: Applications → **Open map for frontend** → blocked finding and Details → **Required flows (CSV)** → pilot question. Omit the implementation discussion and separate harness.

If a live-style action is unavailable, stay in the captured flow and explain the boundary. For disabled Find, wrong windows, unavailable health or harness navigation, use the [presenter troubleshooting table](README.md#troubleshooting-and-cleanup). Stop the two preview servers you started with Ctrl-C after the session.
