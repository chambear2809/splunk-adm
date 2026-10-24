# Networking SE demo: follow a client to its application

**Audience:** network architects, campus/DC operators and segmentation teams. **Time:** 20 minutes, or 25 with the optional endpoint/DNS segment. **Outcome:** show how attachment, traffic and application evidence answer different parts of a connectivity question and give teams a reviewable handoff.

Complete the [presenter setup](README.md#presenter-setup). Keep these two bookmarks ready:

- [Catalyst wired → ACI](http://127.0.0.1:5173/applications?mode=demo&scenario=catalyst-aci)
- [Meraki MR wireless via MS390 IPFIX → NXOS](http://127.0.0.1:5173/applications?mode=demo&scenario=meraki-nxos)

## Opening — 0:00–2:00

**Say:** “A user reports trouble reaching checkout. We need to identify the client's attachment, the application conversations we observed, and the infrastructure context available for those conversations. This is a synthetic dataset with fixed historical windows. I will show the supporting evidence and where it stops.”

**Ask:** “When that ticket arrives today, which teams have to exchange an IP, switch port, application name and timestamp before someone can investigate?” Use their answer to emphasize campus, DC or segmentation during the walkthrough.

## Wired client into ACI — 2:00–8:00

| Do | Expected result | Say |
| --- | --- | --- |
| Open the Catalyst bookmark. In **Find an address, EPG, or device**, enter `10.61.0.20` and click **Find**. | A matching `checkout` application and client attachment evidence. | “We can begin with the address from the ticket and locate a related application where bindings and captured traffic support that relationship.” |
| Click **Open map for checkout**. Verify `checkout`, environment `demo`, cluster `cilium-aci-east`, namespace `shop`, and the synthetic label. | Captured map window October 18, 2026, 03:35–03:55 UTC, displayed in the browser's timezone. | “Routing scope and time matter. The same private IP in another network or at another time must not become this client.” |
| In **Network**, use **Highlight by name, IP, EPG, port or device** with `02:61:00:00:00:20`. Select that **Network client** MAC card and read **Details**. Do not select the separate **Unknown IP 10.61.0.20** card for attachment details. | MAC `02:61:00:00:00:20`; Source `wired`, Evidence basis `catalyst_client_snapshot`, routing domain `20`, device `CAMPUS-SW-01`. Scope `campus-aci` appears in the Traffic observations below. | “The controller supplies an observed attachment snapshot. It tells us where this client was reported, with source and time attached.” |
| Point out **Source event time**, **Received time** and the snapshot explanation in Details. | October 18 UTC: source event `03:39:04Z`, receipt `03:39:05Z`; the inspector formats these in local time. | “For this Catalyst snapshot, lastUpdatedTime is freshness information. Attachment is observed from receipt time onward; we do not backdate it to the source timestamp.” |
| Clear the highlight. Select the conversation from `10.61.0.20` to `checkout-api · 10.50.0.20:8080`; use **Table** to locate/select it if lines overlap. | One captured connection with Hubble/ND evidence. Client-specific `hubble_client_tuple` evidence links to `checkout-5f8b9c7d6-m4n7q` on `node-b`. | “The traffic establishes a conversation. Compatible client-specific handoff evidence supports this backend mapping. A Service inventory entry alone would not prove which pod served the client.” |
| Where available, click **Show candidate path** in the connection inspector, then open **Devices** and locate **Client attachment devices**. | Inventory-based candidate path and the controller attachment reference. | “This helps us choose where to investigate next. Inventory connectivity is a candidate path; it is not a captured packet-hop sequence.” |

Do not change the scope or time picker to today's window. The captured map is fixed. If the connection is difficult to select, use Table and the client/server tuple rather than narrating an unselected line.

## Separate exporter observations — 8:00–10:00

Return to **Network**, highlight `02:61:00:00:00:20`, select that **Network client** card and scroll its **Details** to **Traffic observations (3)**. This aggregates the three incident observation edges. The core IP-to-Service conversation selected earlier has no Stream observations; **Table** lists conversations and cannot select these separate observation edges. Locate the Stream observations by exporter:

| Exporter | Captured context |
| --- | --- |
| `192.0.2.102` | Standard exporter observation |
| `10.61.255.1` | Catalyst SD-WAN, observation domain `701`, routing domain/VPN `20` |
| `10.61.255.2` | Campus Flexible NetFlow, observation domain `601` |

**Say:** “Several collection points can describe related traffic. Their provenance stays visible. These examples retain unknown sampling and counter semantics and are nonauthoritative; adding them together would overstate what we know. SD-WAN references here do not establish tunnel or router topology.”

If time is short, show one observation and move on. Avoid turning record counts from different observers into a count of unique connections.

## Wireless client into NX-OS — 10:00–15:00

| Do | Expected result | Say |
| --- | --- | --- |
| Open the Meraki bookmark. Find `10.71.0.20`. | `checkout`, attachment evidence for both `MR-NXOS-01` and `MR-NXOS-02`, `meraki_association_event`, and unresolved evidence. | “This example deliberately prevents a convenient but unsafe answer: an IP alone does not identify one wireless client.” |
| Inspect the available client evidence and its event times. | Among the observations: MAC `02:71:00:00:00:20` associated with `MR-NXOS-02` at `03:41:04Z`; MAC `02:71:00:00:00:21` with `MR-NXOS-01` at `03:42:34Z`. The `.20` client also has an earlier `MR-NXOS-01` association; these are not unique permanent attachments. | “These are source observations with different client identities and event times. We preserve that ambiguity instead of assigning every flow to one station.” |
| Click **Open map for checkout**; verify cluster `cilium-nxos-west`. Select the client-to-`checkout-api` conversation, then **Devices → Client attachment devices**. | Application conversation evidence and MR attachment context remain inspectable. | “The application view and attachment evidence help the campus and DC teams discuss the same incident without claiming a complete wireless packet path.” |
| Return to **Network**. Highlight and select the **Network client** card `02:71:00:00:00:20`; read **Details → Traffic observations**. Repeat for `02:71:00:00:00:21`. | Each card shows its own MS390 observation from exporter `10.71.0.2`, domain `390`: `.20` has 1,280 bytes / 4 packets; `.21` has 860 bytes / 3 packets. Counter authority and sampling limitations remain. | “The switch exporter observes traffic. The association events provide wireless context. Neither proves RF health, airtime, roaming success or the cause of the user's problem.” |

Do not describe the two MACs as a proven roam by one device or merge their counters into a unique application total.

A MAC card can show **No calls or conversations in this time range** beneath its observations. That message concerns core conversation edges incident to that card; it does not erase the separate exporter observations just inspected. Use the IP-to-Service conversation for the core traffic/handoff step.

## Reviewable handoff — 15:00–18:00

1. Clear the highlight and reset any filters. Open **Export**.
2. Choose **Required flows (CSV)** for a conversation review. Say: “This is an observed-flow review artifact, not a generated or enforced firewall policy. We still need representative windows, owner review and change control.”
3. Reopen **Export** and choose **Context evidence (CSV)** for client attachment and traffic-observation provenance. Explain that the recipient can examine source and scope without treating attachment as traffic.
4. Reopen **Export** to show **Map data (JSON)** as the full loaded graph; the menu closes after each CSV/JSON download. Explain that CSV/JSON map exports are not reduced by visual focus/highlight. To show **Map image (PNG)**, first return to **Network** or **Services**; the image option is disabled in Devices/Table. It captures the visible map presentation.

Downloads stay local until the presenter explicitly shares them. DNS is a separate explicit evidence export if the optional segment is used.

## Close — 18:00–20:00

**Say:** “We started with a client address, found an application relationship, inspected source-specific attachment and traffic, and produced an evidence handoff. The next step is a bounded pilot around one application and one routing scope, using sources your team already owns.”

**Ask:** “Which application and ticket type should we reproduce? Who owns the client attachment feed, flow exporters, routing mappings and application identity? Which missing evidence would change your next action?”

Record the chosen scope, source owners, representative time window and desired decision. Use the [networking operator guide](../operators/cisco-enterprise-networking.md) for a separately planned setup; this demo does not activate V2 or change collection.

## Optional branches

- **VMs or no Kubernetes catalog:** run the [five-minute endpoint/DNS segment](README.md#optional-endpoint-and-dns-segment--5-minutes). Emphasize the scoped-IP starting point and one-hop traffic table. Describe the fixture as a mock UI demonstration before opening it.
- **ACI policy discussion:** open the [ACI pilot bookmark](http://127.0.0.1:5173/applications?mode=demo&scenario=aci), choose **Open map for frontend**, and use the **Blocked conversation → Show path** finding for `win-client-01 → orders-db-01`. The fabric records a drop at `pod-1/node-103`. The separate **No permitting contract** finding describes collected policy; absence from the collection is not proof that no effective permit exists anywhere.
- **Five-minute version:** Catalyst Find → client Details → checkout conversation → Context evidence export → agree on the pilot scope. Skip scenario switching and DNS.

## Answers to likely questions

| Question | Answer |
| --- | --- |
| Does this prove the packet route? | No. Observers, attachments and candidate inventory paths are distinct evidence. Missing hop order stays unknown. |
| Does it diagnose why checkout is slow? | It supports investigation. A blocked record, DNS outcome or attachment event alone is not a causal diagnosis. |
| Does it work with overlapping IP ranges? | Correlation needs explicit routing scope and source authority. Scope is attribution context, not an access-control boundary. |
| Can we use the CSV directly as segmentation policy? | Use it for review. Observation coverage, sampling, omitted periods and security policy still need validation. |
| Is this qualified for our controllers/exporters? | Synthetic TA-shaped examples establish demo behavior. Review exact versions, genuine samples and target qualification before making a support claim. |

For recovery and reset, use the [presenter troubleshooting table](README.md#troubleshooting-and-cleanup).
