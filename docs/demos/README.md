# Synthetic demo presenter guide

Choose the script for your audience:

- [Networking sales engineers](NETWORKING_SE.md): a 20-minute client-to-application investigation across Catalyst/ACI and Meraki/NX-OS, with an optional endpoint/DNS segment.
- [Splunk sales engineers](SPLUNK_SE.md): a 25-minute evidence, search-contract and operations walkthrough, including endpoint/DNS behavior.

Both scripts use repository synthetic data. They require no customer credentials, Splunk installation, collector changes or lab lifecycle. Prepare and rehearse before the meeting; these are demonstrations of behavior, not source or deployment qualification.

## Presenter setup

From the repository root, use Node 22.13+ within 22.x, 24.x or 26+, and npm:

```sh
npm ci --registry=https://registry.npmjs.org --ignore-scripts
npm run dev -- --port 5173 --strictPort
```

Leave the terminal running. Open the appropriate bookmark:

| Scenario | Start URL | Captured map window (UTC) |
| --- | --- | --- |
| ACI pilot fabric | <http://127.0.0.1:5173/applications?mode=demo&scenario=aci> | October 7, 2026, 11:45–12:00 |
| NX-OS fabric | <http://127.0.0.1:5173/applications?mode=demo&scenario=nxos> | October 7, 2026, 11:45–12:00 |
| Catalyst wired → ACI | <http://127.0.0.1:5173/applications?mode=demo&scenario=catalyst-aci> | October 18, 2026, 03:35–03:55 |
| Meraki MR wireless via MS390 IPFIX → NXOS | <http://127.0.0.1:5173/applications?mode=demo&scenario=meraki-nxos> | October 18, 2026, 03:35–03:55 |

The map header may render local time. Keep the captured scope and window. **Build map** is intentionally disabled in demo mode. Catalog metrics use each row's last completed hour, which can differ from the map window. Find accepts only the captured queries listed beneath its input.

In Applications, use **Demo scenario** to switch datasets. On a map, use **Map settings → Demo scenario**, then **Close settings**. Only scopes with a captured map have an enabled **Open map for …** button. Open the start bookmark again to recover the intended scenario and scope; clear any remaining highlight or filters and close Details if necessary.

Before presenting:

1. Open your script and start bookmark in separate tabs. Confirm the synthetic label and expected application scope.
2. Rehearse the Find query, map, Details and export menu. Download one sample export locally if you intend to show its contents.
3. If using endpoint/DNS, start the second server below and rehearse its separate bookmark. It is not one of the captured map scenarios.
4. Keep [qualification status](../ATLAS_FINAL_QUALIFICATION.md), [Cisco source limits](../CISCO_NETWORKING_QUALIFICATION.md) and [DNS qualification](../DNS_EVIDENCE_QUALIFICATION.md) available for technical questions.

## Optional endpoint and DNS segment — 5 minutes

This segment uses the real UI components with a mocked search/configuration client and synthetic Stream DNS. It demonstrates rendering, interpretation and failure isolation. It does **not** execute Splunk searches, demonstrate genuine DNS collection, qualify Hubble DNS, or measure native completion/cancellation or performance. Tell the audience this before switching tabs. The fixture deliberately retains unqualified-schema warnings.

In a second terminal at the repository root, with dependencies already installed:

```sh
npx --no-install vite --config tests/browser/vite.config.ts --host 127.0.0.1 --port 4173 --strictPort
```

Open <http://127.0.0.1:4173/tests/browser/dns-evidence.html>. The harness changes the address bar to a Splunk-shaped path. **Use the original harness bookmark for every reset or fault change; do not reload the rewritten path.** Peer links and exact-source drilldowns are not a working native Splunk demonstration here.

| Step | Do | Expected result and talk track |
| --- | --- | --- |
| 1 — Scope | Keep IP `192.0.2.10`, verified routing scope `prod` and both prefilled times; click **Investigate**. | A one-hop diagram and **Observed one-hop conversations** table show peer `198.51.100.20`, TCP/443, source `hubble`, observer `hubble:worker`, one record and one represented connection. “An endpoint investigation can start from a scoped IP without a Kubernetes application catalog. These are observed conversations; observation times are not necessarily connection-opening times.” |
| 2 — Supplemental evidence | Click **Inspect DNS evidence**. | **DNS resolution observations** shows `api.example.test.`, client `192.0.2.10`, resolver `192.0.2.53`, source `dns_stream` / `sensor-east`, and measured latency `0.025 seconds`. Hubble DNS is `not_selected`. “Resolution adds context to an investigation; it does not create the traffic edge.” |
| 3 — Inspect limitations | Point out supplied address `198.51.100.20`, unpaired TTL `120`, and the attribution/limitations column. | `producer_schema_unqualified`, ambiguous answer/TTL relationships and unknown clock basis remain visible. “A matching address and name do not prove that this connection used that name or selected a particular backend. An operator flag cannot reconstruct missing record relationships.” A `complete` source result describes this mocked retrieval, not schema qualification. |
| 4 — Deliberate exports | Click **Export loaded DNS JSON** or **Export loaded DNS CSV**; separately show **Download endpoint JSON/CSV**. | DNS files are `atlas-dns-evidence.json` / `.csv`; endpoint files are `endpoint-investigation.json` / `.csv`. “Exports are explicit. DNS evidence has its own retrieval time and configuration context; it is not silently added to application-map exports.” |
| 5 — Failure isolation | Open the denied bookmark below; click **Investigate**, then **Inspect DNS evidence**. | DNS reports unavailable while the conversation table remains. “An optional source failing does not erase valid traffic evidence.” This is simulated access denial, not a live role test. |

Choose one additional variant if useful; always click **Investigate**, then **Inspect DNS evidence**:

| Bookmark | Expected result | Point to make |
| --- | --- | --- |
| <http://127.0.0.1:4173/tests/browser/dns-evidence.html?fault=denied> | DNS unavailable; conversation remains | Caller-visible evidence can be incomplete. |
| <http://127.0.0.1:4173/tests/browser/dns-evidence.html?fault=dns-only> | DNS row and root endpoint; no conversation edge | A DNS query is not proof of traffic to an answer. |
| <http://127.0.0.1:4173/tests/browser/dns-evidence.html?fault=off> | Both DNS sources `not_selected`; traffic remains | Optional DNS is independently selected. |
| <http://127.0.0.1:4173/tests/browser/dns-evidence.html?fault=cap&theme=dark> | 64 visible DNS records and “This is a capped subset.” | A display cap is not a complete history or a bound on indexer scan cost. |

Do not turn a synthetic latency value or fast local render into a performance claim. The harness has a `slow` mode for UI cancellation, but it cannot demonstrate native job cleanup; omit it from a native cancellation claim.

## Troubleshooting and cleanup

| Symptom | Presenter action |
| --- | --- |
| Port already in use | Check whether your own preview is already running. Otherwise choose a free port and update the bookmarks. Do not stop an unknown process. |
| Find disabled or no captured result | Use the exact IP in the selected script. The captured query list is authoritative; arbitrary customer addresses cannot work in this demo. |
| Wrong application, empty view or unexpected counts | Reopen the start bookmark, use the enabled map button, clear highlights/filters and verify the captured header. Avoid comparing catalog-hour metrics directly with map-window counts. |
| Open in Search disabled | Expected in captured demo mode. Show provenance/Details or an explicit export; do not switch to a customer search to manufacture a result. |
| Endpoints from the normal navigation asks for live data | Use the separate harness bookmark for the synthetic endpoint segment. The normal demo catalog does not contain endpoint search responses. |
| Harness page blank after refresh/navigation | Reopen `/tests/browser/dns-evidence.html` with the desired `fault` query parameter. |
| Health unknown or Setup writes unavailable | Expected in demo mode. Synthetic captures cannot establish live pipeline health or authorize settings writes. |

Stop only the terminals you started using Ctrl-C. These procedures do not install a Splunk package or alter collection policies. Keep any downloaded demo files clearly labeled synthetic.

## Evidence and maintenance

The captured application walkthroughs are grounded in `frontend/src/data/demoClient.ts`, `fixtures/demo-*.json` and `tests/browser/app.spec.ts`. The DNS segment is grounded in `tests/browser/dns-evidence-harness.tsx`, `tests/browser/dns-evidence.spec.ts` and `fixtures/dns/`. Networking raw-event provenance is in `fixtures/raw-networking/FIELDS.md` and `scenario.json`.

Scripts were checked against the local working tree on October 23, 2026. The ACI map, database Find result, previous-window comparison, Catalyst MAC-card attachment/observation details and endpoint/DNS UI path were manually rehearsed. Remaining networking steps were checked against captures, UI implementation and existing browser assertions. Review corrected the distinction between IP conversation selection and MAC observation selection, removed a switch-port value that the selected inspector does not display, and clarified disabled map/export controls. Relative file/heading links and whitespace were checked. No test suite or Splunk lab was rerun for these documentation changes. The working tree includes corrections newer than the existing 0.4.0 archive; consult the DNS qualification record before claiming an installed package has the same behavior. Rehearse again after UI labels, captures or package versions change.
