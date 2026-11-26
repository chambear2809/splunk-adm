# Plan migration move groups

Open **Explore → Move groups** in Application Atlas, or go to `/en-US/app/splunk_adm/migration` on your search head. The planner groups hosts that talk to each other so they can move in the same wave. It lists the conversations that cross groups as wave blockers, and it holds shared infrastructure (DNS, directory, time) apart so it does not pull the whole estate into one group.

The plan is a **draft built from observed conversations**. Atlas does not change any device, cloud account or migration tool. Downloads are local files only.

## Load conversations

1. Choose a **verified routing scope** and a window: 24 hours, 7, 14 or 30 days. Use 7 to 30 days so weekly and month-end jobs show up. Windows end at the last closed five-minute bucket.
2. Select **Load conversations**. Atlas runs two bounded searches under your own Splunk session:
   - **Conversations.** This search reads the conversation summaries (`source="adm:conversation"`) in the scope and window, using the same scope, contract and de-duplication rules as Endpoints.
     - It aggregates each client, server, port and transport per observer.
     - Across observers it keeps the **largest** single-observer record and byte count, so one conversation seen by several exporters is not double-counted.
     - It keeps the earliest first-seen and latest last-seen, and at most 8 observer names.
     - At most 5,000 conversations are loaded, largest by flow records first. If more exist, the page says how many and marks the plan incomplete.
   - **Coverage.** This search counts the five-minute summary buckets with rows in each UTC day of the window. A day with fewer buckets than expected is reported as **a collection gap or a quiet period**. Atlas cannot tell the two apart, so a missing day never means "no dependency".
3. If the routing-scope configuration changes while the searches run, the result is discarded and you are asked to reload. The same happens if either search reports an error, a warning, or a malformed row. Atlas never plans on partial rows.

## Seeds and traversal

Enter one group per line as `label = address, address`, for example `Orders = 10.20.1.15, 10.20.1.16`. A line without a label gets one. Labels use `=` because IPv6 addresses contain colons. Up to 16 seed groups with 64 addresses in total are allowed.

From each seed, Atlas walks observed conversations in both directions, level by level:

| Rule | Default | Range | Effect |
| --- | --- | --- | --- |
| Traversal depth | 2 | 0–6 | Hops from a seed. Depth 0 keeps only the seeds. |
| Maximum group size | 200 | 1–1,000 | A group stops adding hosts at this size and is marked **size limit reached**. |
| Connection limit | 50 | 1–10,000 | A host with more unclaimed peers than this is kept but **not expanded**, so one busy host cannot absorb the estate. |
| Merge connected seeds | Off | — | When on, seed groups that reach each other become one group (`Orders + Billing`). When off, they stay separate and the conversations between them become wave blockers. |

Traversal is deterministic. It runs in group order, then address order, so the same data, seeds and rules always produce the same plan. A host reachable from two groups joins the earlier group. Each member shows how it was reached (seed or traversal), its hop count, the peer that reached it, and its expansion state:

- **expanded**: all its peers were considered;
- **depth limit**: it sits at the maximum depth;
- **connection limit**: it had too many peers;
- **group size limit**: the group filled up;
- **not expanded**: it was assigned manually.

Hosts the data shows but no group reached are listed under **Not in a group**.

## Shared services

A shared service is kept out of every group, and traversal stops at it. Conversations to it are listed as shared dependencies rather than blockers. There are three ways a host becomes shared.

**Well-known service ports.** A host counts only when it is the **server** on one of the enabled ports in directed conversations, and it has at least the **port-rule minimum clients** (default 2) distinct clients. Rows whose direction is unknown are skipped, and the plan notes how many. These ports are on by default because domain controllers, resolvers and time servers serve every tier:

| Port | Service | Why it is shared | Reference |
| --- | --- | --- | --- |
| 53 TCP/UDP | DNS | Name resolution for every tier | [RFC 1035](https://www.rfc-editor.org/rfc/rfc1035) |
| 88 TCP/UDP | Kerberos | Domain authentication on domain controllers | [RFC 4120](https://www.rfc-editor.org/rfc/rfc4120), [Microsoft port requirements](https://learn.microsoft.com/en-us/troubleshoot/windows-server/networking/service-overview-and-network-port-requirements) |
| 123 UDP | NTP | Estate time source | [RFC 5905](https://www.rfc-editor.org/rfc/rfc5905) |
| 389 TCP/UDP | LDAP / DC locator | Directory lookups on domain controllers | [RFC 4511](https://www.rfc-editor.org/rfc/rfc4511), [MS-ADTS](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-adts/1010e59a-cf64-410c-a05c-a3a6c715261a) |
| 464 TCP/UDP | Kerberos password change | Served by domain controllers | [Microsoft port requirements](https://learn.microsoft.com/en-us/troubleshoot/windows-server/networking/service-overview-and-network-port-requirements) |
| 636 TCP | LDAPS | Directory lookups over TLS | [MS-ADTS](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-adts/1010e59a-cf64-410c-a05c-a3a6c715261a) |
| 3268 / 3269 TCP | Global Catalog (plain / TLS) | Forest-wide directory lookups | [MS-ADTS](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-adts/1010e59a-cf64-410c-a05c-a3a6c715261a) |

These are off by default because an application can own its own server on them:

| Port | Service | Why it is opt-in | Reference |
| --- | --- | --- | --- |
| 445 TCP | SMB | Domain controllers serve SYSVOL on it, but so do application file shares | [Microsoft port requirements](https://learn.microsoft.com/en-us/troubleshoot/windows-server/networking/service-overview-and-network-port-requirements) |
| 2049 TCP/UDP | NFS | Shared filers, or an application's own NFS server | [RFC 7530](https://www.rfc-editor.org/rfc/rfc7530) |
| 1556 TCP | NetBackup PBX | Backup primary and media servers use it, but **clients also listen on 1556**, so raise the minimum client count when you enable it | [Veritas NetBackup ports](https://www.veritas.com/support/en_US/article.100002391) |

Add other ports under **Other shared ports** as `tcp/10102, udp/514`, up to 32.

**Fan-in percentile.** Optionally, a host whose distinct-peer count is in the top 10%, 5% (default) or 1% of loaded hosts is treated as shared. The threshold is a nearest-rank percentile, and it is never lower than the **minimum peers** setting (default 10). The page shows the threshold. This catches unlisted shared services such as monitoring, patching or a central database, but it can also catch a busy application server, so review the list.

**Pinned by you.** Select **Mark shared** on any host to pin it. Pinning always wins. A pinned seed is dropped from its group, and the plan says so.

Select **Not shared** on a detected service to stop port and fan-in detection for that host; traversal then treats it like any other host. **Restore detection** undoes this. If you move a detected-shared host into a group manually, your assignment wins. A seed that matches a detection rule stays a seed, is expanded, and gets a note.

## Move hosts and read the blockers

Use **Move** on a member to put it in another group, or select **Not in a group**. Use **Add to a group** on an unplanned host. The plan recomputes in the browser with no new search: groups, shared services and blockers update together. Manual moves are applied after traversal and do not pull in more hosts. **Clear all manual changes** removes your pins, suppressions and moves.

Each conversation in the plan gets one classification:

- **Wave blocker**: both ends are in different groups. The blocker summary lists each pair of groups with conversation and flow-record counts and up to 16 services. Move those groups in the same wave, or keep the path open between waves.
- **Shared dependency**: one end is a shared service. Keep that service reachable from every wave.
- **Outside the plan**: one end is in a group and the other is in no group.

Edge rows show the client, server, port and transport, and whether the direction was observed. They also show flow records, the largest single-observer byte count, the observers, sampling, and first and last seen. The blocker table shows the first 200 rows; the downloads contain up to 2,000 of each kind, and every list says when it is truncated.

"No cross-group conversations were observed" is **not** proof the groups are independent. The window, sampling, the 5,000-conversation cap and coverage gaps can all hide dependencies.

## Observed and inferred

| Item | Label |
| --- | --- |
| Conversations, ports, volume, observers, first/last seen | **Observed** in the conversation summaries |
| Group membership and blockers | **Inferred** from observed conversations by the traversal rules |
| Port-rule and fan-in shared services | **Inferred** by rule; the reason is shown |
| Pinned shared services and moved hosts | **Manual** |
| VMware VM names | **Inferred context**; never used for grouping |

A plan is **complete** only when the conversation read was not capped, every row had a verified scope, and summary coverage was full. Otherwise every export says **incomplete**.

## VMware names (optional)

**Add VMware names** looks up group member and shared-service addresses (at most 200) in `vmware:inv:vm` inventory from the [Splunk Add-on for VMware](https://splunkbase.splunk.com/app/3215) (`adm_index_vmware_inv`), over the 30 days before the window end.

- It keeps each VM's latest record first, then matches its primary guest IP, `changeSet.guest.ipAddress`. The [VMware field extractions](https://splunkbase.splunk.com/app/5641) 4.0.4 alias that path to `ip` (`default/props.conf`, `[vmware:inv:vm]`).
- It shows `vm_name`, the ESXi host and the cluster.
- The match is by address only, without a routing scope, and covers only the primary guest IP. Several VMs reporting the same IP are flagged **ambiguous**.
- A missing name does not mean the host is not a VM.

## Export

- **Groups CSV**: a metadata row (scope, window, completeness, coverage), then one row per member and per shared service with its reason and evidence label.
- **Dependencies CSV**: a metadata row, then wave blockers, shared dependencies and outside-plan conversations.
- **Plan JSON** (`application-atlas/move-group-plan`, schema 1, `draft: true`): the selection, coverage, seeds, rules, manual overrides, the full plan and any VMware names.

Cells are formula-protected. Atlas does not produce AWS Transform or Azure Migrate import files: no officially documented import shape was confirmed for this data, so map the CSV yourself.

## Limits

| Limit | Value |
| --- | --- |
| Window | 5 minutes to 30 days; preset 24 h, 7, 14, 30 days. Summaries are retained about 35 days. |
| Conversations loaded | 5,000 (largest first; reported when capped) |
| Seed groups / seed addresses | 16 / 64 |
| Group size | 1,000 maximum |
| Exported edges per kind | 2,000 |
| Shared services / unplanned hosts listed | 500 each |
| Manual changes | 1,000 |
| VMware lookups | 200 addresses, 400 rows |

Seeding from an application in the catalog is not available yet: catalog applications are keyed by Kubernetes service, not by address. Enter the application's addresses instead.
