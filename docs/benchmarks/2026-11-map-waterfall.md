# Map search waterfall (0.8.2 → 0.8.4)

Splunk Cloud 10.6 lab stack, `teastore-webui` (CV / K8-Fabrix-AI / teastore),
qualified summaries, 2026-11-04. Logged-in Chromium (persistent profile),
`/tmp/atlas-hf/live-waterfall.mjs`: every `/search/jobs` POST and its
`/results` response timed from navigation (seconds; job create → results body
finished). **Mount**: app shell replaces the Splunk loading text. **Draw**:
`.adm[data-loaded=true]` (summary graph + inventory). **Full**: newest raw
minutes merged. Nodes/edges: full read. The summary chip read "Exact totals"
(read coverage 100) in every run.

## Before: 0.8.2 (serial)

| Window | Mount | Summary graph | Inventory (`adm_topology_with_vsphere`) | Full graph | Inventory again | Draw | Full | Nodes/edges |
| ------ | ----- | ------------- | --------------------------------------- | ---------- | --------------- | ---- | ---- | ----------- |
| 15 min | 5.6¹  | 5.6→8.2       | 8.2→11.7                                | 11.7→20.3  | 20.5→23.0       | 12.0 | 23.0 | 20/149      |
| 1 h    | 2.4   | 2.4→5.0       | 5.1→8.6                                 | 8.6→18.2   | 18.4→21.9       | 8.7  | 21.9 | 20/172      |
| 4 h    | 2.3   | 2.3→6.0       | 6.0→10.6                                | 10.6→22.2  | 22.5→26.0       | 10.7 | 26.0 | 20/179      |
| 24 h   | 2.4   | 2.4→5.8       | 6.0→9.6                                 | 9.6→22.2   | 22.6→26.2       | 9.7  | 26.2 | 35/367      |
| 7 d    | 2.3   | 2.3→5.9       | 6.1→13.7                                | 13.7→24.2  | 24.5→32.2       | 13.7 | 32.2 | 35/367      |

## After: 0.8.4 (two runs)

| Window | Mount      | Summary graph      | `adm_topology`     | `adm_map_vsphere_inventory` | Full graph           | Draw        | Full         | Nodes/edges |
| ------ | ---------- | ------------------ | ------------------ | --------------------------- | -------------------- | ----------- | ------------ | ----------- |
| 15 min | 6.5¹ / 3.9 | 6.5→11.9 / 3.9→8.4 | 6.5→10.1 / 3.9→7.6 | 6.5→9.0 / 3.9→7.6           | 11.9→28.9 / 8.4→17.8 | 12.4¹ / 8.8 | 28.9¹ / 17.8 | 20/163      |
| 1 h    | 2.6 / 2.5  | 2.5→6.7 / 2.5→7.1  | 2.5→6.1 / 2.5→6.2  | 2.5→5.0 / 2.5→6.2           | 6.7→14.8 / 7.1→19.8  | 6.9 / 7.4   | 14.8 / 19.8  | 20/175      |
| 4 h    | 2.5 / 2.4  | 2.5→6.3 / 2.4→7.1  | 2.5→6.1 / 2.4→5.0  | 2.5→5.0 / 2.4→5.0           | 6.3→13.8 / 7.1→17.6  | 6.3 / 7.2   | 13.8 / 17.6  | 20/179      |
| 24 h   | 2.8 / 2.9  | 2.8→8.4 / 2.9→7.2  | 2.8→6.5 / 2.9→5.5  | 2.8→6.5 / 2.9→5.5           | 8.4→18.7 / 7.2→20.1  | 8.7 / 7.2   | 18.7 / 20.1  | 30/307²     |
| 7 d    | 2.4 / 3.1  | 2.4→7.3 / 3.1→9.2  | 2.4→7.7 / 3.1→8.7  | 2.4→4.9 / 3.1→6.0           | 7.2→18.7 / 9.1→21.8  | 7.8 / 9.4   | 18.7 / 21.8  | 35/367      |

¹ First navigation after an install or browser launch (cold Splunk Web cache).
² The 24 h window had slid past older flows: a pinned and a relative `-24h` read
run together returned the same 30/307 with read coverage 100.

## Findings

- 0.8.2 ran the four map jobs one after another. Inventory waited for the
  summary graph only to learn its window, and the full read ran the identical
  inventory read again.
- Rendering is not the bottleneck: results to `data-loaded` took about 40 ms, and
  `rowsToGraph` on the 1.9 MB 24 h result took 20 ms. Bodies are gzip. The summary
  body takes 0.2–0.9 s to finish after its headers arrive; the full body (2.1–3.6 MB)
  takes 0.5–1.7 s.
- Server `runDuration` (REST, alone): summary graph 2.1–2.3 s, full graph
  8.9–10.6 s, `adm_topology` 1.0 s (15 min) to 3.4 s (7 d), and the VMM
  append 1.2–3.5 s. Of that 3.5 s at 7 d, 2.5 s was `adm_vsphere_uplinks`, whose
  rows the map's filter always dropped.
- With three jobs running at once the summary graph runs 3.0–4.7 s. A combined
  inventory job (two at once) did not make the graph faster (2.8–4.2 s), and
  the inventory itself was slower (2.4–5.0 s against a 1.4–3.9 s maximum for
  the split pair).
- The remaining overhead per job is the toolkit's fixed 1 s status poll
  (`@splunk/search-job` progress tracker, not configurable) and the results download.
