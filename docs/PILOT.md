# Application Atlas pilot

Splunk app for network-perspective application dependency mapping, targeting Splunk Enterprise 10.6 for the pilot and Splunk Cloud afterwards. The app builds the map inside Splunk from the installed TAs' data; see [DATA_LAYER.md](DATA_LAYER.md) for the searches, lookups and contracts. It has been validated against TA-shaped synthetic events in a local Splunk 10.6 container, not yet against a live environment.

## Run locally

Requires Node 22.13+, 24.x or 26+ (Vitest does not support Node 25), npm, and `tar` for packaging. Python 3.10+ is needed only for the fixture generator and the lab tests.

```sh
npm ci --registry=https://registry.npmjs.org --ignore-scripts
npm run dev
```

Open the localhost URL printed by Vite. Demo mode replays the rows that the app's `adm_graph` and `adm_topology` searches returned in the lab for a synthetic scenario (October 7, 2026, 11:45–12:00 UTC). By default that's the ACI pilot scenario in `fixtures/raw-aci/scenario.json`. The NX-OS fabric scenario in `fixtures/raw/scenario.json` is available from **Settings**. It is clearly marked synthetic and never substitutes for a failed live search.

## Build and test

```sh
npm run lint
npm test
npm run package
```

`npm run package` builds the standalone preview into `dist/preview/`, builds a self-contained React bundle and CSS into the app's `appserver/static/`, stages the app in `dist/stage/splunk_adm` (adding an `[install] build` number and `docs/DATA_LAYER.md`), and creates `dist/splunk_adm-<version>.tar.gz` plus its SHA256 file. Packaging fails if the `app.conf` versions differ from `package.json`. Set `SOURCE_DATE_EPOCH` for a reproducible build number. No CDN assets or runtime npm installation are required.

Python lint: `ruff check tools tests` and `ruff format --check tools tests` (install Ruff separately).

AppInspect (requires libmagic, e.g. `brew install libmagic`; install `splunk-appinspect` from PyPI in a virtual environment):

```sh
splunk-appinspect inspect dist/splunk_adm-0.2.0.tar.gz --mode precert --included-tags cloud
```

Expected result: no failures or errors; informational warnings for SplunkJS usage, `collections.conf`, and RFC 5737 documentation IPs in the demo data.

### Synthetic fixtures and the Splunk lab

`python3 tools/gen_raw_fixtures.py` regenerates `fixtures/raw/*.ndjson` (HEC envelopes per sourcetype) from `fixtures/raw/scenario.json` (NX-OS fabric). `--scenario aci` regenerates the ACI pilot in `fixtures/raw-aci/`. Every field is traced to its TA or product source in each directory's `FIELDS.md`.

`tests/splunk/lab.sh` runs a local Splunk container (`splunk/splunk`, ports bound to 127.0.0.1) with only the TAs' search-time configuration, never their inputs or scripts, and runs the data-layer tests:

```sh
tests/splunk/lab.sh up && tests/splunk/lab.sh install
ADM_LAB=1 python3 -m unittest discover -s tests/splunk
tests/splunk/lab.sh purge   # removes the container, volumes, image and generated secrets
```

Starting the lab accepts the Splunk General Terms for a local development instance and pulls an image of about 2 GB.

## Pilot prerequisites

| Source | Required configuration |
| --- | --- |
| Splunk Stream (NX-OS leaves) | NetFlow/IPFIX receiver enabled; the `netflow` stream enabled with endpoint, port, `protoid`, byte/packet, exporter, interface and sampling fields. |
| Cisco DC Networking (ND, NX-OS, ACI) | Nexus Dashboard flows and endpoints; NX-OS hostname, interface and CDP-neighbor commands; ACI `stats` and `classInfo_faultInst` inputs (`fvCEp`/`fvIp`, `fvRsCEpToPathEp`, `compVm`, `topSystem`). To name NetFlow host-facing ports, add `show interface snmp-ifindex` as a custom NX-OS command; by default only CDP uplinks carry an ifIndex. |
| Cisco Security Cloud | FTD eStreamer connection events (`cisco:sfw:estreamer`); Isovalent HEC input with `processConnect` events. The TA extracts no NAT-translated tuple, so traffic to a public VIP is not tied to its backend yet. |
| Splunk OTel Collector for Kubernetes (Helm) | `clusterName` set; `splunkPlatform.tracesEnabled: true` with a traces index and `splunkPlatform.sourcetype: otel:traces` (or update the `adm_traces_sourcetype` macro); `clusterReceiver.k8sObjects` with pods in `mode: watch`. The default 6-hour pull is too coarse for IP ownership history. |
| Cilium | Native routing makes pod IPs visible to fabric NetFlow. In tunnel mode the fabric sees only node-to-node VXLAN/Geneve, and pod-level conversations come from Isovalent only. Both are handled. |

## Splunk setup

1. Have a Splunk administrator review and install the package (**Manage Apps → Install app from file**). On Splunk Cloud, use the private-app vetting process.
2. Create a summary index (default name `adm_summary`; on Cloud through ACS). Grant app users read access to it and to the source indexes.
3. Edit the app's index macros (`adm_index_netflow`, `adm_index_dcn`, `adm_index_ftd`, `adm_index_isovalent`, `adm_index_k8s`, `adm_index_traces`, `adm_index_summary`, `adm_summary_index_name`) and `adm_traces_sourcetype` to match your environment.
4. Fill the `adm_observer_scope.csv` lookup (`observer_kind,observer,scope,cluster`) so each exporter, fabric, firewall and cluster maps to its routing scope. Unmapped observers fall into scope `default`; identities only join within one scope.
5. Enable the saved searches: **ADM - Identity builder**, **ADM - Service binding**, **ADM - Service backends**, **ADM - ACI policy**, **ADM - Interface inventory**, **ADM - Conversation rollup**, **ADM - Identity prune**, **ADM - Service binding prune**, **ADM - Service backends prune**, **ADM - Service routes prune** and **ADM - ACI policy prune**. They ship disabled. Don't run a manual identity backfill while the scheduled builder is running.
6. Open **Application Atlas**, choose **Splunk data**, and enter the entry service, environment, cluster and namespace. The map covers the selected time range.

Coverage is limited to what the sources observe. Sampled flows, uninstrumented services, NAT without translated tuples and unmonitored segments stay visible as unknown endpoints or gaps; they are not filled in.

## References

- [Data layer contract](DATA_LAYER.md)
- [Network path evidence](NETWORK_PATH_DESIGN.md)
- [TA package analysis](TA_PACKAGE_ANALYSIS.md)
- [Splunk dashboard script and style integration](https://help.splunk.com/en/splunk-enterprise/developing-views-and-apps-for-splunk-web/10.0/customize-splunk-web/customize-dashboard-styling-and-behavior)
