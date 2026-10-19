# Application Atlas pilot

Splunk app for network-perspective application dependency mapping, targeting Splunk Cloud and Splunk Enterprise 10.6+. The app builds the map inside Splunk from the installed TAs' data; see [DATA_LAYER.md](DATA_LAYER.md) for the searches, lookups and contracts. [Current engineering qualification](ATLAS_FINAL_QUALIFICATION.md) records standalone and bounded same-host SHC execution on Enterprise 10.6.0.5 with TA-shaped synthetic events. This does not establish real controller/exporter collection, customer production qualification or Cloud runtime acceptance; see the [SHC limits](SHC_FINAL_QUALIFICATION.md).

## Run locally

Requires Node 22.13+, 24.x or 26+ (Vitest does not support Node 25), npm, and `tar` for packaging. Python 3.10+ is needed only for the fixture generator and the lab tests.

```sh
npm ci --registry=https://registry.npmjs.org --ignore-scripts
npm run dev
```

Open the localhost URL printed by Vite. Demo mode replays the rows that the app's `adm_graph` and `adm_topology` searches returned in the lab for a synthetic scenario (October 7, 2026, 11:45–12:00 UTC). By default that's the ACI pilot scenario in `fixtures/raw-aci/scenario.json`. The NX-OS fabric scenario in `fixtures/raw/scenario.json` is available from **Settings**. It is clearly marked synthetic and never substitutes for a failed live search.

Settings also offers **Catalyst → ACI** and **Meraki wireless → NX-OS**. These are two views of the combined dataset in `fixtures/raw-networking/`, captured from the V2 searches with their own recorded time window and provenance. Both preserve the separation between attachment evidence and observed traffic. Read the [Cisco qualification status](CISCO_NETWORKING_QUALIFICATION.md) and [operator handout](operators/cisco-enterprise-networking.md) before enabling V2 readers or writers in a deployment.

## Build and test

```sh
npm run lint
npm test
npm run package
```

`npm run package` builds the standalone preview into `dist/preview/`, builds a self-contained React bundle and CSS into the app's `appserver/static/`, stages the app in `dist/stage/splunk_adm` (adding an `[install] build` number and `docs/DATA_LAYER.md`), and creates one `dist/splunk_adm-<version>.tar.gz` archive and its SHA256 file for installs and updates. The archive contains neither scope KV rows nor the legacy CSV migration source, so existing state is preserved; see [upgrade checks](UPGRADES.md). Packaging fails if the `app.conf` versions differ from `package.json`. Set `SOURCE_DATE_EPOCH` for a reproducible build number. No CDN assets or runtime npm installation are required.

Python lint: `ruff check tools tests` and `ruff format --check tools tests` (install Ruff separately).

AppInspect (requires libmagic, e.g. `brew install libmagic`; install `splunk-appinspect` from PyPI in a virtual environment):

```sh
splunk-appinspect inspect dist/splunk_adm-0.3.0.tar.gz --mode precert --included-tags cloud
```

Use Python 3.11 for AppInspect and save its JSON report (`--output-file dist/appinspect-cloud.json`). Run `python3 tools/check_appinspect.py dist/appinspect-cloud.json`; errors and failures block release. The qualified candidate has five warnings: Python script existence, custom-conf replication, `collections.conf`, Python SDK version and synthetic/documentation hostnames/IPs. No legacy SplunkJS bundle ships. See [final engineering qualification](ATLAS_FINAL_QUALIFICATION.md) for the exact package, current evidence and Cloud qualification limits. AppInspect is not a Cloud runtime qualification.

### Synthetic fixtures and the Splunk lab

`python3 tools/gen_raw_fixtures.py` regenerates `fixtures/raw/*.ndjson` (HEC envelopes per sourcetype) from `fixtures/raw/scenario.json` (NX-OS fabric). `--scenario aci` regenerates the ACI pilot in `fixtures/raw-aci/`. Every field is traced to its TA or product source in each directory's `FIELDS.md`.

`--scenario networking` regenerates the combined Cisco dataset. Downloaded vendor archives and extracted source remain in ignored research directories; the distributed app includes provenance records and synthetic captures, not vendor packages. The V2 loader, capture, load, and migration tools require the repository lab lock and explicit local-lab state changes where applicable. Consult each tool's help before running it; do not run independent lab lifecycles concurrently.

`tests/splunk/lab.sh` runs a local Splunk container (`splunk/splunk`, ports bound to 127.0.0.1) with only the TAs' search-time configuration, never their inputs or scripts, and runs the data-layer tests:

```sh
npm run package
npx playwright install chromium  # Linux runners also need Playwright system dependencies
python3 tools/lab_lock.py --root . -- bash -euo pipefail -c '
  if docker inspect adm-splunk-lab >/dev/null 2>&1; then
    echo "Refusing an existing lab container" >&2
    exit 1
  fi
  archives=(dist/splunk_adm-*.tar.gz)
  test "${#archives[@]}" -eq 1
  export ADM_UPGRADE_PACKAGE="$PWD/${archives[0]}"
  trap "tests/splunk/lab.sh purge" EXIT
  tests/splunk/lab.sh up
  tests/splunk/lab.sh install
  ADM_LAB=1 python3 -m unittest discover -s tests/splunk -v
'
```

Starting the lab accepts the Splunk General Terms for a local development instance and pulls an image of about 2 GB.

## Pilot prerequisites

The table below describes the original full pilot. Choose [deployment options and missing-source behavior](operators/deployment-options.md) first; configure only the inputs needed for selected features. The [operator setup sequence](operators/splunk-setup-guide.md) includes optional Catalyst/Meraki inputs and separates V1 setup from staged V2 activation.

| Source                                      | Required configuration                                                                                                                                                                                                                                                                                                                           |
| ------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| Splunk Stream (NX-OS leaves)                | NetFlow/IPFIX receiver enabled; the `netflow` stream enabled with endpoint, port, `protoid`, byte/packet, exporter, interface and sampling fields.                                                                                                                                                                                               |
| Cisco DC Networking (ND, NX-OS, ACI)        | Nexus Dashboard flows and endpoints; NX-OS hostname, interface and CDP-neighbor commands; ACI `stats` and `classInfo_faultInst` inputs (`fvCEp`/`fvIp`, `fvRsCEpToPathEp`, `compVm`, `topSystem`). To name NetFlow host-facing ports, add `show interface snmp-ifindex` as a custom NX-OS command; by default only CDP uplinks carry an ifIndex. |
| Cisco Security Cloud                        | FTD eStreamer connection events (`cisco:sfw:estreamer`); Isovalent HEC input with `processConnect` events. The TA extracts no NAT-translated tuple, so traffic to a public VIP is not tied to its backend yet.                                                                                                                                   |
| Splunk OTel Collector for Kubernetes (Helm) | `clusterName` set; `splunkPlatform.tracesEnabled: true` with a traces index and `splunkPlatform.sourcetype: otel:traces` (or update the `adm_traces_sourcetype` macro); `clusterReceiver.k8sObjects` with pods in `mode: watch`. The default 6-hour pull is too coarse for IP ownership history.                                                 |
| Cilium                                      | Native routing makes pod IPs visible to fabric NetFlow. In tunnel mode the fabric sees only node-to-node VXLAN/Geneve, and pod-level conversations require a pod-visible source such as Isovalent process connections or Hubble flows. Both are handled.                                                                                         |

## Splunk setup

1. Have a Splunk administrator review and install the package (**Manage Apps → Install app from file**). On Splunk Cloud, use the private-app vetting process.
2. Create a summary index (default name `adm_summary`; on Cloud through ACS). Grant app users read access to it and to the source indexes.
3. In **Application Atlas → Setup**, configure and save deployment expectations for the selected sources, including cadence and receipt freshness. Saving requires the [qualified persistence gate](DEPLOYMENT_HEALTH.md#supported-write-contract-and-deployment-gate); settings writes ship disabled and are unavailable on unqualified targets. Saved expectations do not configure collection or activate V2. Then edit the app's index macros (`adm_index_netflow`, `adm_index_dcn`, `adm_index_ftd`, `adm_index_isovalent`, `adm_index_k8s`, `adm_index_traces`, `adm_index_hubble`, `adm_index_summary`, `adm_summary_index_name`) to match your environment. Configure `adm_traces_sourcetype` separately through Splunk macro settings.
4. Populate the `adm_observer_scope` KV lookup (`observer_kind,observer,scope,cluster`) as an administrator, with lowercase matching keys and read-all/admin-sc_admin-write collection ACLs; see the [upsert instructions](operators/splunk-platform.md#application-atlas-configuration). Existing installations must complete the [one-time CSV migration](UPGRADES.md#one-time-csv-to-kv-scope-migration) before enabling searches. Each exporter, fabric, firewall and cluster maps to its routing scope. Unmapped observers remain isolated in authority-qualified `unmapped:<hash>` scopes; identities only join within one scope.
5. After reviewing the Setup checklist, enable only the saved searches needed by the [selected features](operators/deployment-options.md#choose-v1-jobs): **ADM - Identity builder**, **ADM - Service binding**, **ADM - Service backends**, **ADM - ACI policy**, **ADM - Interface inventory**, **ADM - Conversation rollup**, **ADM - Application catalog**. They ship disabled. Do not run a manual identity backfill while the scheduled builder is running. Keep all prune schedules disabled; pruning requires the paused-writer maintenance procedure in [Recovery and replay](RECOVERY.md).
6. Open **Application Atlas → Applications**, select an application or use Find, and open its map. Use the cascading scope controls and time picker, then **Build map**. Map settings switch between live Splunk data and captured demo scenarios.

Coverage is limited to what the sources observe. Sampled flows, uninstrumented services, NAT without translated tuples and unmonitored segments stay visible as unknown endpoints or gaps; they are not filled in.

## References

- [Data layer contract](DATA_LAYER.md)
- [Network path evidence](NETWORK_PATH_DESIGN.md)
- [TA package analysis](TA_PACKAGE_ANALYSIS.md)
- [Splunk dashboard script and style integration](https://help.splunk.com/en/splunk-enterprise/developing-views-and-apps-for-splunk-web/10.0/customize-splunk-web/customize-dashboard-styling-and-behavior)
