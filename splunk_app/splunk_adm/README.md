# Application Atlas pilot

React interface targeting Splunk 10.6. This is an initial development package:
Splunk 10.6 runtime compatibility and AppInspect have not been validated. No
Kubernetes cluster or Splunk instance has been connected. Cisco adapters and
scheduled projection are future work, not shipped collectors.

## Run locally

Requires Node 22.12+ (Node 26 used here), npm, Python 3.10+, and `tar` for packaging.

```sh
npm ci --registry=https://registry.npmjs.org --ignore-scripts
npm run dev
```

Open the localhost URL printed by Vite. Demo data is synthetic and fixed to
October 7, 2026. Select services or connections for evidence; choose **Network &
workloads** for pod identities and flow relationships. Zoom and scroll the map,
highlight by name/IP, or export the complete snapshot. This is not a traffic
simulator. Counts describe the demo fixture, not current production traffic.

## Build

```sh
npm run typecheck
npm run lint
npm run package
```

The package command builds the standalone preview into `dist/preview/`, builds a
self-contained React IIFE and CSS into the app's `appserver/static/`, and creates
`dist/splunk_adm-0.1.0.tar.gz` plus its SHA256 file. No CDN assets or runtime npm
installation are required. Formatting: `npm run format`. There is no test suite
in this initial implementation; these commands are compilation/format checks.

## Splunk pilot setup

1. Have a Splunk administrator review the package and install it in a development
   environment through **Manage Apps → Install app from file**. Follow your normal
   Splunk Cloud private-app review process if applicable. This repository does not
   deploy automatically.
2. Open **Application Atlas**. Its Simple XML 1.1 shell mounts the React app.
   Demo mode is the default even inside Splunk; it never silently substitutes for
   a failed live search.
3. Provision a graph index (example `adm`) and HEC input through your environment's
   normal administration. Grant users read access to the index. Do not embed HEC
   tokens or credentials in the browser or repository. Deploy `adm:graph` parsing
   settings to the appropriate parsing/search tiers for your Splunk topology.
4. Ingest the local HEC envelope file `fixtures/demo-hec.ndjson` through an approved
   HEC client. It contains synthetic data. HEC supplies event timestamps; the
   application does not create indexes or HEC inputs.
5. Choose **Splunk data**, configure index `adm`, boundary `shop-demo`, and **All
   time (demo import)**. Load the snapshot. The UI retains its synthetic-data
   warning because the imported event is marked `demo: true`.

Search integration uses Splunk's authenticated SearchManager; no credentials are
stored in React. It selects one complete latest event by `_time` for the exact
boundary ID. The search window selects snapshot timestamps, not a new aggregation
window. The displayed evidence window comes from that snapshot. Reload manually
to see new projections. Snapshots over 2 MB or 500 nodes / 2,000 edges are rejected.

## Real Kubernetes pilot

Choose the qualified frontend service name, environment, cluster and namespace.
Export selected OTLP JSON spans to the projector, including `service.name`,
environment, `k8s.cluster.name`, `k8s.namespace.name`, and `k8s.pod.uid`. Preserve
parent span IDs. O11y ingestion alone does not make spans searchable in Splunk
Platform; configure an explicit bridge/export and confirm its format.

Provide normalized pod snapshots with UID, namespace, addresses, cluster, and
validity intervals. A current pod list cannot safely identify historical IPs.
Supply scoped Stream flows with start/end times, IPs, byte counts and exporter.
The pilot expects the normalized formats in [GRAPH_CONTRACT.md](GRAPH_CONTRACT.md),
not arbitrary raw TA events or the Collector's compressed/protobuf transport.

```sh
python3 tools/adm_pipeline.py --spans fixtures/spans.json --inventory fixtures/inventory.json --flows fixtures/flows.json --boundary-id shop-demo --service frontend --environment demo --cluster demo-cluster --namespace shop --start 2026-10-07T11:45:00Z --end 2026-10-07T12:00:00Z --demo --output fixtures/demo-graph.json --hec-output fixtures/demo-hec.ndjson
```

For real inputs, remove `--demo`, choose a distinct boundary ID and real window,
and write outputs outside fixtures. Schedule this offline process externally and
send its HEC events using your approved client. No modular input or collector is
shipped. Do not claim full dependency coverage from sampled telemetry. NAT/VIPs,
Service-to-pod load balancing, routed paths, serverless, and uninstrumented services
require additional evidence/adapters; unresolved endpoints remain explicit.

## Implementation references

- [Splunk dashboard script and style integration](https://help.splunk.com/en/splunk-enterprise/developing-views-and-apps-for-splunk-web/10.0/customize-splunk-web/customize-dashboard-styling-and-behavior)
- [Vite library builds](https://vite.dev/guide/build#library-mode)
- [OTLP JSON encoding](https://opentelemetry.io/docs/specs/otlp/)
- [Local TA analysis](TA_PACKAGE_ANALYSIS.md)
