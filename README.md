# Splunk Application Dependency Mapping

**Application Atlas** is a Splunk app that maps application dependencies from the network's point of view. Its scheduled searches combine:

- network evidence from Splunk Stream NetFlow, Cisco ACI, Nexus Dashboard, NX-OS, Cisco FTD, and Isovalent/Hubble;
- Kubernetes object history and OpenTelemetry traces from the Splunk OTel Collector.

For each application, the map shows:

- which workloads talk to what, over which ports;
- how clients reach it: Cilium LoadBalancer VIPs, NodePorts, Ingress/Gateway, or pod IPs;
- which devices saw the traffic, and the candidate leaf and spine path;
- which ACI contract should permit it;
- how confident each identification is.

## Quick start

Requires Node 22.13+, 24.x or 26+ and npm.

```sh
npm ci --registry=https://registry.npmjs.org --ignore-scripts
npm run dev
```

Open the localhost URL printed by Vite. Demo mode needs no Splunk connection. It replays the app's own search output from TA-shaped synthetic data: the ACI pilot scenario by default, or the NX-OS fabric scenario (switch in **Settings**). Build a Splunk app archive with `npm run package`.

**Target:** Splunk Enterprise 10.6 for the pilot (a single ACI fabric with Kubernetes on Cilium), then Splunk Cloud. Validated in a local Splunk 10.6 container against synthetic data; not yet run against a live environment.

## Project layout

- `splunk_app/splunk_adm/`: app configuration, macros, saved searches, KV store collections, lookups and the Simple XML mount.
- `frontend/src/`: React/TypeScript interface and Splunk search provider.
- `fixtures/raw/` (NX-OS fabric) and `fixtures/raw-aci/` (ACI pilot): synthetic scenarios and TA-shaped HEC events, with per-field sources in each `FIELDS.md`.
- `fixtures/demo-*.json`: lab search output used by demo mode.
- `tests/splunk/`: local Splunk lab and data-layer tests.
- `tools/`: fixture generator and app packaging.
- `docs/`: pilot setup, data-layer contract, research and TA analysis.
- `docs/operators/`: what each team must configure, and the Splunk setup guide.
- `research/`: vendor package provenance. Downloaded archives and extracted files are git-ignored.

## Commands

| Command | Purpose |
| --- | --- |
| `npm run dev` | Local demo |
| `npm run lint` | ESLint, type checks and Prettier checks |
| `npm run format` | Format frontend and build files |
| `npm test` | Frontend unit tests (Vitest) |
| `npm run build` | Build standalone preview and Splunk assets |
| `npm run package` | Build, stage in `dist/stage/` and archive the Splunk app |
| `python3 tools/gen_raw_fixtures.py [--scenario aci]` | Regenerate the NX-OS (default) or ACI synthetic events |
| `tests/splunk/lab.sh up` / `install` / `purge` | Local Splunk lab lifecycle (Docker; see [PILOT.md](docs/PILOT.md#synthetic-fixtures-and-the-splunk-lab)) |
| `ADM_LAB=1 python3 -m unittest discover -s tests/splunk` | Data-layer tests against the lab |
| `ruff check tools tests` | Python lint (install Ruff separately) |

Python 3.10+ is needed only for the fixture generator and the lab tests. The lab needs Docker. It pulls a Splunk image of about 2 GB and accepts the Splunk General Terms for a local development instance.

## Documentation

- [Pilot setup and prerequisites](docs/PILOT.md)
- [What each team must provide](docs/operators/README.md), including the [Splunk setup guide](docs/operators/splunk-setup-guide.md)
- [Data layer contract](docs/DATA_LAYER.md)
- [Network path evidence](docs/NETWORK_PATH_DESIGN.md)
- [TA package analysis](docs/TA_PACKAGE_ANALYSIS.md)
- [Telemetry correlation design](docs/TELEMETRY_CORRELATION_DESIGN.md)
- [Stream and NetFlow research](docs/NETFLOW_DEPENDENCY_MAP_RESEARCH.md)
- [Research package inventory](research/README.md)
- [Contributor guidelines](AGENTS.md), [Operating model](docs/OPERATING_MODEL.md), [Security](docs/SECURITY.md)

## License

Licensed under the [Apache License, Version 2.0](LICENSE); see [NOTICE](NOTICE). The packaged Splunk app also includes `THIRD_PARTY_NOTICES.txt` with the licenses of the bundled frontend libraries (React, React DOM, scheduler, lucide-react).
