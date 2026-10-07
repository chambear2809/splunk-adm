# Splunk Application Dependency Mapping

**Application Atlas** is a Splunk app that maps application dependencies from the network's point of view. Scheduled searches combine Splunk Stream NetFlow, Cisco Nexus Dashboard / NX-OS / ACI, Cisco FTD and Isovalent connection evidence with Kubernetes pod history and OpenTelemetry traces from the Splunk OTel Collector. The UI shows which workloads talk to what, over which ports, seen by which devices, and how confident each identification is.

## Quick start

```sh
npm ci --registry=https://registry.npmjs.org --ignore-scripts
npm run dev
```

Open the localhost URL printed by Vite. Demo mode needs no Splunk connection and replays search results produced from TA-shaped synthetic data. Build a Splunk app archive with `npm run package`.

**Target:** Splunk Enterprise 10.6 (pilot), Splunk Cloud. Validated in a local Splunk 10.6 container against synthetic data; not yet run against a live environment.

## Project layout

- `splunk_app/splunk_adm/`: app configuration, macros, saved searches, KV store collections and the Simple XML mount.
- `frontend/src/`: React/TypeScript interface and Splunk search provider.
- `fixtures/raw/`: synthetic scenario and TA-shaped HEC events; `fixtures/demo-*.json`: lab search output used by demo mode.
- `tests/splunk/`: local Splunk lab and data-layer tests.
- `tools/`: fixture generator and app packaging.
- `docs/`: pilot setup, data-layer contract, research and TA analysis.
- `research/`: vendor package provenance; archives/extractions remain ignored.

## Commands

| Command | Purpose |
| --- | --- |
| `npm run dev` | Local demo |
| `npm run lint` | ESLint, type checks and Prettier checks |
| `npm run format` | Format frontend and build files |
| `npm test` | Frontend unit tests (Vitest) |
| `npm run build` | Build standalone preview and Splunk assets |
| `npm run package` | Build, stage in `dist/stage/` and archive the Splunk app |
| `python3 tools/gen_raw_fixtures.py` | Regenerate TA-shaped synthetic events |
| `tests/splunk/lab.sh up` / `install` / `purge` | Local Splunk lab lifecycle |
| `ADM_LAB=1 python3 -m unittest discover -s tests/splunk` | Data-layer tests against the lab |
| `ruff check tools tests` | Python lint (install Ruff separately) |

## Documentation

- [Pilot setup and prerequisites](docs/PILOT.md)
- [Data layer contract](docs/DATA_LAYER.md)
- [Network path evidence](docs/NETWORK_PATH_DESIGN.md)
- [TA package analysis](docs/TA_PACKAGE_ANALYSIS.md)
- [Telemetry correlation design](docs/TELEMETRY_CORRELATION_DESIGN.md)
- [Stream and NetFlow research](docs/NETFLOW_DEPENDENCY_MAP_RESEARCH.md)
- [Research package inventory](research/README.md)
- [Contributor guidelines](AGENTS.md), [Operating model](docs/OPERATING_MODEL.md), [Security](docs/SECURITY.md)
