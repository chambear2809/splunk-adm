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

Requires Node 22.13+ within the 22.x series, 24.x, or 26+ and npm (Node 25 is not supported by Vitest). CI uses Node 22.13.0. Packaging also requires `tar`. Clone with submodules so the vendored operator setup skills (`vendor/splunk-cisco-skills`, see [below](#operator-setup-skills)) are present:

```sh
git clone --recurse-submodules https://github.com/chambear2809/splunk-adm.git
cd splunk-adm
# or, if already cloned: git submodule update --init
npm ci --registry=https://registry.npmjs.org --ignore-scripts
npm run dev
```

Open the localhost URL printed by Vite. Demo mode needs no Splunk connection. It replays the app's own search output from TA-shaped synthetic data: the ACI pilot scenario by default, or the NX-OS fabric scenario (switch in **Settings**). Build Splunk app archives with `npm run package`.

The additional **Catalyst → ACI** and **Meraki wireless → NX-OS** demos use two separate Kubernetes clusters and applications. Their captured results include source-qualified client identity, attachment history, and traffic observations. Wireless attribution is correlated from Meraki association events and switch-exported flows; NetFlow alone does not establish wireless attachment. The Cisco integration is an optional V2 contract with a staged migration. See [qualification status](docs/CISCO_NETWORKING_QUALIFICATION.md) before enabling it.

Packaging creates `dist/splunk_adm-<version>.tar.gz` and its SHA256 file. The same archive installs and updates the app; deployment-owned state lives in KV store and `local/`. See [upgrade preservation checks](docs/UPGRADES.md).

**Targets:** Splunk Cloud and Splunk Enterprise 10.6+. The pilot is a single ACI fabric with Kubernetes on Cilium. Recorded qualification covers Splunk Enterprise 10.6.0.5 with synthetic data: the complete standalone installed suite, separate V2 migration/browser acceptance, and a bounded same-host SHC deployment. Cloud runtime, formal vetting, real controller/exporter collection, production topology/capacity and a customer pilot remain unqualified. See [current engineering qualification](docs/ATLAS_FINAL_QUALIFICATION.md) and the [SHC procedure and limits](docs/SHC_FINAL_QUALIFICATION.md).

## Install in Splunk

Choose [deployment options](docs/operators/deployment-options.md), then follow the [operator setup sequence](docs/operators/splunk-setup-guide.md) to install the archive, create the summary index, configure source-index macros and viewer permissions, populate observer scopes, save qualified deployment expectations, and enable the searches required by the selected sources. Settings writes require the [deployment persistence gate](docs/DEPLOYMENT_HEALTH.md#supported-write-contract-and-deployment-gate). The app does not collect source data or create indexes, and its saved searches ship disabled. Existing installations must follow the [upgrade procedure](docs/UPGRADES.md), including any required scope migration, before enabling searches.

## Project layout

- `splunk_app/splunk_adm/`: app configuration, macros, saved searches, KV store collections, lookups and the Simple XML mount.
- `frontend/src/`: React/TypeScript interface and Splunk search provider.
- `fixtures/raw/` (NX-OS fabric) and `fixtures/raw-aci/` (ACI pilot): synthetic scenarios and TA-shaped HEC events, with per-field sources in each `FIELDS.md`.
- `fixtures/raw-networking/`: combined Catalyst and Meraki scenario; `fixtures/demo-networking-*.json` contains captures from the implemented Splunk pipeline with provenance.
- `fixtures/demo-*.json`: lab search output used by demo mode.
- `tests/splunk/`: local Splunk lab and data-layer tests.
- `tools/`: fixture generator and app packaging.
- `docs/`: pilot setup, data-layer contract, research and TA analysis.
- `docs/operators/`: what each team must configure, and the Splunk setup guide.
- `research/`: vendor package provenance. Downloaded archives and extracted files are git-ignored.
- `vendor/splunk-cisco-skills/`: pinned submodule of operator setup automation (see below).

## Commands

| Command                                                                                        | Purpose                                                                                                  |
| ---------------------------------------------------------------------------------------------- | -------------------------------------------------------------------------------------------------------- |
| `npm run dev`                                                                                  | Local demo                                                                                               |
| `npm run lint`                                                                                 | ESLint, type checks and Prettier checks                                                                  |
| `npm run format`                                                                               | Format frontend and build files                                                                          |
| `npm test`                                                                                     | Frontend unit tests (Vitest)                                                                             |
| `npm run typecheck:browser` / `npm run test:browser`                                           | Browser test type checks / Playwright regressions (see [browser setup](docs/BROWSER_TESTS.md))           |
| `npm run build`                                                                                | Build standalone preview and Splunk assets                                                               |
| `npm run package`                                                                              | Build, stage in `dist/stage/` and archive the Splunk app                                                 |
| `python3 tools/gen_raw_fixtures.py [--scenario aci]`                                           | Regenerate the NX-OS (default) or ACI synthetic events                                                   |
| `tests/splunk/lab.sh up` / `install` / `purge`                                                 | Local Splunk lab lifecycle (Docker; see [PILOT.md](docs/PILOT.md#synthetic-fixtures-and-the-splunk-lab)) |
| `ADM_LAB=1 python3 tools/lab_lock.py --root . -- python3 -m unittest discover -s tests/splunk` | Data-layer tests against the lab                                                                         |
| `ruff check tools tests`                                                                       | Python lint (install Ruff separately)                                                                    |
| `ruff format --check tools tests`                                                              | Python formatting checks                                                                                 |
| `python3 -m unittest discover -s tests -p 'test_*.py'`                                         | Offline Python tests                                                                                     |

Python tooling and lab tests require Python 3.10+; the frontend demo does not require Python. Use Python 3.11 for AppInspect, as described in [pilot validation](docs/PILOT.md#build-and-test).

The lab requires Docker and the extracted Stream Wire Data 8.1.6, Cisco Security Cloud 3.7.2, and Cisco DC Networking 1.2.2 add-ons under `research/extracted/`; these ignored vendor artifacts are not included in a clone. See the [package manifest](research/package-manifest.json) for provenance and checksums and [CI artifact preparation](docs/CI.md) for extraction instructions. The full lab suite also requires a built archive and Playwright Chromium; follow the [complete lab lifecycle](docs/PILOT.md#synthetic-fixtures-and-the-splunk-lab), which handles exclusive ownership and cleanup. Starting the lab pulls a Splunk image of about 2 GB and accepts the Splunk General Terms for a local development instance.

## Pipeline health

Administrators configure shared source selection, cadence and receipt freshness in **Setup** after qualifying persistence. With no saved expectations, deployment health remains unknown; source receipt alone never selects sources. Saving expectations does not configure collectors or activate V2. See [deployment health and write prerequisites](docs/DEPLOYMENT_HEALTH.md).

In the installed app, choose **Data health** to inspect source freshness, ingestion delay, and scheduled-search outcomes. Health is app-wide and available even before a map loads. Missing data or restricted permissions are shown as unconfirmed; synthetic demo data is never presented as live health. See [the health contract](docs/DATA_LAYER.md#pipeline-health-and-search-completeness).

## Operator setup skills

What each team must configure to get data into Splunk ([docs/operators/](docs/operators/README.md)) can be automated with [splunk-cisco-skills](https://github.com/chambear2809/splunk-cisco-skills), vendored here as a submodule pinned to a reviewed commit so a pilot always uses the version we validated. Each skill renders a plan for review, applies only the requested change, and validates it.

Discoverable from:

- **Claude Code** — project skills under `.claude/skills/<name>/`, or the `splunk-cisco-skills` MCP server (`.mcp.json`).
- **Cursor** — project skills under `.cursor/skills/<name>/`, or its MCP server (`.cursor/mcp.json`).
- **Codex** — the MCP server registered in `.codex/config.toml`, or run scripts directly from the submodule.

The MCP server needs its own virtualenv once:

```sh
cd vendor/splunk-cisco-skills
python3 -m venv .venv
.venv/bin/pip install --index-url https://pypi.org/simple -r requirements-agent.txt
```

Mutating execution stays disabled in every committed registration (`SPLUNK_SKILLS_MCP_ALLOW_MUTATION=0`). See [AGENTS.md](AGENTS.md#operator-setup-skills) and the submodule's own `README.md`/`CLAUDE.md` for credential handling and script usage. To update the pin: `cd vendor/splunk-cisco-skills && git fetch && git checkout <reviewed commit>`, then commit the submodule bump here.

## Documentation

- [Deployment options and behavior without optional products](docs/operators/deployment-options.md)
- [Current engineering qualification](docs/ATLAS_FINAL_QUALIFICATION.md) and [SHC evidence and limits](docs/SHC_FINAL_QUALIFICATION.md)
- [Deployment expectations and health](docs/DEPLOYMENT_HEALTH.md)
- [Pilot setup and prerequisites](docs/PILOT.md)
- [Cisco networking integration and qualification](docs/CISCO_NETWORKING_QUALIFICATION.md)
- [Cisco source setup and telemetry limits](docs/operators/cisco-enterprise-networking.md)
- [V2 staged migration and rollback](docs/CISCO_CONTRACT_MIGRATION.md)
- [What each team must provide](docs/operators/README.md), including the [Splunk setup guide](docs/operators/splunk-setup-guide.md)
- [Data layer contract](docs/DATA_LAYER.md)
- [Recovery, replay and maintenance](docs/RECOVERY.md)
- [Synthetic pipeline benchmarks](docs/BENCHMARKS.md)
- [Continuous-load correctness soak](docs/CONTINUOUS_LOAD.md)
- [Actual scheduler and downtime testing](docs/SCHEDULER_TESTS.md)
- [Mixed-source load and attribution](docs/MIXED_LOAD.md)
- [Data quality and pipeline health](docs/DATA_QUALITY.md)
- [Browser regression tests](docs/BROWSER_TESTS.md)
- [Upgrade preservation checks](docs/UPGRADES.md)
- [Backup and restore rehearsal](docs/BACKUP_RESTORE.md)
- [Process interruption rehearsal](docs/FAILURE_TESTS.md)
- [Read-only pilot readiness](docs/PILOT_READINESS.md)
- [Network path evidence](docs/NETWORK_PATH_DESIGN.md)
- [TA package analysis](docs/TA_PACKAGE_ANALYSIS.md)
- [Telemetry correlation design](docs/TELEMETRY_CORRELATION_DESIGN.md)
- [Stream and NetFlow research](docs/NETFLOW_DEPENDENCY_MAP_RESEARCH.md)
- [Research package inventory](research/README.md)
- [Continuous integration](docs/CI.md)
- [Contributor guidelines](AGENTS.md), [Operating model](docs/OPERATING_MODEL.md), [Security](docs/SECURITY.md)

## License

Licensed under the [Apache License, Version 2.0](LICENSE); see [NOTICE](NOTICE). The packaged Splunk app also includes `THIRD_PARTY_NOTICES.txt` with license texts for frontend runtime dependencies, including React, Splunk UI libraries, styled-components, and lucide-react.
