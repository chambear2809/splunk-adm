# Splunk Application Dependency Mapping

**Application Atlas** is a React Splunk app pilot for mapping an OpenTelemetry
application in Kubernetes from its frontend entry boundary to downstream services,
pods and network endpoints. It combines trace relationships with time scoped
Kubernetes inventory and Stream NetFlow evidence. The initial implementation
includes a synthetic demo and an offline graph projector.

## Quick start

```sh
npm ci --registry=https://registry.npmjs.org --ignore-scripts
npm run dev
```

Open the localhost URL printed by Vite. No Splunk or Kubernetes connection is
needed for demo mode. Build a Splunk app archive with `npm run package`.

**Target:** Splunk 10.6. The package has not been installed or validated in a live
Splunk instance. Cisco enrichment and automatic collection are not yet implemented.

## Project layout

- `frontend/src/`: React/TypeScript interface, graph renderer and Splunk provider.
- `src/splunk_adm/`: bounded Python telemetry projector.
- `tools/`: projection CLI and app packaging.
- `fixtures/`: synthetic OTLP, pod inventory, flows, and generated snapshots.
- `splunk_app/splunk_adm/`: app configuration and Simple XML React mount.
- `docs/`: pilot instructions, graph contract, research and TA analysis.
- `research/`: vendor package provenance; archives/extractions remain ignored.

## Commands

| Command | Purpose |
| --- | --- |
| `npm run dev` | Local React demo |
| `npm run typecheck` | TypeScript compilation checks |
| `npm run lint` | ESLint, type checks and Prettier checks |
| `npm run format` | Format frontend and build files |
| `npm run build` | Build standalone preview and Splunk assets |
| `npm run package` | Build and archive the Splunk app |

No test suite is configured in this initial implementation.

## Documentation

- [Pilot setup and live-data prerequisites](docs/PILOT.md)
- [Graph contract and boundary semantics](docs/GRAPH_CONTRACT.md)
- [Stream and NetFlow research](docs/NETFLOW_DEPENDENCY_MAP_RESEARCH.md)
- [Telemetry correlation design](docs/TELEMETRY_CORRELATION_DESIGN.md)
- [Downloaded TA analysis](docs/TA_PACKAGE_ANALYSIS.md)
- [Research package inventory](research/README.md)
- [Contributor guidelines](AGENTS.md), [Operating model](docs/OPERATING_MODEL.md), [Security](docs/SECURITY.md)
