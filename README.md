# Application Atlas

**Application dependency mapping in Splunk.** Application Atlas connects network flows, Kubernetes history, application traces and Cisco infrastructure data to show who talks to what, over which ports, and how clients reach an application.

## Why it matters

IP addresses change, workloads move, and dependency evidence is spread across network, platform and application tools. Atlas brings that context together to help teams:

- **Troubleshoot:** connect clients, services, workloads and external systems with traffic observations.
- **Plan changes:** identify dependencies before migrations, network changes or segmentation.
- **Review connectivity:** export required flows and inspect ACI policy context and evidence gaps.

The map distinguishes observations from inferred candidate paths. Missing data stays unresolved; it is never replaced with demo data.

## Products and what each must provide

**Splunk is required; other products depend on the features you need.** Network conversations require a supported traffic feed. Kubernetes history and traces add workload and application context.

| Product                                                                            | What it adds                                                                           | Required configuration or data                                                                                                       |
| ---------------------------------------------------------------------------------- | -------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------ |
| [**Splunk Enterprise**](docs/operators/splunk-platform.md)                         | Search, correlation, history and the Atlas interface                                   | Healthy KV Store; source and summary indexes; index permissions and routing-scope mappings.                                          |
| [**Splunk Stream + NetFlow/IPFIX exporters**](docs/operators/network-stream.md)    | Connections, ports, traffic counters and observing devices                             | Stream add-ons, a receiver and an enabled NetFlow stream; endpoint, time, exporter, interface and sampling fields.                   |
| [**Cisco ACI / APIC**](docs/operators/aci-network.md)                              | Endpoint identity, EPG/bridge-domain context, candidate fabric paths and policy intent | DC Networking add-on, read-only APIC access, and endpoint, topology and policy inputs.                                               |
| [**Nexus Dashboard / NX-OS**](docs/operators/aci-network.md)                       | Flow, endpoint, device and interface context                                           | DC Networking add-on; applicable flow/endpoint inputs and device/interface/neighbor collection.                                      |
| [**Kubernetes + Splunk OTel Collector**](docs/operators/kubernetes-platform.md)    | Pod/workload identity and Service/backend history                                      | Cluster identity, RBAC, object watches with initial state, and HEC delivery to Splunk.                                               |
| [**Cilium / Hubble**](docs/operators/cilium-isovalent.md)                          | Pod-level flows and evidence linking Service frontends to backends                     | Hubble JSON-lines flow export, collector file tailing, cluster identity and load-balancing settings.                                 |
| [**Isovalent Runtime Security**](docs/operators/cilium-isovalent.md)               | Process connection evidence                                                            | Cisco Security Cloud add-on, `processConnect` events through HEC, and a source-to-cluster mapping.                                   |
| [**Applications using OpenTelemetry**](docs/operators/application-teams.md)        | Service calls and service-to-workload bindings                                         | OTLP export, service/environment/pod attributes, and CLIENT spans with peer IP, port and timestamps.                                 |
| [**Cisco FMC / FTD**](docs/operators/firewall-security.md)                         | Firewall observations for traffic crossing FTD                                         | Cisco Security Cloud add-on and eStreamer connection events.                                                                         |
| [**Catalyst Center — optional V2**](docs/operators/cisco-enterprise-networking.md) | Wired-client identity and attachment observations                                      | Enterprise Networking add-on, scoped client API access and explicit source profiles.                                                 |
| [**Meraki — optional V2**](docs/operators/cisco-enterprise-networking.md)          | Wireless-client attachment context                                                     | Meraki add-on, association events, compatible flow evidence and source profiles. NetFlow alone cannot establish wireless attachment. |

Optional SD-WAN IPFIX retains overlay references, not router/tunnel topology. Verify exact product versions and compatibility in the guides.

## Get started

**Try the demo:** use Node 22.13+ within 22.x, 24.x or 26+, and npm.

```sh
git clone --recurse-submodules https://github.com/chambear2809/splunk-adm.git
cd splunk-adm
npm ci --registry=https://registry.npmjs.org --ignore-scripts
npm run dev
```

Open the localhost URL; the captured synthetic demos need no Splunk connection.

**Use your data:** follow the [operator setup sequence](docs/operators/splunk-setup-guide.md). Atlas reads indexed data; operators configure collectors, indexes, permissions, scopes and deployment expectations. Searches and settings writes ship disabled; settings persistence requires deployment qualification. V2 activation follows the [migration procedure](docs/CISCO_CONTRACT_MIGRATION.md).

**Develop/package:** `npm run lint`, `npm test`, `npm run package` (requires `tar`). The archive and checksum appear in `dist/`. See [build/lab requirements](docs/PILOT.md) and [CI](docs/CI.md).

## Project status

Recorded qualification covers **Splunk Enterprise 10.6.0.5** with synthetic data: standalone execution, V2 migration and bounded same-host SHC validation. Production capacity/topology, real controller/exporter collection, customer pilots and Splunk Cloud runtime/vetting remain unqualified. SHC validation does not authorize V2 cutover there. See [qualification evidence and limits](docs/ATLAS_FINAL_QUALIFICATION.md).

## Operator setup skills

Pinned automation in `vendor/splunk-cisco-skills` supports Claude Code, Cursor and Codex. Follow [team setup guides](docs/operators/README.md) and [skill/credential instructions](AGENTS.md#operator-setup-skills); MCP mutations ship disabled.

## Further reading

- [Data and correlation contract](docs/DATA_LAYER.md) · [Deployment expectations and health](docs/DEPLOYMENT_HEALTH.md)
- [Upgrades](docs/UPGRADES.md) · [Backup/restore](docs/BACKUP_RESTORE.md) · [Recovery](docs/RECOVERY.md)
- [Contributing](AGENTS.md) · [Security](docs/SECURITY.md)

Licensed under [Apache 2.0](LICENSE); see [NOTICE](NOTICE).
