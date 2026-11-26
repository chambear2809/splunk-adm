# Application Atlas support matrix

Atlas does not support "Splunk Enterprise 10.6 or later" as a blanket range. Each feature has its own runtime gate in the shipped code, and each gate admits only the platforms, builds and topologies that have qualification evidence. If a gate refuses the server, that feature stays read-only or unavailable. This is by design, not a fault to work around. Do not write KV rows directly or edit gate constants to get past a refusal.

This page is derived from the shipped gates (`splunk_app/splunk_adm/bin/`, `default/*.conf`) and the qualification records in [FEATURE_QUALIFICATION.json](../FEATURE_QUALIFICATION.json), [FEATURE_DELIVERY.md](../FEATURE_DELIVERY.md), [ATLAS_FINAL_QUALIFICATION.md](../ATLAS_FINAL_QUALIFICATION.md), [SHC_QUALIFICATION.md](../SHC_QUALIFICATION.md) and [validation/RUN_STATUS.md](../validation/RUN_STATUS.md). When a gate changes, update this page in the same change.

## Platform floor: Python 3.13

Every Atlas REST handler (`restmap.conf`: settings, investigations, dependency monitoring, collaboration, observer mapping), both custom search commands (`commands.conf`: `admqualified`, `admacipoll`) and the dependency-watch alert action declare `python.required = 3.13`. The recovery action declares `3.9,3.13`. Splunk selects only interpreters from that list ([restmap.conf `python.required`](https://help.splunk.com/en/data-management/splunk-enterprise-admin-manual/10.4/configuration-file-reference/10.4.6-configuration-file-reference/restmap.conf), [commands.conf `python.required`](https://help.splunk.com/en/splunk-enterprise/administer/admin-manual/10.6/configuration-file-reference/10.6.2-configuration-file-reference/commands.conf)). A platform that does not ship Python 3.13 cannot run these components, so it sits below the Atlas floor whatever its version string. Atlas targets 10.6; Splunk 10.4 was explicitly ruled out ([UI Toolkit decision](../SPIKE-UITK.md)). Installed qualification used embedded Python 3.13.11.

## Feature by platform

Key:

- **Qualified**: the code admits this platform and a recorded installed run passed (scope as noted).
- **Admitted, unqualified**: the code admits it, but no complete installed qualification has passed.
- **Unverified**: no code gate blocks it, and no qualification record exists.
- **Refused**: the code rejects it, so the feature stays read-only or unavailable.

| Feature | Enterprise 10.6.0.5, standalone | Enterprise 10.6.1.1 build `b2ae2962645c`, standalone | Other Enterprise 10.6.x builds | Enterprise 10.6.0.5 search head cluster | Splunk Cloud Platform |
| --- | --- | --- | --- | --- | --- |
| Read-only V1 views (Explore, Device, Map, Impact, Services, catalog) | Qualified: full installed suite on synthetic data | Admitted, unqualified: candidate 0.9.3 installed with bounded role and settings checks; the full qualification has not passed | Unverified | Qualified for synthetic, same-host three-member SHC only; production topology unverified | Installed through private-app vetting (0.9.1–0.9.3) on a stack reporting 10.6.0.5. Trace and Device rendered; the catalog and map scope options reported incomplete identity evidence. Not a formal Cloud runtime qualification |
| Setup writes (`adm_settings`, ship disabled) | Qualified in `single_namespace` and `qualified_shc` modes | Admitted in `single_namespace` mode only; installed write, authorization and concurrency qualification pending | Refused (read-only) | Qualified for synthetic same-host SHC (`qualified_shc`: at least 3 healthy peers on one version) | Refused (read-only) |
| Cases (`adm_investigations`, ship disabled) | Admitted: installed functional rehearsal on emulated Linux/amd64. Native, real-source and production qualification pending | Admitted, unqualified | Refused | Refused | Refused |
| Baselines and dependency watch (ship disabled) | Admitted: metadata and owner-private storage only. No production source provider ships, so capture and evidence fail closed | Admitted, unqualified (same limits) | Refused | Refused | Refused |
| Collaboration (shared saved views, business ownership) | Unverified on an installed host; unit-tested only. Writes are administrator-only | Unverified | Unverified | Unverified | Unverified; needs the `adm_investigate` grant (see [Cloud roles](#splunk-cloud-roles)) |
| Automated assisted recovery (ships disabled) | Qualified: core milestone live tests | Admitted, unqualified | Refused | Refused | Refused |
| Cisco V2 migration helper (external tool) | Qualified live | Admitted, unqualified | Admitted, unqualified (any `10.6.x` patch) | Refused | Refused |

## What each gate checks

- **Setup writes**: `bin/adm_settings_lib/rest.py`. Requires `adm_settings.conf` `write_mode` set to `single_namespace` or `qualified_shc` and `platform = enterprise`. Also requires `product_type = enterprise` and no Cloud markers or Cloud license group. The cohosted PDL KV Store must be ready, outside migration, upgrade or backup. Version must be `QUALIFIED_VERSIONS` (10.6.0.5); 10.6.1.1 build `b2ae2962645c` is admitted only in `single_namespace`. `single_namespace` requires a standalone KV Store whose GUID matches the server. `qualified_shc` requires at least three registered peers, a stable captain, no rolling restart or upgrade, and matching peer versions. The caller needs `admin_all_objects` and collection write. See [deployment health](../DEPLOYMENT_HEALTH.md#supported-write-contract-and-deployment-gate).
- **Cases and Baselines**: `bin/adm_cases_lib/splunk_host.py`, which Baselines reuses. Requires `mode = single_search_head` and `platform = enterprise`. Requires `product_type = enterprise`, version 10.6.0.5 or 10.6.1.1 build `b2ae2962645c`, and no Cloud markers. The active license group must be Trial or Enterprise. Search head clustering must be disabled. Every request needs the `adm_investigate` capability. The request supervisor runs only on Linux. Baselines also require `source_mode = unavailable`.
- **Recovery**: `bin/adm_recovery_lib/core.py`. Requires version 10.6.0.5 or 10.6.1.1 build `b2ae2962645c`, `product_type = enterprise` and no `instance_type`. Server roles must be exactly indexer, KV Store and local license manager. The server must not forward and must have no SHC, no indexer clustering and no remote search peers. The owner must be `admin`/`sc_admin` with `search`, `schedule_search`, `run_collect` and `output_file`. See [recovery](../RECOVERY.md).
- **Read-only views and collaboration** have no platform gate. They depend on the Python 3.13 floor, the Atlas viewer role (see [Roles](splunk-platform.md#roles-and-kv-store)) and index access.

## Other builds and Splunk Cloud

A server outside the admitted set still loads the app. Read-only views work subject to the Python floor and permissions, and gated features report themselves unavailable or read-only. Setup shows that writes are not qualified for the reported server. Case and baseline routes fail closed. Recovery refuses before changing any writer. To add a build, qualify it on an installed target, record the evidence, then change the gate and this page together.

### Splunk Cloud roles

Splunk Cloud Platform manages roles only through Splunk Web ([About configuring role-based user access](https://help.splunk.com/en/splunk-cloud-platform/administer/manage-users-and-security/10.8/manage-splunk-platform-users-and-roles/about-configuring-role-based-user-access)). Do not assume the `adm_viewer` and `adm_investigate` roles in the app's `authorize.conf` exist on a Cloud stack. Installed Cloud checks of 0.9.1–0.9.3 returned 403 on the `adm_investigate` routes, and no role grant was made. Before granting access on Cloud, an `sc_admin` creates the roles in Splunk Web as described in [Splunk platform setup](splunk-platform.md#roles-and-kv-store).
