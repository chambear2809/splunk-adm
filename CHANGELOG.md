# Changelog

All notable changes to Application Atlas (`splunk_adm`) are documented in this
file. The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and the app version follows `package.json` and `default/app.conf`.

Each release lists the operator actions needed to update an existing
installation. Always follow the general procedure in
[docs/UPGRADES.md](docs/UPGRADES.md): update over the existing `splunk_adm`
installation with the single release archive, back up the `adm_*` KV
collections and record effective index and scope macros first, and review
effective `local/` overrides afterwards.

## [Unreleased]

### Changed

- The `adm_recovery` alert action now declares `python.required = 3.13`, matching
  every other shipped REST handler, command and alert action. Splunk Cloud
  disables Python 3.9, and the app already required 3.13 for its other entry
  points. `tools/check_release.py` now rejects any other recovery interpreter
  setting.
- CI's AppInspect gate uses `splunk-appinspect==4.4.0` (the version Splunk Cloud
  vetting reports) and inspects the exact packaged archive with the `cloud`,
  `private_victoria` and `private_classic` tags.

### Added

- CI jobs for the Go `otel_atlas_receiver` (`go mod verify`, `go vet`,
  `go test`), production npm and Python tool dependency audits, a
  checksum-verified gitleaks scan of the full git history and CodeQL analysis of
  JavaScript/TypeScript and Python. See [docs/CI.md](docs/CI.md).
- [docs/CLOUD_VETTING.md](docs/CLOUD_VETTING.md) records the AppInspect results
  and the disposition of each warning.

### Upgrade actions

- If a deployment has a `local/alert_actions.conf` override of
  `[adm_recovery] python.required`, remove it or set it to `3.13`; a local value
  takes precedence over the packaged default.

## [0.10.0] - 2026-11-26

### Added

- Shared saved views and business ownership, stored in the new insert-only
  revision ledgers `adm_saved_views` and `adm_business_ownership` and served by
  the `adm/collaboration` REST endpoint. They are designed to persist on Splunk
  Cloud and search head clusters through the KV Store. Saves stop at 1,024 records per ledger until an
  administrator compacts it (seal-then-epoch-root compaction).
- The administrator-only `adm/observer-mapping` REST endpoint for maintaining
  observer-to-scope mappings, with administrator write rechecks and bounded scans.
- Ecosystem TA adapters: new `adm_index_*` macros for Stream TCP, F5, HAProxy,
  AWS, Azure, GCP, Palo Alto, FortiGate and ServiceNow, plus the inert
  `adm_itsi_import_objects` and `adm_ifmib_capacity` placeholders. Atlas searches
  indexes that existing Splunkbase TAs already populate and ships no collector
  (see [docs/operators/ecosystem-tas.md](docs/operators/ecosystem-tas.md)).
- Four opt-in webhook alerts that ship disabled: _ADM - Newly blocked production
  dependency_, _ADM - Redundancy loss_, _ADM - Unexpected new dependency_ and
  _ADM - Telemetry blindness_.
- An assignable `adm_investigate` role that contains only the `adm_investigate`
  capability. The built-in `admin` and `sc_admin` roles receive the capability on
  install.
- Offline and connected change-scenario tooling: versioned scenario bundles,
  capture contracts, bounded query plans, a trusted query executor and transport,
  run authorization and physical readback verification, and opt-in host resource
  leases for task-owned labs.

### Changed

- The case request supervisor admits three concurrent requests instead of one.
  A request whose retirement is unproven keeps its slot until its process group
  is proven gone, and recycled process group IDs are never signalled
  ([docs/CASE_REQUEST_SUPERVISION.md](docs/CASE_REQUEST_SUPERVISION.md)).
- The `atlas_k8s_snapshot` receiver replaces its cumulative 16 MiB raw cap with a
  per-page `max_page_bytes` limit and logs fixed failure reason codes.
- `tools/import_configuration_changes.py` refuses to overwrite existing outputs
  unless `--overwrite` is given, and restores the previous HEC file if an
  overwrite fails.
- The optional configuration-history loader shares the optional-asset lifecycle,
  cleans up stale assets before retrying and validates packaged history assets in
  release checks.

### Security

- `role_adm_investigate` explicitly disables Splunk's implicit new-role
  capabilities (`run_collect`, `run_mcollect`, `edit_own_objects`,
  `list_all_objects`, `schedule_rtsearch`).
- The collaboration endpoint preserves other principals' private views across
  saves and distinguishes KV Store 403 responses from uncertain writes.
- Hardened Splunk REST handlers, SPL alert searches, frontend exports and release
  gates after an adversarial review, including Cilium policy output.

### Upgrade actions

Follow [docs/UPGRADES.md](docs/UPGRADES.md), then:

- **Roles.** Admin users gain `adm_investigate` through `admin`/`sc_admin`. To give
  a non-admin investigator access, assign the new `adm_investigate` role
  alongside an existing role that provides source access. Review any
  `local/authorize.conf` that overrides `[role_adm_investigate]`, `[role_admin]`
  or `[role_sc_admin]` for this app.
- **KV Store.** Include the new `adm_saved_views` and `adm_business_ownership`
  collections in KV backups. They are declared `replicate = false`. Check their
  ACLs after the update: read `*`, write `admin`/`sc_admin`
  ([docs/operators/splunk-platform.md](docs/operators/splunk-platform.md)).
- **REST endpoints.** The update adds the `adm/collaboration` and
  `adm/observer-mapping` handlers to `restmap.conf` and `web.conf`. Plan the
  restart your platform requires to load new REST endpoints, using the supported
  restart procedure for that platform.
- **Macros.** Point each new `adm_index_*` macro at the index its TA populates, or
  leave it on `index=unconfigured_optional`. As described in
  [docs/UPGRADES.md](docs/UPGRADES.md), an existing `local/macros.conf`
  definition takes precedence over the packaged default.
- **Alerts.** The four webhook alerts stay disabled until an administrator
  configures a webhook URL and enables them, after the summary and NetFlow macros
  are populated.
- **Rollback.** Before rolling back to 0.9.x, back up both collaboration
  ledgers. Older releases do not read them.
