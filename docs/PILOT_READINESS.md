# Pilot readiness checker

`tools/pilot_readiness.py` is a read-only analyzer for preparing an Application
Atlas pilot. It checks only sources explicitly selected by the operator. An
unselected vendor or source is reported as `not_selected`; it is never treated
as an outage or as a requirement that every vendor be installed.

The analyzer reports these states:

- `blocked`: a selected source has an invalid or empty index macro, a required
  builder is disabled, or effective permissions do not support the app's
  read/write and owner-dispatch contract;
- `warning`: quality rows contain excluded/accepted-with-warning records,
  observers are unmapped, a prune is enabled, or the app version differs;
- `unknown`: visibility, quality, mapping, schedule, permission, or app
  evidence was unavailable. Restricted indexes and REST/search access are
  evidence limits, not proof of an outage;
- `pass`, `ready`: the observed checks passed. A report with any required
  `unknown` evidence cannot be `ready`.

Quality evidence follows `adm_health_quality`: rows are grouped by
`source`/`status`/`reason`/`records`. The `reason=evaluated` row supplies the
candidate count; invalid-field and `unmapped_scope` reason rows are counted
separately and may overlap.

The lab-only command uses the existing localhost helpers in
`tests/splunk/lab.py` and performs GETs plus read-only searches:

```sh
python3 tools/pilot_readiness.py --lab --source netflow --source k8s --json
```

At least one `--source` is required. Valid values are `netflow`, `dcn`, `ftd`,
`isovalent`, `k8s`, `traces`, `hubble`, and `summary`. Without `--lab`, the
CLI analyzes an empty snapshot and is useful for exercising output shape; a
future connector can call `analyze(snapshot, selected_sources)` directly. The
checker does not accept credentials or URLs, dispatch saved searches, write
lookups/KV collections, change schedules, or dump secret configuration.

The current lab adapter is intentionally limited: it cannot establish live
collector configuration, exporter delivery, sampling accuracy, or visibility
outside the lab user's permissions. Scope mapping and quality evidence should
therefore be read as bounded evidence from the current Splunk context.

The raw Kubernetes readiness probe counts only eligible pod objects: it
excludes `DELETED` events and Pending pods, because those objects may not yet
have an assigned pod IP. The traces probe checks the fields required by the
service-binding builder plus numeric, ordered span times and therefore covers Kubernetes-correlated service
binding evidence only. The summary probe checks client/server/records coverage;
replay identity coverage is reported separately as a warning for legacy rows.

Exit codes are `0` for ready/warning, `1` for blocked, and `2` for unknown.
Warnings remain visible and should be assessed before a pilot. An unavailable
macro lookup is unknown; a confirmed empty or invalid definition is blocked.
