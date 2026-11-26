# Atlas TA release snapshots (historical / deprecated)

> **Deprecated — retained for rollback/audit only:** Application Atlas now targets official, unmodified Splunkbase add-ons — **Cisco DC Networking 2.0.10 (Splunkbase 7777)** and **Splunk Add-on for AppDynamics 3.3.0 (Splunkbase 3471)**. See [`docs/operators/official-splunkbase-tas.md`](../../docs/operators/official-splunkbase-tas.md) for the supported official-TA configuration. Do **not** deploy these historical modified vendor builds on new environments; these snapshots remain in the repository solely for audit and rollback until live validation completes and removal is explicitly approved.

`20261031-r1/` preserves our historical deployed AppDynamics 3.3.0 and Cisco DC Networking 1.2.2 modifications. These are Atlas builds based on those vendor versions, not official vendor releases.

Each release contains a `manifest.json` and `files/` with every added or changed package file, including configuration defaults and embedded Atlas source. Apply the listed additions/replacements to the pinned vendor archive to recover the deployed file contents. No vendor files were deleted. The manifest records archive modes and SHA-256 checksums. These source snapshots can be versioned with this project; no commit has been made.

The exact installable archives live under `research/packages/atlas/`. Vendor baselines remain under `research/packages/`. Those binary archives are ignored by Git under the project's existing policy; keep a separate backup when moving or cloning the project. `research/package-manifest.json` records both vendor and modified archive checksums.

These are release records, not live development directories. Active overlay source and builders live in the Atlas development worktree under `integrations/*_ta_overlay/` and `tools/package_*_ta_overlay.py`. The source snapshot remains valid as development continues. Host-local configuration, credentials, tokens, and `.env` files are excluded.

`20261031-r2-candidate/dc-networking/` preserves the opt-in ACI poll v2 candidate, adding explicit `fvRsCtx` collection. It was subsequently deployed on the HF with v2 explicitly enabled; the first scheduled 515-event capture passed validation. The original snapshot manifest records its status at archive time. Existing v1 validation and r1 archives are retained. Cloud R5 now consumes v2 and supports explicit administrator-provided routing-domain bindings. The TA archive alone does not establish a qualified device path.

## Native Kubernetes point receiver

The Atlas receiver source is in `integrations/otel_atlas_receiver/`, with a pinned full-collector builder in `tools/build_atlas_otel_collector.py`. The reviewed custom 0.164.0 Linux binary, build manifest and pinned image archive are in `research/packages/atlas/`; their hashes and current validation status are in `research/package-manifest.json`. This is an Atlas collector distribution, not a signed vendor TA. The native receiver is deployed on the cluster receiver. Two production Node and two Pod generations passed source, count, digest and time validation through the existing `k8s` route; point snapshots do not establish continuous ownership. The digest alias archive preserves the exact platform image reference for offline MicroK8s import. See `docs/DEVICE_PATH_QUALIFICATION_STATUS.md` for current evidence and operational limits.
