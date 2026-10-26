# ThousandEyes qualification

Status: implementation in progress; no production qualification is claimed.

Baseline: `1e4f2043ffc095ed0d87a090f572178bd204b134`.
The [design](THOUSANDEYES_DESIGN.md) defines required semantics, ownership,
acceptance and resource controls. Vendor support/version evidence belongs in
`docs/research/thousandeyes.md` and its capability matrix.

The coordinator's actual session metadata confirms `gpt-6.1-sol / medium`.
The user changed Luna workstreams to `gpt-6-luna / max`; the first replacement
worker's metadata confirms that assignment. Independent review must use
`gpt-6-astra / medium` and remains pending. No permanent project agent preference
was changed. Retired or preflight-only agents do not provide feature approval.

Commands, candidate/package hashes, reports, benchmark conditions, actual
assignments and task-resource cleanup are retained in the ignored
`dist/thousandeyes-qualification/` evidence directory. This document will name
the final candidate and distinguish synthetic installed behavior from genuine
producer/deployment qualification before PR/merge.
