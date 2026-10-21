# Automated assisted recovery for the ADM - Scheduler missed-slot alert.
# See docs/RECOVERY.md before enabling. Override only in local/adm_recovery.conf.
# Budgets above the shipped defaults are refused as outside qualified limits.

[recovery]

enabled = <boolean>
* Defaults to 0. The action refuses to run unless this is 1 and the saved
  search's action.adm_recovery is also enabled.

management_uri = <https origin>
* Defaults to https://localhost:8089.
* Must be an HTTPS origin on localhost, 127.0.0.1 or ::1 with no path,
  query, fragment or credentials.

ca_file = <path>
* Defaults to empty, which uses the platform CA bundle.
* Certificate verification is never disabled.

initial_backlog_limit = <positive integer>
* Defaults to 4 (maximum). Maximum missed slots in the initial plan; a larger
  backlog is refused before the schedule is paused.

total_slot_limit = <positive integer>
* Defaults to 8 (maximum). Must be at least initial_backlog_limit.

slot_timeout_seconds = <positive integer>
* Defaults to 120 (maximum). Per-slot replay search timeout.

pause_cap_seconds = <positive integer>
* Defaults to 1080 (maximum). Longest time the target schedule stays paused.

action_deadline_seconds = <positive integer>
* Defaults to 1260 (maximum). Overall action deadline.

lease_seconds = 1800
* Fixed at 1800. Any other value is refused.

preflight_seconds = <positive integer>
* Defaults to 60 (maximum). Deadline for deployment and target preflight.

cleanup_seconds = <positive integer>
* Defaults to 120 (maximum). Time reserved to restore the target schedule.

manifest_count_limit = <positive integer>
* Defaults to 10000 (maximum). Largest accepted search result count.
