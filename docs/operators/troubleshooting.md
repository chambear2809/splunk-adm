# Troubleshooting Application Atlas endpoints

Application Atlas REST endpoints and the recovery alert action return generic errors such as `unavailable` on purpose. Splunk exceptions can carry session tokens, request content or deployment details, so these details never reach the browser. To diagnose a refused or failed request, use the app's operator log instead.

## Where the log is

| Item | Value |
| --- | --- |
| File | `$SPLUNK_HOME/var/log/splunk/splunk_adm.log`, on every search head that serves the app |
| Rotation | 5 MiB per file with 3 backups (`splunk_adm.log.1` to `.3`), so at most about 20 MiB per instance |
| Index | `_internal`, through the platform's built-in monitor of `var/log/splunk`. The app adds no input |
| Sourcetype | `adm:operator`, assigned by `props.conf` in the app (`[source::...splunk_adm.log*]`) |
| Timestamps | UTC, millisecond precision |

The file is created on first use with mode `0600`. Logging is best-effort and never changes a response. The handlers skip logging in four cases:

- `SPLUNK_HOME` is unset, relative, or not its own canonical path. A symlinked `SPLUNK_HOME` is one example.
- `var/log/splunk` is missing or a symlink.
- The log file is a symlink or has more than one hard link.
- The file cannot be written.

On Splunk Cloud Platform, `_internal` access depends on your stack's role configuration. Ask Splunk Support for the events if your role cannot search `_internal`.

## What a line contains

Each refused or failed request writes one `key=value` line:

```text
2026-11-26T20:15:41.570Z level=ERROR event=adm_request outcome=failed handler=adm_observer_mapping method=POST status=503 code=unavailable error_class=Unavailable correlation_id=251093d144f44f8d891d8634dc3e77bf duration_ms=2
```

| Field | Meaning |
| --- | --- |
| `level` | `INFO` for refusals (HTTP 4xx), `ERROR` for failures (HTTP 5xx or a failed alert action), `DEBUG` for successes |
| `outcome` | `refused`, `failed` or `ok` |
| `handler` | `adm_deployment_settings`, `adm_investigations`, `adm_dependency_monitoring`, `adm_collaboration`, `adm_observer_mapping` (the `restmap.conf` stanza names), or `adm_recovery` for the alert action |
| `method` | The HTTP method, when it is a standard method. Not present for the alert action or case requests |
| `status` | The HTTP status returned to the caller |
| `exit_code` | The alert action's exit code. Used instead of `status` |
| `code` | The decision or error code from the response (for example `forbidden`, `invalid`, `unavailable`, `body_too_large`, `recovery_disabled`). The value is `unspecified` when the response has no short identifier code |
| `error_class` | The Python exception class that caused the response, when there is one |
| `correlation_id` | 32 hex characters. A client-supplied `X-Request-Id` or `X-Correlation-Id` header is used only when it is a UUID. Otherwise each request gets a new random ID |
| `duration_ms` | Time spent in the handler |

The log never contains request or response bodies, query strings, URL paths, headers, session tokens, usernames, or exception messages, at any level. To find who made a request, match the time and endpoint against `splunkd_access.log`, which Splunk already restricts to `_internal` readers.

Case requests (`adm_investigations`) are logged by the persistent handler around the request supervisor. The disposable request child discards its stderr and writes nothing to this log, so a case failure shows the supervisor's outcome (`status=503 code=unavailable` or `status=413 code=body_too_large`) without a child-side exception class.

## Sample searches

Failures and refusals in the last 24 hours, by endpoint and cause:

```spl
index=_internal sourcetype=adm:operator earliest=-24h
| stats count latest(_time) AS last_seen BY host handler outcome status code error_class
| convert ctime(last_seen)
| sort - count
```

Failure trend for one endpoint:

```spl
index=_internal sourcetype=adm:operator handler=adm_collaboration outcome=failed earliest=-7d
| timechart span=1h count BY error_class
```

Matching an `unavailable` response with the platform access log (use the time window and host of the failure):

```spl
index=_internal (sourcetype=adm:operator handler=adm_collaboration status=503)
    OR (sourcetype=splunkd_access uri="*/adm/collaboration*" status=503)
    earliest=-15m
| table _time host sourcetype handler status code error_class user uri
```

Recovery alert action outcomes:

```spl
index=_internal sourcetype=adm:operator handler=adm_recovery
| stats count BY outcome code error_class exit_code
```

Examples of `error_class` values and where to look next:

| `error_class` | Likely cause |
| --- | --- |
| `JSONDecodeError` | Malformed request body from a non-browser client |
| `SettingsError`, `LedgerError`, `Invalid`, `Unavailable` | App-defined refusal or persistence failure. The `code` field gives the reason |
| Connection, timeout or HTTP client classes (for example `ConnectionRefusedError`, `TimeoutError`) | splunkd management API or KV Store is unhealthy. Check `index=_internal sourcetype=splunkd component=KVStore*` |
| `FileNotFoundError`, `PermissionError` | Missing packaged file or wrong file ownership in the app directory. Reinstall the package |
| `ValueError` (from `adm_recovery`) | Invalid `adm_recovery.conf` value or an unexpected alert payload |

## Log level

`default/adm_logging.conf` ships `level = INFO`, which records refusals and failures only. To change it, create `local/adm_logging.conf` on the search head:

```ini
[logging]
level = DEBUG
```

| Level | Records |
| --- | --- |
| `DEBUG` | All requests, including successes |
| `INFO` (default) | Refusals and failures |
| `WARNING`, `ERROR` | Failures only |
| `OFF` | Nothing |

Running handlers reread the level within 30 seconds, so no restart is needed. Unrecognized values fall back to `INFO`. Set `DEBUG` only while you investigate, because every request then writes a line. The release gate (`tools/check_release.py`) rejects a package whose default level is not `INFO`.
