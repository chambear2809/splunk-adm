# Application Atlas private investigation records.
# This endpoint is disabled by default. No Cloud or SHC deployment is qualified.

[persistence]
mode = <string>
* disabled (default), or single_search_head after installed qualification.
* Local SQLite storage is not replicated between search heads.

platform = <string>
* unqualified (default), or enterprise after installed qualification.
* The host checks its runtime version, Cloud marker and SHC configuration.
* A dedicated adm_investigate capability is also required for every request.

capture_mode = <string>
* disabled (default), or reproducible_qualified_v1 after separate qualification.
* Rechecks bounded admqualified comparison windows using each current caller.
* Saved evidence is withheld if current access, configuration or results differ.
* Source retention loss does not delete the case or its notes.
* Does not enable attachments, schedules, notifications, Cloud or SHC support.

storage_backend = <string>
* sqlite (default, omitted from packaged defaults) or kvstore after installed
  qualification. sqlite remains standalone Enterprise only. kvstore uses the
  insert-only CAS ledger and does not enable a custom collector.

[capture_transport]
management_uri = <string>
* unconfigured (default), or an explicit HTTPS loopback management origin.
* localhost, 127.0.0.1 or ::1 only; the certificate SAN must match.
ca_file = <absolute path>
* unconfigured (default), or an explicit matching public CA PEM file.
* No verification fallback, proxy, redirect, or CA discovery is supported.
* The file must be regular, non-linked, owned by root or the Splunk user,
  and not writable by group or other users. Private keys are rejected.
* Missing or invalid trust disables protected evidence, while notes stay usable.
