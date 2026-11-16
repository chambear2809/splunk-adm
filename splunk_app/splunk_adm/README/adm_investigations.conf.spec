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
