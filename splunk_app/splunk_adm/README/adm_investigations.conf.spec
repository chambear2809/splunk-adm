# Application Atlas user-authored investigation notes.
# This endpoint is disabled by default. No Cloud or SHC deployment is qualified.

[persistence]
mode = <string>
* disabled (default), or single_search_head after installed qualification.
* Local SQLite storage is not replicated between search heads.

platform = <string>
* unqualified (default), or enterprise after installed qualification.
* The host checks its runtime version, Cloud marker and SHC configuration.
* A dedicated adm_investigate capability is also required for every request.
