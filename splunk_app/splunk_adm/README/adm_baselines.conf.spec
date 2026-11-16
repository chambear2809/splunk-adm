# Private, non-replicated baseline storage. No installed deployment is qualified.
[persistence]
mode = <string>
* disabled (default), or single_search_head after installed qualification.
platform = <string>
* unqualified (default), or enterprise after installed qualification.
* Runtime checks require Enterprise 10.6.0.5 and a standalone search head.
* Every request requires the dedicated adm_investigate capability.
source_mode = unavailable
* The only shipped value; there is no production source provider.
* No setting enables capture, schedules, notifications, or automated actions.
