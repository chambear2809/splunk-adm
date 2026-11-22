# Private, non-replicated baseline storage. No installed deployment is qualified.
[persistence]
mode = <string>
* disabled (default), or single_search_head after installed qualification.
platform = <string>
* unqualified (default), or enterprise after installed qualification.
* Runtime checks require a standalone Enterprise 10.6.0.5 search head, or
  Enterprise 10.6.1.1 with build b2ae2962645c. Runtime admission does not
  establish installed app qualification.
* Every request requires the dedicated adm_investigate capability.
source_mode = unavailable
* The only shipped value; there is no production source provider.
* No setting enables capture, schedules, notifications, or automated actions.
