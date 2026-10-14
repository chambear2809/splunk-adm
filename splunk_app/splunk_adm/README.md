# Application Atlas

Network-perspective application dependency mapping for Splunk Enterprise 10.6 and Splunk Cloud. Demo mode shows synthetic data and is the default view.

The app builds its map from data collected by Splunk Stream, Cisco DC Networking (Nexus Dashboard, NX-OS, ACI), Cisco Security Cloud (FTD, Isovalent) and the Splunk OpenTelemetry Collector for Kubernetes. It does not create indexes or collect data itself.

To set it up:

1. Create a summary index (default `adm_summary`).
2. Set the `adm_index_*` macros to your indexes.
3. Populate the `adm_observer_scope` KV lookup as admin/sc_admin (lowercase observer_kind/observer keys; scope/cluster values unchanged). For an upgrade, migrate the retained CSV once before enabling searches; see packaged docs/DATA_LAYER.md and the repository docs/UPGRADES.md.
4. Enable the `ADM - …` saved searches, which ship disabled.

See `docs/DATA_LAYER.md` for the searches, lookups, field contracts and source prerequisites.

Licensed under the Apache License, Version 2.0 (`LICENSE`, `NOTICE`). Bundled third-party licenses are in `THIRD_PARTY_NOTICES.txt`.
