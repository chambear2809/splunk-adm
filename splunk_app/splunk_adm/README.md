# Application Atlas

Network-perspective application dependency mapping for Splunk Enterprise 10.6 and Splunk Cloud. Demo mode shows synthetic data and is the default view.

The app builds its map from data collected by Splunk Stream, Cisco DC Networking (Nexus Dashboard, NX-OS, ACI), Cisco Security Cloud (FTD, Isovalent) and the Splunk OpenTelemetry Collector for Kubernetes. It does not create indexes or collect data itself.

To set it up:

1. Create a summary index (default `adm_summary`).
2. Set the `adm_index_*` macros to your indexes.
3. Fill the `adm_observer_scope.csv` lookup.
4. Enable the `ADM - …` saved searches, which ship disabled.

See `docs/DATA_LAYER.md` for the searches, lookups, field contracts and source prerequisites.
