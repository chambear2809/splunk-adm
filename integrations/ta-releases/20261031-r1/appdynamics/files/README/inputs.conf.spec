[appdynamics_status://<name>]
application_list = select the applications to collect the Application, Business Transaction, Tier, Tier Node, and Remote Services Status. Leave blank as a shorthand for all applications
duration = The time period (in minutes) that you wish to retrieve data for.  e.g.:  5 = retrieve data for the past 5 minutes. [1-60] (Default: 5)
global_account = Select the account to be used to authenticate to AppDynamics
index = Optional override. Leave blank to use the Add-on Settings default index. (Default: default)
interval = Time interval of input in seconds. (Default: 300)
metrics_to_collect = select the metrics you want to ingest
type = (Default: Status)

[appdynamics_database_metrics://<name>]
collect_baselines_radio = In addition to the metric value, all baselines will report avg, min, max, std dev (Default: default)
compress_data_flag = With this selected, only one summary rollup metric will be collected. This is useful when wanting to perform summation for a period of time, rather than collect a lot of metrics (Default: true)
database_list = select the databases to collect the list of metrics from, select account first, leave empty to retrieve data for all databases
duration = The time period (in minutes) that you wish to retrieve data for.  e.g.:  5 = retrieve data for the past 5 minutes. [1-60] (Default: 5)
global_account = Select the account to be used to authenticate to AppDynamics
index = Optional override. Leave blank to use the Add-on Settings default index. (Default: default)
interval = Time interval of input in seconds. (Default: 300)
metrics_to_collect = select the metrics you want to ingest (Default: custom_metrics~hardware~kpi~performance~server_stats)
type = (Default: Database)

[appdynamics_hardware_metrics://<name>]
application_list = select the applications to collect the list of hardware metrics from, select account first. Leave blank as a shorthand for all applications
collect_baselines_radio = In addition to the metric value, all baselines will report avg, min, max, std dev (Default: default)
compress_data_flag = With this selected, only one summary rollup metric will be collected. This is useful when wanting to perform summation for a period of time, rather than collect a lot of metrics (Default: true)
duration = The time period (in minutes) that you wish to retrieve data for.  e.g.:  5 = retrieve data for the past 5 minutes. [1-60] (Default: 5)
global_account = Select the account to be used to authenticate to AppDynamics
index = Optional override. Leave blank to use the Add-on Settings default index. (Default: default)
interval = Time interval of input in seconds. (Default: 300)
metrics_to_collect = select the metrics you want to ingest (Default: cpu~disk~memory~network~system)
tiernode_radio = Tier level rollup, Individual Node metrics, or Both (Default: tier)
type = (Default: Hardware)

[appdynamics_application_snapshots://<name>]
application_list = select the applications to collect Business Transaction Snapshots from, select account first. Leave blank as a shorthand for all applications
archived = select this to only ingest snapshots flagged as Archived by a user
duration = The time period (in minutes) that you wish to retrieve data for.  e.g.:  5 = retrieve data for the past 5 minutes. [1-60] (Default: 5)
execution_time_in_milis = only snapshots for transactions running longer than this will be ingested (Default: 0)
first_in_chain = select this to only ingest snapshots for BT top level snapshots, ignoring segments
global_account = Select the account to be used to authenticate to AppDynamics
index = Optional override. Leave blank to use the Add-on Settings default index. (Default: default)
interval = Time interval of input in seconds. (Default: 300)
metrics_to_collect = select the snapshot types you want to ingest (Default: SLOW~VERY_SLOW~STALL~ERROR~NORMAL)
need_exit_calls = select this to include exit call details in the snapshots (Default: true)
need_props = select this to include error details, custom data, log messages, stack traces, and other details (Default: true)
type = (Default: Snapshots)

[appdynamics_analytics_api://<name>]
analytics_account = Select the account to be used to authenticate to AppDynamics Analytics
duration = The time period (in minutes) that you wish to retrieve data for.  e.g.:  5 = retrieve data for the past 5 minutes. [1-60] (Default: 5)
global_account = (Default: N/A (Analytics))
index = Optional override. Leave blank to use the Add-on Settings default index. (Default: default)
interval = Time interval of input in seconds. (Default: 300)
query = Enter a search query to execute
source_entry = Enter the source name to ingest data as, if 'appdynamics_' is not at the beginning it will be prepended (Default: appdynamics_analytics)
type = (Default: Analytics)

[appdynamics_security://<name>]
application_list = select the applications to collect the list of hardware metrics from, select account first. Leave blank as a shorthand for all applications
duration = The time period (in minutes) that you wish to retrieve data for.  e.g.:  5 = retrieve data for the past 5 minutes. [1-60] (Default: 5)
global_account = Select the account to be used to authenticate to AppDynamics
index = Optional override. Leave blank to use the Add-on Settings default index. (Default: default)
interval = Time interval of input in seconds. (Default: 300)
metrics_to_collect = select the metrics you want to ingest (Default: attack_counts~business_risk~vulnerabilities)
type = (Default: Security)

[appdynamics_events_policy://<name>]
application_list = select the applications to collect the list of hardware metrics from, select account first. Leave blank as a shorthand for all applications
duration = The time period (in minutes) that you wish to retrieve data for.  e.g.:  5 = retrieve data for the past 5 minutes. [1-60] (Default: 5)
event_filter = 
global_account = Select the account to be used to authenticate to AppDynamics
index = Optional override. Leave blank to use the Add-on Settings default index. (Default: default)
interval = Time interval of input in seconds. (Default: 300)
type = (Default: Events)

[appdynamics_custom_metrics://<name>]
application_list = select the applications to collect the list of custom metrics from, select account first
collect_baselines_radio = In addition to the metric value, all baselines will report avg, min, max, std dev (Default: default)
compress_data_flag = With this selected, only one summary rollup metric will be collected. This is useful when wanting to perform summation for a period of time, rather than collect a lot of metrics (Default: true)
duration = The time period (in minutes) that you wish to retrieve data for.  e.g.:  5 = retrieve data for the past 5 minutes. [5-60] (Default: 5)
global_account = Select the account to be used to authenticate to AppDynamics
index = Optional override. Leave blank to use the Add-on Settings default index. (Default: default)
interval = Time interval of input in seconds. (Default: 300)
metrics_to_collect = Enter a comma separated list of metric paths to collect, wildcards '*' are allowed
source_entry = Enter, or accept the default, splunk source to ingest this data to, if 'appdynamics_' is not at the beginning it will be prepended (Default: appdynamics_custom_metric)
source_type_entry = Enter, or accept the default, splunk source type to ingest this data to, if 'appdynamics_' is not at the beginning it will be prepended (Default: appdynamics_custom_data)
type = (Default: Custom)

[appdynamics_audit://<name>]
duration = The time period (in minutes) that you wish to retrieve data for.  e.g.:  5 = retrieve data for the past 5 minutes. [5-60] (Default: 5)
global_account = Select the account to be used to authenticate to AppDynamics
index = Optional override. Leave blank to use the Add-on Settings default index. (Default: default)
interval = Time interval of input in seconds. (Default: 300)
type = (Default: Audit)

[appdynamics_licenses://<name>]
duration = The time period (in minutes) that you wish to retrieve data for.  e.g.:  5 = retrieve data for the past 5 minutes. [5-60] (Default: 1440)
global_account = Select the account to be used to authenticate to AppDynamics
index = Optional override. Leave blank to use the Add-on Settings default index. (Default: default)
interval = Time interval of input in seconds. (Default: 3600)
type = (Default: License)

[appdynamics_topology://<name>]
application_list = Leave blank to collect all active APM applications.
global_account = Select the account to authenticate to AppDynamics
index = Optional override. Leave blank to use the Add-on Settings default index. (Default: appdynamics)
interval = Topology changes slowly; collect periodically, for example every hour. (Default: 3600)
type = (Default: Topology)

[atlas_appdynamics_inventory://<name>]
global_account = Name of an existing AppDynamics TA account; required.
controller_account = Exact Controller OAuth account name; required.
authority = Stable lowercase Atlas Controller authority; required.
scope = Atlas routing scope; required.
index = Destination index; required.
management_certificate_sha256 = Optional exact SHA-256 of the loopback management server's DER certificate; 64 hexadecimal characters.
interval = Collection interval in seconds.
disabled = Enable or disable this configured input.
