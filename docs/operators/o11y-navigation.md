# Navigate between Atlas and Splunk Observability Cloud

Application Atlas provides manual navigation context for APM, infrastructure,
logs, detectors and incidents. It does not call the Observability Cloud API or
claim that a detector or incident belongs to the selected service. The selected
Atlas graph service supplies the exact service, environment, cluster and
Kubernetes namespace. Optional OTel service namespace and APM MMS ID are shown
separately; neither is substituted for Kubernetes namespace.

## From Atlas to Observability Cloud

The product actions open the configured HTTPS tenant origin. If no configured
origin is supplied, Atlas uses Splunk's documented realm URL form:
`https://app.<realm>.observability.splunkcloud.com/`. Set the configured origin
to the origin shown by the operator's organization if the tenant uses an
organization domain or an existing legacy domain. The configured value must
be HTTPS and contain only an origin, without credentials, a route, query, or
fragment. An invalid explicit value suppresses external links instead of
falling back to a guessed realm.

These links open the tenant home. They do not encode identity, event IDs or
time in a product URL because the reviewed Splunk product documentation does
not define stable public URLs for those filters. Atlas shows the exact selected
identity and UTC time window, detector/incident IDs when supplied, and a
copyable investigation context. Choose the product path and set the local
filters manually:

| Product        | Where to navigate and what to verify                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                              |
| -------------- | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| APM            | Open **APM → Overview → Services**. The top-bar search supports the documented `service: <name>` prefix. Check environment, cluster, Kubernetes namespace and OTel service namespace separately; the service name alone is not the full Atlas identity. ([APM overview](https://help.splunk.com/en/splunk-observability-cloud/monitor-application-performance/manage-services-spans-and-traces-in-splunk-apm/monitor-your-overall-apm-environment), [global search](https://help.splunk.com/en/splunk-observability-cloud/search-reference/search-in-splunk-observability-cloud)) |
| Infrastructure | Open **Infrastructure → Infrastructure Catalog**, choose the relevant navigator, and add the cluster/namespace/service filters available for that navigator. Choose the same time window with its time picker. ([Navigators](https://help.splunk.com/en/splunk-observability-cloud/observability-for-ai/splunk-ai-infrastructure-monitoring/monitor-and-troubleshoot-your-ai-infrastructure/use-navigators))                                                                                                                                                                      |
| Logs           | Open **Logs → Log Observer**, select the same time range, and use **Add Filter → Fields** for fields present in the connected log source. Log Observer Connect also requires an authorized connection and selected index. ([Search logs](https://help.splunk.com/en/splunk-observability-cloud/manage-data/view-splunk-platform-logs/search-logs-by-keywords-or-fields), [logs table](https://help.splunk.com/en/splunk-observability-cloud/manage-data/view-splunk-platform-logs/browse-logs-in-the-logs-table))                                                                 |
| Detectors      | Open **Alerts → Detectors**, or use top-bar search with the documented `detector:` prefix. Native detector IDs supplied to Atlas remain visible/copyable for manual verification; the Atlas action does not construct an ID URL. ([View detectors](https://help.splunk.com/en/splunk-observability-cloud/create-alerts-detectors-and-service-level-objectives/create-alerts-and-detectors/view-detectors), [global search](https://help.splunk.com/en/splunk-observability-cloud/search-reference/search-in-splunk-observability-cloud))                                          |
| Incidents      | If the Incidents dashboard is enabled for the organization, filter by Entity and Environment and use its documented name search. Native incident IDs remain visible/copyable for manual lookup; an ID-specific route is not generated. ([Incident details](https://help.splunk.com/en/splunk-observability-cloud/create-alerts-detectors-and-service-level-objectives/incidents-and-notification-rules/incidents/incident-details))                                                                                                                                               |

The exact service context comes from the selected Atlas graph node. It is not
joined to detector/incident events by service name, MMS ID, or another display
label. APM MMS ID is context only. Splunk documents Incidents as a controlled
availability feature, so its presence and access can depend on the tenant.

## Add a reciprocal APM data link to Atlas

Splunk global data links can be exposed for APM services, traces and spans. An
Observability Cloud administrator can configure a **Custom URL** destination
for an organization-wide link. Use the deployed Atlas application's own
**Copy link** action to obtain its valid entry URL, including the current
Splunk locale or reverse-proxy prefix. Do not hand-write an Atlas route.
([Data links](https://help.splunk.com/en/splunk-observability-cloud/data-tools/navigate-to-related-resources-with-data-links))

Configure the link in the tenant and verify the resulting URL with a known
service before sharing it:

1. In Atlas, build the live map for the service and time range that should be
   the starting context, then use **Copy link**. This produces the supported
   Atlas route and parameter names for that installation.
2. In Observability Cloud, create a global data link whose trigger is a
   verified APM property. Select **Custom URL** and start with the copied Atlas
   link. Use the data-link editor's variable picker and property mapping for
   values that are actually emitted by that service. Splunk documents custom
   URL variables such as `{{properties.host}}`, as well as `{{key}}`,
   `{{value}}`, `{{start_time}}` and `{{end_time}}`; do not invent other
   placeholder names.
3. Map values only when they are the same identity dimension and representation
   as Atlas expects:

   | APM property                  | Atlas field        | Requirement                                                                             |
   | ----------------------------- | ------------------ | --------------------------------------------------------------------------------------- |
   | `service.name`                | `service`          | Exact verified service property; no display-name join.                                  |
   | `deployment.environment.name` | `environment`      | Use only when this is the same deployment environment represented in the Atlas graph.   |
   | `k8s.cluster.name`            | `cluster`          | Use only when the emitted cluster value matches the Atlas graph.                        |
   | `k8s.namespace.name`          | `namespace`        | Atlas `namespace` means Kubernetes namespace. Do not map OTel `service.namespace` here. |
   | `service.namespace`           | No Atlas URL field | Keep as a distinct OTel dimension; it is not Kubernetes namespace.                      |
   | APM MMS ID                    | No Atlas URL field | Health-capture context only; this does not select or identify the Atlas graph service.  |

4. Confirm Atlas accepts the copied link and displays the intended identity.
   Atlas validates the route parameters and the graph still must be built from
   the selected live sources; the link does not cause an automatic graph
   search. Use fixed values or manual selection when a source property is
   missing or has not been verified.
5. Treat time separately. Atlas accepts safe Splunk-relative bounds such as
   `-1h` and `now`, or numeric Unix seconds. Splunk data-link time variables
   have a configurable format. Confirm their exact output unit and value in
   the target tenant before mapping them to Atlas `earliest` and `latest`. Do
   not pass milliseconds or another unit through unchanged. If the output is
   incompatible, use an agreed fixed relative window with manual time
   alignment, or a separately supported translation outside the browser.

Never put API tokens or other credentials in a data-link URL. APM property
values and time ranges can appear in browser history, referrers, proxy logs and
Splunk audit records; follow the organization's URL data-handling policy.

## Product documentation

- [Observability Cloud domain transition](https://help.splunk.com/en/splunk-observability-cloud/reference/splunk-observability-cloud-domain-transition-guide)
- [Search in Observability Cloud](https://help.splunk.com/en/splunk-observability-cloud/search-reference/search-in-splunk-observability-cloud)
- [APM overview](https://help.splunk.com/en/splunk-observability-cloud/monitor-application-performance/manage-services-spans-and-traces-in-splunk-apm/monitor-your-overall-apm-environment)
- [Infrastructure navigators](https://help.splunk.com/en/splunk-observability-cloud/observability-for-ai/splunk-ai-infrastructure-monitoring/monitor-and-troubleshoot-your-ai-infrastructure/use-navigators)
- [Search logs](https://help.splunk.com/en/splunk-observability-cloud/manage-data/view-splunk-platform-logs/search-logs-by-keywords-or-fields)
- [View detectors](https://help.splunk.com/en/splunk-observability-cloud/create-alerts-detectors-and-service-level-objectives/create-alerts-and-detectors/view-detectors)
- [Incident details](https://help.splunk.com/en/splunk-observability-cloud/create-alerts-detectors-and-service-level-objectives/incidents-and-notification-rules/incidents/incident-details)
- [Data links](https://help.splunk.com/en/splunk-observability-cloud/data-tools/navigate-to-related-resources-with-data-links)
