# AppDynamics inventory evidence design

## Purpose and boundary

The `appdynamics_inventory` supplemental source imports read-only Controller Application Model snapshots. It adds current application, tier, node, node-IP and backend-candidate context to an explicitly requested endpoint inspection. It does not create traffic records, graph edges, connection counts or causal claims. Node IPs are point observations; absence from a later snapshot does not close an earlier assignment. The AppDynamics importer also derives the existing `asset_history` v1 `snapshot_current` records from the same node metadata. That second source remains the sole asset-history contract.

## Official API basis

The chosen contract is the documented XML default in the [26.10 Application Model API](https://help.splunk.com/en/appdynamics-saas/extend-splunk-appdynamics/26.10.0/extend-splunk-appdynamics/splunk-appdynamics-apis/application-model-api). It uses only these read requests:

| Request                                                                  | Purpose                                                                         |
| ------------------------------------------------------------------------ | ------------------------------------------------------------------------------- |
| `GET /controller/rest/applications`                                      | List application IDs and names.                                                 |
| `GET /controller/rest/applications/{applicationId}/tiers`                | List tiers and their IDs, names and reported node counts.                       |
| `GET /controller/rest/applications/{applicationId}/tiers/{tierId}/nodes` | List nodes and their IDs, names, machine metadata and IP addresses.             |
| `GET /controller/rest/applications/{applicationId}/backends`             | List application-scoped backend objects, properties and reported tier/node IDs. |

The documented node XML wraps addresses as `<ipAddresses><ipAddress>10.0.0.1</ipAddress></ipAddresses>`. The collector uses that XML structure, rejects unknown XML element shapes and never guesses JSON array encodings. The documentation describes optional `output=JSON` but does not specify a universal response-size pagination contract for these Application Model lists. This collector therefore uses XML and its own hard caps; reaching any cap fails the entire snapshot instead of returning an apparently complete partial inventory. `time-range-type` filters “alive on” a GMT day and is omitted. It is not a historical address-ownership interval.

The [API clients guide](https://help.splunk.com/en/appdynamics-saas/extend-splunk-appdynamics/26.4.0/extend-splunk-appdynamics/splunk-appdynamics-apis/api-clients) documents OAuth client-credentials authentication at `POST /controller/api/oauth/access_token`, using form fields `grant_type=client_credentials`, `client_id=<apiClientName>@<accountName>` and `client_secret`. The response supplies `access_token` and `expires_in`; REST reads use `Authorization: Bearer <token>`. The token and secret are never written into a snapshot or log. The collector requires an operator-supplied HTTPS origin, verifies TLS, refuses redirects and sends requests only to that origin.

Create a read-only role with **Applications > View** for only the selected applications. Splunk AppDynamics' [least-privilege API client guidance](https://help.splunk.com/en/appdynamics-saas/mcp-server-integration/26.7.0/configure-a-least-privileged-api-client) identifies that application permission as the read grant for application, tier, node and business transaction data. This collector does not call the business transaction or event APIs. Do not grant configuration, edit, delete or account-administration permissions to the runtime client.

## Identity and semantics

The indexed schema is `application_atlas.appdynamics_inventory.v1` with `sourcetype=adm:appdynamics_inventory` and `source=appdynamics_inventory`. AppDynamics' numeric Controller IDs are retained as distinct IDs. A node key is the Controller authority plus application ID, tier ID and node ID; names remain labels. This prevents colliding IDs from different Controllers or applications from merging.

Each export has a UUID `snapshot_id`, one `snapshot` manifest and one record per application, tier, node and backend. Every row includes the Controller authority, routing scope, `snapshot_at`, exact collection start/end/skew, `snapshot_complete`, source record ID, observation time and SHA-256 record fingerprint. The manifest declares record counts. The importer recomputes the fingerprints and count relationships, validates object references and backend associations, and checks the derived Asset History manifest against the node IP rows before writing either output.

Node addresses are canonical IP literals. IPv4-mapped IPv6 is canonicalized to IPv4. Zone-scoped IPv6 is retained as reported but is unmatchable because a zone identifier cannot be safely compared across routing scopes. Shared IPs remain separate node identities and are presented as multiple matches.

Backend discovery is modeled application inventory, not a traffic log. The [default backend discovery documentation](https://help.splunk.com/en/appdynamics-saas/application-performance-monitoring/26.3.0/configure-instrumentation/backend-detection-rules/default-automatic-backend-discovery) describes backend discovery from type and properties. The collector derives endpoint candidates only from allowlisted host, URL and port properties, removes URL credentials/query/fragment, labels unresolved names without DNS lookup, and redacts secret-like property names. Positive reported tier/node IDs are called `verified_node` only when they identify exactly one node within that same complete application snapshot. Zero/missing IDs remain `application_scope_only`; positive unmatched IDs remain `unverified_reported_ids`. Neither a candidate endpoint nor a verified model association proves that a request used the backend.

Credential-bearing URLs and connection strings are sanitized or dropped even
when their property names are not on the endpoint allowlist. The importer caps
accepted snapshot input at 50 MiB and rejects any rendered HEC event line above
65,535 bytes rather than allowing index-time truncation.

## Search and completeness

The browser search uses the configured AppDynamics index selector and verified `appd_controller` authority mappings for the selected routing scope. It scans only the configured freshness window, independent of the traffic selection's historical window. It selects the latest snapshot per Controller and fails closed on tied latest snapshots, invalid rows, mismatched record counts, duplicate IDs, conflicting copies of one fingerprint, skew mismatch, or a source scan above 10,000 rows. It focuses results to exact selected-IP node records, their application/tier ancestors and backends from those applications. The focused result is capped at 64 rows. Any input/output cap, unqualified schema, changed configuration or rejected row suppresses relationships.

The browser presents current matching nodes and modeled backend candidates as separate tables. `associatedWithMatchedNode` means only that positive Controller-reported association IDs match a selected node in the same snapshot. Endpoint candidate IP equality is labeled as a candidate equality, not runtime use. Hostname candidates are never resolved.

The checked 26.10 [Tiers and Nodes UI guide](https://help.splunk.com/en/appdynamics-saas/application-performance-monitoring/26.10.0/tiers-and-nodes) documents navigation through Applications, Tiers & Nodes, and expanding a tier. It does not define stable application/tier/node/backend UI deep-link routes. The [Events API](https://help.splunk.com/en/appdynamics-saas/extend-splunk-appdynamics/26.4.0/extend-splunk-appdynamics/splunk-appdynamics-apis/alert-and-respond-api/events-api) includes an event `deepLinkUrl`, but this source does not collect events and does not reuse that event-specific path. The UI therefore links only to the operator-configured HTTPS Controller origin and displays IDs for manual navigation; it never constructs event or object URLs from indexed data.

## Tests and qualification

The synthetic fixtures in [`fixtures/appdynamics`](../fixtures/appdynamics/) follow the documented XML response shape. They cover multiple applications, shared addresses, IPv6, zone-scoped IPv6, backend IDs that are positive or zero, unresolved endpoint names and secret-like properties. Unit tests cover TLS-origin and redirect boundaries, bounds, malformed XML, identity, completeness, importer output and AppDynamics evidence normalization.

This design does not establish a live customer Controller version, permission set, API cadence, index latency/retention, source volume, search role, field extraction or HEC acknowledgement/readback. Qualify those in the target deployment before enabling the optional source.
