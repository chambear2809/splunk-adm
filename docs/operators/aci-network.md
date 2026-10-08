# ACI and Nexus Dashboard team

**Purpose:** give Splunk read-only access to the ACI fabric and Nexus Dashboard, and export NetFlow from the leaves, so the dependency map can name endpoints, show fabric paths and ACI policy, and mark where traffic was seen.

## What we need from you

- [ ] A read-only APIC account and a read-only Nexus Dashboard account for the Cisco DC Networking add-on.
- [ ] The four existing APIC inputs enabled, plus one new input with extra object classes.
- [ ] LLDP enabled on the leaf ports facing Kubernetes nodes.
- [ ] ACI NetFlow v9 export from the leaves to the Splunk Stream receiver, sourced from each leaf's out-of-band address.
- [ ] Nexus Dashboard flow and endpoint inputs for the pilot site.
- [ ] Optional: contract logging on the application's ports.

## APIC and Nexus Dashboard accounts

Create one read-only local user on APIC (password or certificate; the add-on supports both via its APIC Authentication Type setting) and one on Nexus Dashboard, then add them in the add-on under **Configuration → ACI Account** and **ND Account**. Read access to all tenants and fabric objects is required; confirm the read-only role name for your APIC release.

## APIC inputs

Enable these existing inputs (add-on **Inputs** page, or the equivalent `inputs.conf` keys) with your account and `index = cisco_dc`:

| Input                       | Collects                                                                                                | Why                                                  |
| --------------------------- | ------------------------------------------------------------------------------------------------------- | ---------------------------------------------------- |
| `stats`                     | `fvCEp` with attachment paths                                                                           | Endpoint IP, MAC, EPG and leaf port                  |
| `classInfo_faultInst`       | `topSystem`, `compVm`, `compHv`, `fvCEp`, `fvRsCons`, `fvRsProv`, `fvRsVm`, `fvRsHyper`                 | Switch names and roles, VM names, contract relations |
| `health_fvTenant`           | `fvTenant`, `fvAp`, `fvEPg`, `fvBD`, `vzFilter`, `vzEntry`, `vzBrCP`, `fvCtx`, `l3extOut`, `fabricNode` | Tenant/EPG names, contract filters, node roles       |
| `classInfo_fvRsCEpToPathEp` | `fvRsCEpToPathEp`, `acllogPermitL3Pkt`, `acllogDropL3Pkt` and others                                    | Attachment paths, contract permit/drop logs          |

Add one new `classInfo` input for fabric links, host LLDP neighbors and the contract objects. `vzBrCP` and `vzEntry` are repeated here because the default `health_fvTenant` input writes them merged with health records.

The `cisco-dc-networking-setup` skill's `application-atlas` preset (alias `adm`) creates this input for you, named `classInfo_adm`:

```sh
cd vendor/splunk-cisco-skills
bash skills/cisco-dc-networking-setup/scripts/setup.sh \
  --classinfo-preset application-atlas --account "<your ACI account name>" --index "cisco_dc" --dry-run
# review the rendered plan, then rerun without --dry-run
```

Or create it by hand:

```ini
[cisco_nexus_aci://classInfo_adm]
apic_account = <your ACI account name>
apic_input_type = classInfo
apic_arguments = fabricLink lldpAdjEp vzBrCP vzSubj vzRsSubjFiltAtt vzEntry l3extInstP l3extSubnet
interval = 300
index = cisco_dc
disabled = 0
```

### Optional: complete policy evaluation

With only the input above, the map names a permitting contract where one matches, and otherwise shows "Policy not evaluated". It never says "no contract permits this", because vzAny, taboos, preferred groups, ESGs and VRF enforcement can also permit or deny traffic. To let the map report "no permitting contract", also collect the `adm-policy` preset:

```sh
bash skills/cisco-dc-networking-setup/scripts/setup.sh \
  --classinfo-preset adm-policy --account "<your ACI account name>" --index "cisco_dc" --dry-run
```

Or by hand:

```ini
[cisco_nexus_aci://classInfo_adm_policy]
apic_account = <your ACI account name>
apic_input_type = classInfo
apic_arguments = fvCtx fvAEPg fvEPg fvESg vzAny vzRsAnyToCons vzRsAnyToProv vzRsAnyToConsIf vzInTerm vzOutTerm vzTaboo fvRsProtBy vzRsSubjGraphAtt
interval = 300
index = cisco_dc
disabled = 0
```

Then ask the Splunk team to set the app macro `adm_aci_policy_complete` to `1`. Only do this when every policy construct used in the VRF is covered by these classes. Check arrival per class with `bash skills/cisco-dc-networking-setup/scripts/validate.sh --classinfo-preset application-atlas --index cisco_dc` (and `adm-policy` for the second input).

## LLDP on host ports

Leaf ports facing Kubernetes nodes need an interface policy with LLDP receive enabled. The Kubernetes team runs an LLDP agent on each node that advertises the Kubernetes node name as its system name. This is how the map attaches nodes to leaf ports when nodes sit behind a floating-SVI L3Out, where their IPs are not ACI endpoints.

## ACI NetFlow export

Configure a NetFlow v9 exporter toward the Splunk Stream receiver (address and UDP port from the Stream owner, see [network-stream.md](network-stream.md)):

| Setting              | Value                                                                                                         |
| -------------------- | ------------------------------------------------------------------------------------------------------------- |
| Exporter version     | v9                                                                                                            |
| Source IP type       | `oob-mgmt-ip` (so each record names the leaf by its OOB address)                                              |
| Destination          | Stream receiver IP and UDP port                                                                               |
| Record match keys    | source/destination IPv4, source/destination port, protocol                                                    |
| Monitors attached to | the bridge domains of Kubernetes nodes, client VMs and server VMs, and the Kubernetes L3Out interface profile |

Verify with your APIC release:

- the exact GUI path and field names;
- leaf hardware support;
- whether NetFlow and Nexus Dashboard flow telemetry can run on the same leaf, or the fabric node control policy forces you to pick one per leaf. If you must choose, tell us which leaves use which. The map works with either source alone. Without NetFlow on the leaf that receives LoadBalancer traffic, the map can't tell which node received a DSR connection.

ACI NetFlow records carry the ingress interface only, not egress or VRF.

## Nexus Dashboard inputs

Enable `endpoints` and `flows` (existing stanzas) with your ND account, `index = cisco_dc`, and the pilot site. Flow telemetry must be enabled in Nexus Dashboard for the VRFs carrying the application's traffic.

## Contract logging (optional)

To show observed permit/drop evidence in addition to contract intent, set the `log` directive on the contract subject filters for the application's ports. ACI keeps ACL-log records in a bounded, sampled buffer, so they confirm traffic but do not count it.

## How to verify

```spl
index=cisco_dc sourcetype=cisco:dc:aci:class component IN (topSystem, fabricLink, lldpAdjEp, vzSubj, vzRsSubjFiltAtt, l3extInstP, l3extSubnet) | stats count by component
index=cisco_dc sourcetype=cisco:dc:aci:stats component=fvCEp | head 5
index=cisco_dc sourcetype=cisco:dc:nd:flows | head 5
index=netflow sourcetype=stream:netflow | stats count by exporter_ip
```

Every leaf OOB address should appear as an `exporter_ip`.

## Automation skills

Skills from [splunk-cisco-skills](https://github.com/chambear2809/splunk-cisco-skills) render a plan for review, apply only the requested change, and validate it. Run them from Claude Code, Codex or Cursor, or run their scripts directly. Its `main` branch now covers Splunk Enterprise 10.6: check each skill's own 10.6 status (`supported`, `conditional`, or `not-applicable`) in [SPLUNK_ENTERPRISE_10_6_COMPATIBILITY.md](https://github.com/chambear2809/splunk-cisco-skills/blob/main/SPLUNK_ENTERPRISE_10_6_COMPATIBILITY.md) and follow any documented guardrails before applying.

- [cisco-dc-networking-setup](https://github.com/chambear2809/splunk-cisco-skills/tree/main/skills/cisco-dc-networking-setup): DC Networking accounts and the default inputs for APIC, Nexus Dashboard and Nexus 9000, plus the `application-atlas`/`adm` and `adm-policy` custom `classInfo` presets used above (`--classinfo-preset`), or any other class list with `--classinfo-input`/`--classinfo-classes`.
- [cisco-product-setup](https://github.com/chambear2809/splunk-cisco-skills/tree/main/skills/cisco-product-setup): entry point that routes a Cisco product (ACI, Nexus 9000) to the right setup skill.
- [splunk-stream-setup](https://github.com/chambear2809/splunk-cisco-skills/tree/main/skills/splunk-stream-setup): the Stream forwarder's NetFlow receiver that your ACI NetFlow exporter targets (owned by the Stream team; see [network-stream.md](network-stream.md)).

## What to send back

- APIC and Nexus Dashboard versions; leaf and spine models.
- Node list (node ID, name, role, OOB address).
- Tenant, VRF, bridge domain, EPG, L3Out and external EPG names used by the application, its clients and its databases.
- The LoadBalancer VIP and pod CIDR prefixes as configured in the L3Out external EPG subnets.
- One hour of sample events for each component above.

## Open questions

- Are Kubernetes nodes in an EPG/bridge domain, behind a floating-SVI L3Out, or both?
- Is vzAny, a preferred group, ESGs, a service graph (PBR), an unenforced VRF, or contracts with source-port or TCP-flag (`est`) filters used in the application VRF? The map doesn't evaluate those. Where they could apply, or where policy for an address isn't collected, it shows "Policy not evaluated" instead of naming a contract, so tell us which apply.
- Which leaves run NetFlow vs Nexus Dashboard flow telemetry?

## Sources

Input stanzas and classes: DC Networking 1.2.2 `default/inputs.conf:81-127`, `README/inputs.conf.spec:25-32`, `appserver/static/js/build/globalConfig.json` (account fields). Class writer and sourcetype: `bin/cisco_nexus_aci.py:467-490,549-609`; `default/props.conf:191`. Object attributes (`fabricLink`, `lldpAdjEp`, NetFlow exporter `sourceIpType`): APIC Management Information Model, release 6.1(x). ACL-log and contract model: same MIM. Contract and topology use: `docs/DATA_LAYER.md`.
