# Intersight and VMware add-ons: lab setup (2026-11-04)

Lab: Splunk Cloud `<stack>` (10.6.0.5, search tier) and heavy
forwarder `splunk-ta` 10.110.253.20 (10.6.0.5, `/opt/splunk`, Enterprise Trial
license). The HF runs every modular input and forwards to Cloud.

## What is installed where

| Package | Cloud search tier | HF `splunk-ta` |
| --- | --- | --- |
| Splunk_TA_Cisco_Intersight (Splunkbase 7828) | **3.1.1** (ACS, Splunkbase) | **3.2.2** (`research/packages/cisco-intersight-add-on-for-splunk_322.spl`, sha256 `5046084b...333a5f`) |
| Splunk_TA_vmware 4.2.1 + SA-Hydra 4.3.0 (Splunkbase 3215) | not installed (ACS: "App is not self-service installable") | installed from `splunk-add-on-for-vmware_421.tgz` (sha256 `89d00700...44eb6`) |
| TA-VMW-FieldExtractions 4.0.4 (Splunkbase 5641) | **not installed** (blocked, see below) | not needed (search-time only) |

HF installs were extracted into `/opt/splunk/etc/apps` as `splunk`, then
splunkd was restarted at 2026-11-04T04:14Z.

Why Cloud has Intersight 3.1.1: the repo registry lists 3.2.2 platforms only
through 10.5, so `install_app.sh` refuses it on 10.6 without
`--accept-unsupported-platform`, and that override was not used. 3.1.1 is the
repo-verified pin for 10.6. Sourcetypes are unchanged between the two versions.

## Indexes (Cloud, ACS, event, 90 searchable days)

`intersight`, `vmware-inv`, `vmware-perf`, `vmware-taskevent` (the
Splunk_TA_vmware defaults from `ta_vmware_collection.conf`).

## Intersight

- Cloud: macro `cisco_intersight_index` = `index IN (intersight)`; app visible;
  135 shipped dashboard views visible.
- HF: account `ATLAS_INTERSIGHT` (hostname `intersight.com`) created 2026-11-04T05:02Z
  after the OAuth2 app was recreated (the first app was invalid/expired). 7 inputs
  enabled into `index=intersight` via `setup.sh --enable-inputs --account
  ATLAS_INTERSIGHT --index intersight --input-type all --app-version 3.2.2`: audit
  logs, alarms, inventory, ports_and_interfaces (ether/NetworkPorts,
  PhysicalPorts, PortChannels, adapter/HostEthInterfaces), pools, device and
  network metrics. No restart was needed. The secret temp file was deleted.
- Rollback: disable/delete the 7 `ATLAS_INTERSIGHT_*` inputs and the account in
  the TA's configuration page or REST endpoints.

## VMware (HF = combined Data Collection Scheduler + DCN)

All configuration is in app `Splunk_TA_vmware` on the HF, written through
splunkd REST (the add-on's Collection Configuration page is a Splunk Web
controller, and Splunk Web is disabled on the HF):

- `local/hydra_node.conf` `[https://127.0.0.1:8089]` user `atlas_vmw_dcn`,
  heads 4. `atlas_vmw_dcn` is a local admin user with a generated password,
  stored only in `storage/passwords` (realm `https://127.0.0.1:8089`). The
  user is disabled when the HF's Enterprise Trial license expires.
- `local/ta_vmware_collection.conf` `[10.110.253.10]` target_type `vc`, username
  `administrator@vsphere.local` (password in `storage/passwords`, realm
  `10.110.253.10`), `hostsystem_inv_config = config.network`. By default,
  HostSystem inventory collects only `config.hyperThread`. This setting adds
  vSwitch, proxySwitch, pnic, portgroup and vmk data.
- Inputs enabled: `ta_vmware_collection_scheduler://puff`, workers
  `alpha beta delta epsilon` (the scheduler enables them), and SA-Hydra
  `bootstrap_hydra_gateway.py`. The gateway listens on `0.0.0.0:8008`.
- Splunk Web is disabled (`startwebserver = 0`), so no splunkweb cert existed.
  The Hydra gateway reads web.conf `privKeyPath`/`serverCert`, so a self-signed
  pair was generated at `etc/auth/splunkweb/{privkey.pem,cert.pem}`.
- Known issue: a splunkd restart while workers are running can orphan worker
  processes (ppid 1). They keep taking jobs and fail with
  `BrokenPipeError`. Fix: `kill` the `ta_vmware_collection_worker.py`
  processes whose ppid is 1.

## Validation (Cloud, first 2 h, 2026-11-04T04:46Z)

`vmware-inv`: hostsystem 4, vm 19 (19 VMs), datastore 8, hierarchy 48,
resourcepool 4. No clustercomputeresource events, because the vCenter has no
cluster. `vmware-perf`: 12 `vmware:perf:*` sourcetypes, 135 to 270 each.
`vmware-taskevent`: events 41, tasks 1. `intersight`: 0 (account blocked).

`splunk-vmware-ta-setup validate.sh --completion` fails for three reasons: the
skill's index model wants a metrics `vmware-perf` (TA 4.2.1 writes event perf
by default), ACS index describe needs a stack-scoped token, and
Splunk_TA_vmware is absent from Cloud. The Intersight completion gate also
fails on account/inputs/data.

## VMware network fields (raw JSON paths, `vmware:inv:*`)

Cloud has no VMware search-time app, so `KV_MODE=json` is off. Use
`spath path=...` explicitly: events are 50 KB or more, which exceeds the
automatic spath cutoff.

HostSystem (`vmware:inv:hostsystem`, requires `hostsystem_inv_config = config.network`):

- vSwitch: `changeSet.config.network.vswitch{}.name`, `.key`, `.pnic{}`
  (`key-vim.host.PhysicalNic-vmnicN`), `.spec.bridge.nicDevice{}`,
  `.spec.policy.nicTeaming.nicOrder.activeNic{}`, `.portgroup{}`, `.mtu`,
  `.spec.bridge.linkDiscoveryProtocolConfig.protocol` (cdp)
- Standard portgroup: `changeSet.config.network.portgroup{}.spec.name`,
  `.spec.vlanId`, `.spec.vswitchName`, `.vswitch`, `.port{}.type`
  (`virtualMachine`/`host`), `.port{}.mac{}` (connected vNIC MACs)
- DVS host proxy: `changeSet.config.network.proxySwitch{}.dvsName`, `.dvsUuid`,
  `.key` (`DvsPortset-0`), `.pnic{}`,
  `.spec.backing.pnicSpec{}.pnicDevice` / `.uplinkPortKey` /
  `.uplinkPortgroupKey`, `.uplinkPort{}.key` / `.value` (`uplinkN`), `.mtu`
- pNIC: `changeSet.config.network.pnic{}.device`, `.mac`, `.key`, `.driver`,
  `.linkSpeed.speedMb`, `.pci`
- vmk: `changeSet.config.network.vnic{}.device`, `.portgroup`, `.spec.mac`,
  `.spec.ip.ipAddress`, `.spec.netStackInstanceKey`
- Network moids: `changeSet.network.ManagedObjectReference{}.moid` / `.type`
  (`Network`, `DistributedVirtualPortgroup`)

VirtualMachine (`vmware:inv:vm`):
`changeSet.config.hardware.device{}.macAddress`, `.deviceInfo.label` /
`.summary`, `.connectable.connected`. Backing on a DVS:
`.backing.port.switchUuid` / `.portgroupKey` / `.portKey`. Backing on a
standard vSwitch: `.backing.deviceName` and `.backing.network.moid`. The
device class (for example Vmxnet3) is not emitted; select NICs by the
presence of `macAddress`. Guest view: `changeSet.guest.net{}.macAddress`,
`.network` (an ACI VMM portgroup name such as `Tenant|AppProfile|EPG`),
`.ipAddress{}`, `.deviceConfigId` (joins to device `key`). Placement:
`changeSet.summary.runtime.host.moid` / `.name`.

No DVS or portgroup inventory sourcetype exists. The `dvportgroup-N` to
name/VLAN mapping is not collected; only keys and moids are.

## Rollback

HF (`ssh splunk@10.110.253.20`):

```
/opt/splunk/bin/splunk disable app Splunk_TA_vmware ; ... SA-Hydra ; ... Splunk_TA_Cisco_Intersight   # or:
rm -rf /opt/splunk/etc/apps/{Splunk_TA_vmware,SA-Hydra,Splunk_TA_Cisco_Intersight}
rm -f /opt/splunk/etc/auth/splunkweb/{privkey.pem,cert.pem}
/opt/splunk/bin/splunk restart
```

Then delete the user `atlas_vmw_dcn` (`DELETE /services/authentication/users/atlas_vmw_dcn`).
Removing the app directories also removes their `storage/passwords` entries.

Cloud (ACS): `acs apps uninstall Splunk_TA_Cisco_Intersight`, then
`acs indexes delete --name <idx>` for each of the four indexes. This deletes
their data.
