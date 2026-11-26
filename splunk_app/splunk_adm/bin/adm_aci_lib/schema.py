"""Versioned APIC poll schema; synchronized with the producer core."""

CLASSES = (
    "fvCEp",
    "fvIp",
    "fvRsCEpToPathEp",
    "fabricLink",
    "lldpAdjEp",
    "topSystem",
    "fabricNode",
    "l1PhysIf",
    "ethpmPhysIf",
    "l3EncRtdIf",
    "fvRsBd",
    "fvCtx",
    "fvBD",
    "fvAEPg",
    "netflowExporterPol",
    "netflowMonitorPol",
    "netflowRecordPol",
    "netflowRsMonitorToExporter",
    "netflowRsMonitorToRecord",
    "netflowRtBDToNetflowMonitorPol",
    "netflowRsExporterToCtx",
    "netflowRsExporterToEPg",
)

# Poll versions are distinct fixed contracts; v1 remains the default.
CLASSES_V1 = CLASSES
CLASSES_V2 = CLASSES_V1 + ("fvRsCtx",)

VOLATILE_ATTRIBUTES = {
    "topSystem": frozenset({"currentTime", "systemUpTime", "clusterTimeDiff"})
}

# Official Cisco DC Networking Add-on 2.0.10 (Splunkbase 7777) classInfo catalog.
# DC Networking 2.0.10 ships no fvRsCtx or fvRsBd preset in its guided
# aci_collection areas; operators configure apic_input_type=classInfo with
# space-separated class names in apic_arguments (sourcetype=cisco:dc:aci:class).
OFFICIAL_DCN_VERSION = "2.0.10"
OFFICIAL_DCN_SPLUNKBASE_ID = "7777"
OFFICIAL_DCN_CLASSINFO_SOURCETYPE = "cisco:dc:aci:class"
OFFICIAL_DCN_STATS_SOURCETYPE = "cisco:dc:aci:stats"

OFFICIAL_DCN_CORE_CLASSES = (
    "fvCEp",
    "fvRsCEpToPathEp",
    "topSystem",
    "fabricLink",
    "lldpAdjEp",
    "fvRsCons",
    "fvRsProv",
    "vzBrCP",
    "vzSubj",
    "vzRsSubjFiltAtt",
    "vzEntry",
    "l3extInstP",
    "l3extSubnet",
    "l3extRsPathL3OutAtt",
)
OFFICIAL_DCN_NETWORK_CLASSES = (
    "fvRsBd",
    "fvBD",
    "fvRsCtx",
    "fvCtx",
    "fvAEPg",
)
OFFICIAL_DCN_FABRIC_ROUTED_CLASSES = (
    "fabricNode",
    "l1PhysIf",
    "ethpmPhysIf",
    "l3EncRtdIf",
)
OFFICIAL_DCN_VMM_CLASSES = (
    "compVm",
    "compHv",
    "fvRsVm",
    "fvRsHyper",
    "compHpNic",
    "hvsAdj",
)
OFFICIAL_DCN_SPINE_CLASSES = (
    "isisAdjEp",
    "coopEpRec",
)
OFFICIAL_DCN_VPC_CLASSES = (
    "pcAggrIf",
    "pcRsMbrIfs",
)
OFFICIAL_DCN_ACLLOG_CLASSES = (
    "acllogPermitL3Pkt",
    "acllogDropL3Pkt",
)
OFFICIAL_DCN_POLICY_COMPLETE_CLASSES = (
    "fvCtx",
    "fvAEPg",
    "fvEPg",
    "fvESg",
    "vzAny",
    "vzRsAnyToCons",
    "vzRsAnyToProv",
    "vzRsAnyToConsIf",
    "vzInTerm",
    "vzOutTerm",
    "vzTaboo",
    "fvRsProtBy",
    "vzRsSubjGraphAtt",
)
OFFICIAL_DCN_RECOMMENDED_CLASSINFO = tuple(
    dict.fromkeys(
        OFFICIAL_DCN_CORE_CLASSES
        + OFFICIAL_DCN_NETWORK_CLASSES
        + OFFICIAL_DCN_VMM_CLASSES
        + OFFICIAL_DCN_SPINE_CLASSES
        + OFFICIAL_DCN_VPC_CLASSES
    )
)


def official_apic_arguments(classes=OFFICIAL_DCN_RECOMMENDED_CLASSINFO) -> str:
    """Return a validated space-separated apic_arguments string for DCN 2.0.10."""
    import re

    pattern = re.compile(r"^[A-Za-z][A-Za-z0-9_-]{0,127}\Z")
    unique: list[str] = []
    seen: set[str] = set()
    for name in classes:
        if not isinstance(name, str) or not pattern.fullmatch(name):
            raise ValueError(f"invalid_aci_class_name:{name!r}")
        if name not in seen:
            seen.add(name)
            unique.append(name)
    if not unique:
        raise ValueError("empty_aci_class_list")
    return " ".join(unique)

