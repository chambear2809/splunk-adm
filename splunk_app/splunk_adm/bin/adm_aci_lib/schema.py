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
