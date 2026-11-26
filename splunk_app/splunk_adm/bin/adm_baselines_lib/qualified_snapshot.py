"""Read already-indexed qualified graph summaries. No collector is created."""

from .executor import Unavailable


class SnapshotUnavailable(Unavailable):
    pass


class QualifiedSnapshotProvider:
    """Resolve retained ``source=adm:qualified`` summaries written by admqualified.

    The broker must already hold closed, independently authorized records. This
    adapter never dispatches collection, SNMP polls, syslog listeners or HEC
    inputs. Operators collect with Stream, SC4SNMP, SC4S, Splunkbase TAs and
    the Splunk Distribution of OpenTelemetry Collector.
    """

    contract_revision = "qualified-snapshot-v1"
    required_source = "adm:qualified"

    def __init__(self, broker):
        self.broker = broker

    def lookup(self, principal, selection, window):
        if not isinstance(principal, str) or not principal:
            raise SnapshotUnavailable("principal required")
        if not isinstance(selection, dict) or set(selection) != {
            "service",
            "environment",
            "cluster",
            "namespace",
        }:
            raise SnapshotUnavailable("invalid selection")
        if not isinstance(window, dict):
            raise SnapshotUnavailable("invalid window")
        references = self.broker.lookup(principal, selection, window)
        if not isinstance(references, list):
            raise SnapshotUnavailable("invalid retained catalog")
        rows = []
        for reference in references:
            record = self.broker.read(reference)
            if not isinstance(record, dict):
                raise SnapshotUnavailable("invalid retained record")
            capture = record.get("capture")
            provenance = record.get("provenance")
            source = capture.get("source") if isinstance(capture, dict) else None
            proven = provenance.get("source") if isinstance(provenance, dict) else None
            if source != self.required_source or proven != self.required_source:
                raise SnapshotUnavailable(
                    "only source=adm:qualified summaries are admitted"
                )
            if not self.broker.authorize(principal, reference, provenance):
                raise SnapshotUnavailable("retained record is not authorized")
            rows.append(capture)
        if not rows:
            raise SnapshotUnavailable("no source=adm:qualified summaries are retained")
        return rows
