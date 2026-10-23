#!/usr/bin/env python3
"""Export one complete, bounded SignalFlow service-health capture as HEC NDJSON.

The token is read only from SPLUNK_OBSERVABILITY_TOKEN. This tool never sends
events to Splunk; the completed HEC envelopes require a separately configured
HEC event ingestion job.
"""

from __future__ import annotations

import argparse
from dataclasses import dataclass
from datetime import datetime, timezone
import json
import math
import os
from pathlib import Path
import re
import sys
import tempfile
import threading
import time
from typing import Any, Callable, Iterable, Mapping
import uuid


SCHEMA = "application_atlas.o11y_health.v1"
SOURCETYPE = "atlas:o11y_health"
SDK_VERSION = "1.3.9"
MAX_WINDOW_SECONDS = 86_400
MAX_DATA_POINTS = 10_000
MAX_METRIC_RECORDS = 63  # one completion event makes the Splunk cap 64
MAX_INPUT_TIMESERIES = 10_000
MAX_OUTPUT_BYTES = 1_048_576
DEFAULT_TIMEOUT_SECONDS = 30

SERVICE_DIMENSIONS = (
    "service.name",
    "deployment.environment.name",
    "k8s.cluster.name",
    "k8s.namespace.name",
    "service.namespace",
)
APM_DIMENSIONS = (*SERVICE_DIMENSIONS, "sf_dimensionalized", "sf_mms_id")


@dataclass(frozen=True)
class MetricSpec:
    label: str
    metric: str
    statistic: str
    aggregation: str
    unit: str


METRICS: dict[str, MetricSpec] = {
    "request_count": MetricSpec(
        "request_count",
        "service.request",
        "count",
        "histogram.count(by=apm_service_dimensions)",
        "count",
    ),
    "request_errors": MetricSpec(
        "request_errors",
        "service.request",
        "count",
        "histogram.count(by=apm_service_dimensions, sf_error=true)",
        "count",
    ),
    "request_latency_p90": MetricSpec(
        "request_latency_p90",
        "service.request",
        "percentile_90",
        "histogram.percentile(pct=90, by=apm_service_dimensions)",
        "ns",
    ),
    "container_cpu_utilization": MetricSpec(
        "container_cpu_utilization",
        "container.cpu.utilization",
        "mean",
        "data.mean(by=service_identity_dimensions)",
        "1",
    ),
    "jvm_memory_used": MetricSpec(
        "jvm_memory_used",
        "jvm.memory.used",
        "mean",
        "data.mean(by=service_identity_dimensions)",
        "By",
    ),
}


@dataclass(frozen=True)
class ExportRequest:
    observer: str
    organization_id: str
    realm: str
    scope: str
    service_name: str
    environment: str
    cluster: str
    kubernetes_namespace: str
    apm_mms_id: str
    service_namespace: str | None
    start: float
    end: float
    timeout_seconds: int = DEFAULT_TIMEOUT_SECONDS

    def validate(self) -> None:
        for name in ("observer", "organization_id", "scope"):
            _safe_identifier(getattr(self, name), name)
        if self.observer != self.observer.lower():
            raise ValueError("observer must be a lowercase ingestion identity")
        if not re.fullmatch(r"[a-z][a-z0-9]{0,7}", self.realm):
            raise ValueError("realm is invalid")
        for name in (
            "service_name",
            "environment",
            "cluster",
            "kubernetes_namespace",
        ):
            _safe_dimension(getattr(self, name), name)
        if self.service_namespace is not None:
            _safe_dimension(self.service_namespace, "service_namespace")
        if not re.fullmatch(r"[A-Za-z0-9._:-]{1,128}", self.apm_mms_id):
            raise ValueError("apm_mms_id is not a safe APM MMS identifier")
        if (
            isinstance(self.start, bool)
            or not isinstance(self.start, (int, float))
            or isinstance(self.end, bool)
            or not isinstance(self.end, (int, float))
            or not math.isfinite(self.start)
            or not math.isfinite(self.end)
            or self.start < 0
            or self.end <= self.start
            or self.end - self.start > MAX_WINDOW_SECONDS
        ):
            raise ValueError("window must be an integer interval no longer than 24h")
        if not 1 <= self.timeout_seconds <= 300:
            raise ValueError("timeout must be between 1 and 300 seconds")


def _safe_identifier(value: str, name: str) -> None:
    if not isinstance(value, str) or not re.fullmatch(
        r"[A-Za-z0-9][A-Za-z0-9._:/@-]{0,254}", value
    ):
        raise ValueError(f"{name} is not a safe identifier")


def _safe_dimension(value: str, name: str) -> None:
    if (
        not isinstance(value, str)
        or not value
        or len(value) > 255
        or any(ord(char) < 32 or ord(char) == 127 for char in value)
    ):
        raise ValueError(f"{name} must be a non-empty dimension value")


def _signalflow_string(value: str) -> str:
    # JSON string literals are valid SignalFlow string literals and escape
    # delimiters/control characters without concatenating operator input.
    return json.dumps(value, ensure_ascii=True)


def _identity_filter(request: ExportRequest) -> str:
    pairs = (
        ("service.name", request.service_name),
        ("deployment.environment.name", request.environment),
        ("k8s.cluster.name", request.cluster),
        ("k8s.namespace.name", request.kubernetes_namespace),
    )
    if request.service_namespace is not None:
        pairs += (("service.namespace", request.service_namespace),)
    return " and ".join(
        f"filter({_signalflow_string(key)}, {_signalflow_string(value)})"
        for key, value in pairs
    )


def build_signalflow_program(request: ExportRequest, resolution_seconds: int) -> str:
    """Create fixed SignalFlow; all user input is passed as escaped filters."""
    request.validate()
    if not 1 <= resolution_seconds <= 86_400:
        raise ValueError("resolution is outside the supported range")
    identity = _identity_filter(request)
    dims = "[" + ", ".join(_signalflow_string(x) for x in SERVICE_DIMENSIONS) + "]"
    apm_dims = "[" + ", ".join(_signalflow_string(x) for x in APM_DIMENSIONS) + "]"
    resolution = _signalflow_string(f"{resolution_seconds}s")
    program = [
        f"service_identity = {identity}",
        f"service_identity_dimensions = {dims}",
        f"apm_service_dimensions = {apm_dims}",
        "apm_service_identity = service_identity and "
        'filter("sf_dimensionalized", "true") and '
        f'filter("sf_mms_id", {_signalflow_string(request.apm_mms_id)})',
        'request_histogram = histogram("service.request", '
        f"filter=apm_service_identity, resolution={resolution})",
        "request_histogram.count(by=apm_service_dimensions)"
        '.publish(label="request_count")',
        'error_histogram = histogram("service.request", '
        f'filter=apm_service_identity and filter("sf_error", "true"), '
        f"resolution={resolution})",
        "error_histogram.count(by=apm_service_dimensions)"
        '.publish(label="request_errors")',
        "request_histogram.percentile(pct=90, by=apm_service_dimensions)"
        '.publish(label="request_latency_p90")',
        'data("container.cpu.utilization", filter=service_identity, '
        f"resolution={resolution}).mean(by=service_identity_dimensions)"
        '.publish(label="container_cpu_utilization")',
        'data("jvm.memory.used", filter=service_identity, '
        f"resolution={resolution}).mean(by=service_identity_dimensions)"
        '.publish(label="jvm_memory_used")',
    ]
    return "\n".join(program)


def _dimension(properties: Mapping[str, Any], key: str) -> str:
    value = properties.get(key)
    if not isinstance(value, str) or not value or len(value) > 255:
        raise ValueError(f"SignalFlow output lacks required {key} dimension")
    return value


def _seconds(timestamp_ms: Any, start: float, end: float) -> float:
    if isinstance(timestamp_ms, bool) or not isinstance(timestamp_ms, (int, float)):
        raise ValueError("SignalFlow logical timestamp is invalid")
    value = timestamp_ms / 1000
    if not math.isfinite(value) or value < start or value > end:
        raise ValueError("SignalFlow emitted a point outside the requested window")
    return value


def collect_capture(
    request: ExportRequest,
    computation: Any,
    *,
    captured_at: int | None = None,
    on_timeout: Callable[[], None] | None = None,
    normal_end: Callable[[], bool] | None = None,
) -> list[dict[str, Any]]:
    """Return a complete HEC capture; any stream or identity defect raises."""
    request.validate()
    captured = int(time.time()) if captured_at is None else captured_at
    if captured < 0:
        raise ValueError("capture time is invalid")
    if getattr(computation, "id", None) is None:
        # The SDK may populate the handle after consuming the first message.
        # Defer this check until the stream is fully consumed.
        pass

    # The published chart labels and originating metric are an allowlist. The
    # client exposes metadata via get_metadata(tsid), as documented by Splunk.
    latest: dict[tuple[str, tuple[str, ...]], dict[str, Any]] = {}
    data_points = 0
    labels_with_data: set[str] = set()
    for message in computation.stream():
        message_type = message.__class__.__name__
        if message_type in {"ErrorMessage", "ChannelAbortMessage"}:
            raise ValueError(f"SignalFlow stream ended with {message_type}")
        if not hasattr(message, "logical_timestamp_ms") or not hasattr(message, "data"):
            continue
        timestamp = _seconds(message.logical_timestamp_ms, request.start, request.end)
        if not isinstance(message.data, Mapping):
            raise ValueError("SignalFlow data batch is malformed")
        for tsid, value in message.data.items():
            data_points += 1
            if data_points > MAX_DATA_POINTS:
                raise ValueError("SignalFlow result exceeded the point cap")
            if value is None:
                continue
            if isinstance(value, bool) or not isinstance(value, (int, float)):
                raise ValueError("SignalFlow emitted a non-numeric metric")
            value = float(value)
            if not math.isfinite(value) or value < 0:
                raise ValueError("SignalFlow emitted an invalid metric value")
            metadata = computation.get_metadata(tsid)
            if not isinstance(metadata, Mapping):
                raise ValueError("SignalFlow output metadata is missing")
            # sf_metric is a generated computation MTS ID; publish(label=...)
            # is exposed as sf_streamLabel in SignalFlow metadata.
            label = metadata.get("sf_streamLabel")
            spec = METRICS.get(label) if isinstance(label, str) else None
            originating_metric = metadata.get("sf_originatingMetric")
            if spec is None or (
                originating_metric is not None and originating_metric != spec.metric
            ):
                raise ValueError("SignalFlow output label or metric is unrecognized")
            if spec.metric == "service.request" and (
                metadata.get("sf_dimensionalized") != "true"
                or metadata.get("sf_mms_id") != request.apm_mms_id
            ):
                raise ValueError("SignalFlow APM MMS identity does not match request")
            dimensions = {key: _dimension(metadata, key) for key in SERVICE_DIMENSIONS}
            expected = {
                "service.name": request.service_name,
                "deployment.environment.name": request.environment,
                "k8s.cluster.name": request.cluster,
                "k8s.namespace.name": request.kubernetes_namespace,
            }
            if request.service_namespace is not None:
                expected["service.namespace"] = request.service_namespace
            if any(dimensions[key] != value for key, value in expected.items()):
                raise ValueError("SignalFlow output identity does not match request")
            if metadata.get("sf_error") not in (None, "true", "false"):
                raise ValueError("SignalFlow error dimension is malformed")
            if label == "request_errors" and metadata.get("sf_error") not in (
                None,
                "true",
            ):
                raise ValueError("request_errors stream contains non-error rows")
            key = (label, tuple(dimensions[name] for name in SERVICE_DIMENSIONS))
            previous = latest.get(key)
            if previous and previous["logical_timestamp"] == timestamp:
                raise ValueError("duplicate SignalFlow point for one grouped identity")
            if previous is None or timestamp > previous["logical_timestamp"]:
                latest[key] = {
                    "logical_timestamp": timestamp,
                    "value": value,
                    "spec": spec,
                    "dimensions": dimensions,
                    "sf_service": metadata.get("sf_service"),
                    "sf_environment": metadata.get("sf_environment"),
                    "apm_mms_id": request.apm_mms_id
                    if spec.metric == "service.request"
                    else None,
                    "sf_dimensionalized": metadata.get("sf_dimensionalized")
                    if spec.metric == "service.request"
                    else None,
                    "sf_mms_id": metadata.get("sf_mms_id")
                    if spec.metric == "service.request"
                    else None,
                    "sf_error": "true" if label == "request_errors" else None,
                    "metric_source_basis": "sf_originatingMetric"
                    if originating_metric == spec.metric
                    else "fixed_signalflow_program",
                }
            labels_with_data.add(label)
            if len(latest) > MAX_METRIC_RECORDS:
                raise ValueError("SignalFlow grouped result exceeded the record cap")

    # This is the SDK's state set only by EndOfChannelMessage. close() also sets
    # it, so the timeout path is separately latched and cannot publish success.
    if getattr(computation, "state", None) != getattr(
        computation, "STATE_COMPLETED", 4
    ):
        raise ValueError("SignalFlow did not send a normal end-of-channel")
    if getattr(computation, "find_limited_resultset", False):
        raise ValueError("SignalFlow limited the matched result set")
    if getattr(computation, "group_by_missing_property", False):
        raise ValueError("SignalFlow service identity dimensions are missing")
    if getattr(computation, "num_input_timeseries", 0) > MAX_INPUT_TIMESERIES:
        raise ValueError("SignalFlow input time-series cap was exceeded")
    if not getattr(computation, "id", None):
        raise ValueError("SignalFlow computation did not start")
    if normal_end is not None and not normal_end():
        raise ValueError("SignalFlow did not deliver EndOfChannelMessage")
    if on_timeout is not None and on_timeout():
        raise TimeoutError("SignalFlow query timed out")

    resolution_ms = getattr(computation, "resolution", None)
    if latest and (
        isinstance(resolution_ms, bool)
        or not isinstance(resolution_ms, (int, float))
        or not math.isfinite(resolution_ms)
        or resolution_ms <= 0
    ):
        raise ValueError("SignalFlow actual resolution was not reported")
    actual_resolution_seconds = (
        resolution_ms / 1000 if resolution_ms is not None else None
    )

    namespaces = {entry["dimensions"]["service.namespace"] for entry in latest.values()}
    if request.service_namespace is None and len(namespaces) > 1:
        raise ValueError(
            "More than one OTel service.namespace matched; select an explicit service namespace"
        )

    output = []
    for entry in sorted(
        latest.values(),
        key=lambda row: (row["spec"].label, row["dimensions"]["service.namespace"]),
    ):
        spec: MetricSpec = entry["spec"]
        dims = entry["dimensions"]
        event = {
            "schema": SCHEMA,
            "event_type": "metric",
            "capture_id": "",  # filled after capture identity is allocated
            "captured_at": captured,
            "capture_window_start": request.start,
            "capture_window_end": request.end,
            "observer_id": request.observer,
            "organization_id": request.organization_id,
            "realm": request.realm,
            "routing_scope": request.scope,
            "service_name": request.service_name,
            "environment": request.environment,
            "cluster": request.cluster,
            "kubernetes_namespace": request.kubernetes_namespace,
            "service_namespace": dims["service.namespace"],
            "apm_mms_id": entry["apm_mms_id"],
            "sf_dimensionalized": entry["sf_dimensionalized"],
            "sf_mms_id": entry["sf_mms_id"],
            "signal_label": spec.label,
            "metric_name": spec.metric,
            "metric_source_basis": entry["metric_source_basis"],
            "statistic": spec.statistic,
            "unit": spec.unit,
            "aggregation": spec.aggregation,
            "resolution_seconds": actual_resolution_seconds,
            "logical_timestamp": entry["logical_timestamp"],
            "value": entry["value"],
            "sf_service": entry["sf_service"]
            if isinstance(entry["sf_service"], str)
            else None,
            "sf_environment": entry["sf_environment"]
            if isinstance(entry["sf_environment"], str)
            else None,
            "sf_error": entry["sf_error"],
            "pod_uid": None,
            "container_name": None,
            "host_name": None,
            "jvm_memory_pool_name": None,
        }
        output.append(event)

    if len(output) > MAX_METRIC_RECORDS:
        raise ValueError("SignalFlow result exceeded the metric record cap")
    capture_id = str(uuid.uuid4())
    for event in output:
        event["capture_id"] = capture_id
    output.append(
        {
            "schema": SCHEMA,
            "event_type": "export_completion",
            "capture_id": capture_id,
            "captured_at": captured,
            "capture_window_start": request.start,
            "capture_window_end": request.end,
            "observer_id": request.observer,
            "organization_id": request.organization_id,
            "realm": request.realm,
            "routing_scope": request.scope,
            "service_name": request.service_name,
            "environment": request.environment,
            "cluster": request.cluster,
            "kubernetes_namespace": request.kubernetes_namespace,
            "apm_mms_id": request.apm_mms_id,
            "sf_dimensionalized": "true",
            "sf_mms_id": request.apm_mms_id,
            "service_namespace": request.service_namespace,
            "expected_record_count": len(output),
            "signals_with_data": len(labels_with_data),
        }
    )
    return output


def _resolution_seconds(request: ExportRequest) -> int:
    # Keep no more than about 300 points per signal for a full-day query.
    return max(10, math.ceil((request.end - request.start) / 300))


def render_hec_ndjson(
    request: ExportRequest, events: Iterable[Mapping[str, Any]]
) -> str:
    capture = list(events)
    if not capture or len(capture) > MAX_METRIC_RECORDS + 1:
        raise ValueError("capture has no completion event or exceeds its row cap")
    if capture[-1].get("event_type") != "export_completion":
        raise ValueError("completion event must be the final row")
    capture_id = capture[-1].get("capture_id")
    if not isinstance(capture_id, str) or any(
        event.get("capture_id") != capture_id for event in capture
    ):
        raise ValueError("capture IDs do not agree")
    lines = []
    for event in capture:
        envelope = {
            "time": event["captured_at"],
            "host": request.observer,
            "source": "atlas:o11y_health/export",
            "sourcetype": SOURCETYPE,
            "event": event,
        }
        lines.append(json.dumps(envelope, ensure_ascii=False, separators=(",", ":")))
    rendered = "\n".join(lines) + "\n"
    if len(rendered.encode("utf-8")) > MAX_OUTPUT_BYTES:
        raise ValueError("completed export exceeds the output byte cap")
    return rendered


def publish_atomic(path: Path, rendered: str) -> None:
    """Publish the complete file atomically, refusing to replace an existing file."""
    path = path.expanduser().resolve()
    if path.exists():
        raise FileExistsError("refusing to overwrite an existing export file")
    if not path.parent.is_dir():
        raise FileNotFoundError("export directory must already exist")
    temporary_name: str | None = None
    try:
        with tempfile.NamedTemporaryFile(
            mode="w",
            encoding="utf-8",
            newline="\n",
            dir=path.parent,
            prefix=f".{path.name}.",
            suffix=".partial",
            delete=False,
        ) as handle:
            temporary_name = handle.name
            os.chmod(temporary_name, 0o600)
            handle.write(rendered)
            handle.flush()
            os.fsync(handle.fileno())
        # link() is exclusive and atomic. A race cannot replace another file.
        os.link(temporary_name, path)
        os.unlink(temporary_name)
        temporary_name = None
        directory_fd = os.open(path.parent, os.O_RDONLY)
        try:
            os.fsync(directory_fd)
        finally:
            os.close(directory_fd)
    finally:
        if temporary_name and os.path.exists(temporary_name):
            os.unlink(temporary_name)


def _make_sdk_client(token: str, realm: str, timeout_seconds: int) -> Any:
    try:
        from signalfx.signalflow import SignalFlowClient
    except ImportError as error:  # pragma: no cover - depends on operator install
        raise RuntimeError(
            f"install signalflow-client-python=={SDK_VERSION}"
        ) from error
    endpoint = f"https://stream.{realm}.observability.splunkcloud.com"
    return SignalFlowClient(token=token, endpoint=endpoint, timeout=timeout_seconds)


class _EndOfChannelTracker:
    def __init__(self) -> None:
        self.count = 0

    def wrap(self, channel: Any) -> Any:
        tracker = self

        class TrackingChannel:
            def __init__(self, source: Any) -> None:
                self.source = source

            def __iter__(self) -> "TrackingChannel":
                return self

            def __next__(self) -> Any:
                message = next(self.source)
                if message.__class__.__name__ == "EndOfChannelMessage":
                    tracker.count += 1
                return message

            def next(self) -> Any:
                return self.__next__()

            def close(self) -> Any:
                close = getattr(self.source, "close", None)
                return close() if callable(close) else None

        return TrackingChannel(channel)


def _track_sdk_completion(computation: Any, tracker: _EndOfChannelTracker) -> None:
    """Track raw EOC messages because the SDK consumes them and exposes state."""
    stream = getattr(computation, "_stream", None)
    execute = getattr(computation, "_execute", None)
    if stream is None or not callable(execute):
        raise ValueError("unsupported SignalFlow client computation shape")
    computation._stream = tracker.wrap(stream)

    def tracked_execute() -> Any:
        return tracker.wrap(execute())

    computation._execute = tracked_execute


def run_export(
    request: ExportRequest,
    output: Path,
    *,
    token: str,
    client_factory: Callable[[str, str, int], Any] = _make_sdk_client,
    captured_at: int | None = None,
) -> list[dict[str, Any]]:
    request.validate()
    if not token:
        raise ValueError("SPLUNK_OBSERVABILITY_TOKEN is required")
    client = client_factory(token, request.realm, request.timeout_seconds)
    computation: Any = None
    end_tracker = _EndOfChannelTracker()
    timed_out = threading.Event()
    timer: threading.Timer | None = None
    try:
        resolution = _resolution_seconds(request)
        program = build_signalflow_program(request, resolution)
        computation = client.execute(
            program,
            start=int(request.start * 1000),
            stop=int(request.end * 1000),
            resolution=resolution * 1000,
            immediate=True,
        )
        _track_sdk_completion(computation, end_tracker)

        def timeout_stream() -> None:
            timed_out.set()
            if computation is not None:
                try:
                    computation.close()
                except Exception:
                    pass
            try:
                client.close()
            except Exception:
                pass

        timer = threading.Timer(request.timeout_seconds, timeout_stream)
        timer.daemon = True
        timer.start()
        events = collect_capture(
            request,
            computation,
            captured_at=captured_at,
            on_timeout=timed_out.is_set,
            normal_end=lambda: end_tracker.count == 1,
        )
        if timer:
            timer.cancel()
            timer = None
        if timed_out.is_set():
            raise TimeoutError("SignalFlow query timed out")
        rendered = render_hec_ndjson(request, events)
        if timed_out.is_set():
            raise TimeoutError("SignalFlow query timed out")
        publish_atomic(output, rendered)
        return events
    finally:
        if timer:
            timer.cancel()
        try:
            client.close()
        except Exception:
            pass


def _parse_time(value: str) -> float:
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as error:
        raise argparse.ArgumentTypeError(
            "use an ISO-8601 time with UTC offset"
        ) from error
    if parsed.tzinfo is None:
        raise argparse.ArgumentTypeError("time must include a UTC offset")
    return parsed.astimezone(timezone.utc).timestamp()


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--observer", required=True)
    parser.add_argument("--organization-id", required=True)
    parser.add_argument("--realm", required=True)
    parser.add_argument("--scope", required=True)
    parser.add_argument("--service-name", required=True)
    parser.add_argument("--environment", required=True)
    parser.add_argument("--cluster", required=True)
    parser.add_argument("--kubernetes-namespace", required=True)
    parser.add_argument("--apm-mms-id", required=True)
    parser.add_argument("--service-namespace")
    parser.add_argument("--start", required=True, type=_parse_time)
    parser.add_argument("--end", required=True, type=_parse_time)
    parser.add_argument("--timeout", type=int, default=DEFAULT_TIMEOUT_SECONDS)
    parser.add_argument("--output", required=True, type=Path)
    args = parser.parse_args(argv)
    request = ExportRequest(
        observer=args.observer,
        organization_id=args.organization_id,
        realm=args.realm,
        scope=args.scope,
        service_name=args.service_name,
        environment=args.environment,
        cluster=args.cluster,
        kubernetes_namespace=args.kubernetes_namespace,
        apm_mms_id=args.apm_mms_id,
        service_namespace=args.service_namespace,
        start=args.start,
        end=args.end,
        timeout_seconds=args.timeout,
    )
    token = os.environ.get("SPLUNK_OBSERVABILITY_TOKEN", "")
    try:
        events = run_export(request, args.output, token=token)
    except Exception:
        # SDK errors can include request/transport context. Keep output generic
        # so credentials and source payloads are never copied to a terminal log.
        print(
            "Observability Cloud export failed; no complete file was published.",
            file=sys.stderr,
        )
        return 1
    print(f"Published {len(events)} complete events to {args.output}")
    return 0


if __name__ == "__main__":  # pragma: no cover - CLI entry point
    raise SystemExit(main())
