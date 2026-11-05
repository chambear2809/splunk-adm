#!/usr/bin/env python3
from __future__ import annotations
import configparser
import json
import sys
import time
from urllib.parse import parse_qsl, urlsplit
from pathlib import Path

ROOT = Path(__file__).resolve().parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "lib"))
from adm_identity_lib.search import (  # noqa: E402
    bounded_query,
    reduce_rows,
    SearchError,
    NativeSearch,
    bounded_network_query,
    reduce_network_rows,
)
from adm_identity_lib.slices import (  # noqa: E402
    SLICE_SECONDS,
    merge as merge_slices,
    plan as plan_slices,
)
from adm_identity_lib import rollup  # noqa: E402
from splunklib.searchcommands import Configuration, GeneratingCommand, Option, dispatch  # noqa: E402


# Concurrent slice reads per long-window graph. Each read runs one nested job
# at a time, so 2 keeps the caller within the default user role quota (3).
SLICE_WORKERS = 2
# Raw slices read after the newest summarized slice (the not-yet-summarized
# tail) and, when summaries have holes, how many holes are read in full
# before falling back to sampling them.
MAX_TAIL_SLICES = 2
MAX_GAP_READS = 4
# Rollup evidence budget per slice and family; truncated reads are split.
ROLLUP_MAX_ROWS = 200000
ROLLUP_MIN_SPLIT = 2
# Indexed events need a moment to become searchable after their _indextime.
VISIBILITY_MARGIN = 30
# ADM - Qualified graph rollup runs two minutes after each slice ends
# (dispatch -7m@m to -2m@m): a slice is closed for it only when
# lateness + VISIBILITY_MARGIN <= 120 s. Larger horizons are per-run
# (lateness=<s>, adm_qualified_rollup(1)) re-runs over older ranges.
MAX_SCHEDULED_LATENESS = 120 - VISIBILITY_MARGIN
EMPTY_MARKERS = (
    "empty",
    "no qualified observations",
    "No complete interval snapshot",
    "incomplete",
)
# Of those, slices that could not be qualified (not read, unlike empty ones).
UNQUALIFIED_MARKERS = ("No complete interval snapshot", "incomplete")


def sample_gaps(gaps, limit=MAX_GAP_READS):
    """Unsummarized slices read raw: all of them up to ``limit``, else ``limit``
    evenly spaced ones (always the oldest and the newest)."""
    if len(gaps) <= limit:
        return list(gaps)
    if limit < 2:
        return list(gaps[-limit:]) if limit else []
    step = (len(gaps) - 1) / (limit - 1)
    return sorted({gaps[round(i * step)] for i in range(limit)})


def reconcile_runs(rows, seen, chosen, excluded, duplicated, aggregate):
    """Aggregate rows that cover exactly the runs the manifest chose.

    The optimistic aggregate is dispatched beside the manifest read, so a run
    collected between the two (a newly summarized slice, or a concurrent run
    with another horizon) can be read by one and not the other. Its run rows
    say which runs it read: any run not chosen is excluded and the aggregate
    repeated (otherwise that slice would be counted from summaries and again
    from its raw read), and a chosen run holding the selected service that the
    aggregate did not read is re-read (otherwise it would be claimed as
    summarized without contributing). ``aggregate(exclude, dedup)`` returns
    (rows, seen runs).
    """
    runs = {c["run"] for c in chosen.values()}
    rooted = {c["run"] for c in chosen.values() if c["root"]}
    exclude, dedup = set(excluded), bool(duplicated)
    # Documents of a duplicated run need dedup; a re-read applies it.
    doubled = bool(set(duplicated) & seen)
    attempts = 0
    while True:
        stray, missed = seen - runs, rooted - seen
        if not stray and not missed and not doubled:
            return rows
        if attempts == 2:
            raise SearchError(
                "Qualified summaries changed while this window was read; run the search again."
            )
        attempts += 1
        exclude |= stray
        rows, seen = aggregate(exclude, dedup)
        doubled = False


@Configuration(type="events", streaming=False)
class AdmQualified(GeneratingCommand):
    mode = Option(require=True)
    service = Option(require=False)
    environment = Option(require=False)
    namespace = Option(require=False)
    cluster = Option(require=False)
    start = Option(require=False)
    as_of = Option(require=False)
    lateness = Option(require=False)
    # "raw" (default) merges the not-yet-summarized newest minutes; "deferred"
    # answers from summaries only and reports the pending seconds, so a client
    # can render first and merge the raw tail with a second read.
    tail = Option(require=False)

    def generate(self):
        config = configparser.ConfigParser(interpolation=None)
        config.read(
            [
                str(ROOT.parent / "default" / "adm_identity.conf"),
                str(ROOT.parent / "local" / "adm_identity.conf"),
            ]
        )
        profile = dict(config["profile"]) if config.has_section("profile") else {}
        if profile.get("enabled", "false").lower() not in ("true", "1"):
            raise SearchError("Qualified identity is disabled.")
        profile["enabled"] = True
        profile["namespaces"] = [
            x.strip() for x in profile.get("namespaces", "").split(",") if x.strip()
        ]
        now = time.time()
        if self.mode == "rollup":
            for row in self._rollup(profile, config, now):
                yield row
            return
        if self.mode == "summary_health":
            yield self._summary_health(profile, config, now)
            return
        try:
            if self.mode == "graph":
                info = self.metadata.searchinfo
                as_of = float(
                    self.as_of or getattr(info, "latest_time", None) or now - 15
                )
                start = float(
                    self.start or getattr(info, "earliest_time", None) or as_of - 120
                )
            else:
                # Five minutes always spans several complete ownership
                # snapshots, so a producer audit gap cannot empty the catalog.
                as_of = float(self.as_of or now - 15)
                start = float(self.start or as_of - 300)
        except (TypeError, ValueError, OverflowError):
            raise SearchError("Identity search bounds must be finite.") from None
        # Catalog URLs must replay the exact same exclusive search bounds.
        # Reject nonfinite values before conversion and preserve integer epochs.
        import math

        if not math.isfinite(start) or not math.isfinite(as_of):
            raise SearchError("Identity search bounds must be finite.")
        start, as_of = int(start), int(as_of)
        selection = {
            key: getattr(self, key)
            for key in ("service", "environment", "cluster", "namespace")
        }
        if self.mode == "graph" and as_of - start > SLICE_SECONDS:
            output = self._summarized(profile, config, selection, start, as_of)
            if output is None:
                output = self._sliced(profile, config, selection, start, as_of)
        else:
            output = self._window(profile, config, selection, start, as_of)
        # SCP fixes its CSV columns from the first record. Graph records have
        # different shapes, so declare their complete union before emitting any.
        fields = sorted({key for row in output for key in row})
        for row in output:
            yield {key: row.get(key) for key in fields}

    def _sliced(self, profile, config, selection, start, as_of):
        """Long windows: independently qualified slices, merged by qualified ID."""
        from concurrent.futures import ThreadPoolExecutor

        if not all(selection.values()):
            raise SearchError("Graph requires a complete service identity.")
        try:
            windows, total = plan_slices(start, as_of)
        except ValueError as exc:
            raise SearchError(str(exc)) from None

        def one(window):
            try:
                return self._window(profile, config, selection, *window), True
            except (SearchError, ValueError) as exc:
                # A slice without complete evidence or without the selected
                # service contributes nothing; it is never interpolated. An
                # empty slice was read; one without complete evidence was not.
                if any(marker in str(exc) for marker in EMPTY_MARKERS):
                    return None, not any(m in str(exc) for m in UNQUALIFIED_MARKERS)
                raise

        try:
            workers = int(profile.get("slice_workers", SLICE_WORKERS))
        except (TypeError, ValueError):
            raise SearchError("Invalid slice_workers.") from None
        if not 1 <= workers <= 6:
            raise SearchError("slice_workers must be between 1 and 6.")
        with ThreadPoolExecutor(max_workers=workers) as pool:
            results = list(pool.map(one, windows))
        outputs = [rows for rows, _ in results if rows]
        # Empty slices (no evidence, or none for the selected service) are
        # read and contribute nothing; only incomplete ones are unread.
        read = [window for window, (_, ok) in zip(windows, results) if ok]
        if not outputs:
            raise SearchError(
                "Selected service has no qualified observations in this window."
            )
        try:
            merged = merge_slices(outputs, start, as_of, total, read)
        except ValueError as exc:
            raise SearchError(str(exc)) from None
        meta = merged[-1]
        meta["read_coverage"] = (
            100
            if len(read) == total
            else min(99, sum(b - a for a, b in read) * 100 // (as_of - start))
        )
        return merged

    # ------------------------------------------------------------ summaries

    def _settings(self, config):
        section = dict(config["summary"]) if config.has_section("summary") else {}
        flag = section.get("enabled", "false").strip().lower()
        if flag not in ("true", "false", "1", "0"):
            raise SearchError("Invalid summary enabled flag.")
        index = section.get("index", "adm_summary_v2").strip()
        try:
            lateness = int(section.get("lateness", "90"))
        except ValueError:
            raise SearchError("Invalid summary lateness.") from None
        if not 0 <= lateness <= MAX_SCHEDULED_LATENESS:
            raise SearchError(
                f"adm_identity.conf [summary] lateness must be between 0 and "
                f"{MAX_SCHEDULED_LATENESS} seconds: ADM - Qualified graph rollup "
                "summarizes the slice that ended two minutes before it runs. "
                "Re-run a range with a larger horizon with "
                "adm_qualified_rollup(<seconds>) instead."
            )
        try:
            rollup._check_query(index, "0" * 24, "r" + "0" * 16)
        except rollup.SummaryError:
            raise SearchError("Invalid summary index.") from None
        return {"enabled": flag in ("true", "1"), "index": index, "lateness": lateness}

    def _workers(self, profile):
        try:
            workers = int(profile.get("slice_workers", SLICE_WORKERS))
        except (TypeError, ValueError):
            raise SearchError("Invalid slice_workers.") from None
        if not 1 <= workers <= 6:
            raise SearchError("slice_workers must be between 1 and 6.")
        return workers

    def _summary_health(self, profile, config, now):
        """One row describing summary lag, gaps and run hygiene (last 24 h)."""
        settings = self._settings(config)
        row = {
            "summary_enabled": int(settings["enabled"]),
            "summary_index": settings["index"],
            "lateness": settings["lateness"],
        }
        if not settings["enabled"]:
            return {**row, "status": "disabled"}
        network = self._network_config(config, profile)
        fp = rollup.fingerprint(profile, network)
        end = int(now) - int(now) % SLICE_SECONDS
        start = end - 86400
        rows = self._native().run(
            rollup.manifest_query(settings["index"], fp, start, end, "r" + "0" * 16),
            allow_empty=True,
            evidence=False,
            max_rows=4 * rollup.MAX_READ_SLICES,
        )
        chosen, excluded, duplicated = rollup.choose_runs(rows, start, end)
        # Slices the schedule should have finished: closed, past lateness,
        # visibility margin and one five-minute period of scheduling slack.
        due_end = now - settings["lateness"] - VISIBILITY_MARGIN - SLICE_SECONDS
        due = [
            s for s in range(start, end, SLICE_SECONDS) if s + SLICE_SECONDS <= due_end
        ]
        missing = [s for s in due if s not in chosen]
        newest = max(chosen) + SLICE_SECONDS if chosen else None
        lag = int(now - newest) if newest else None
        status = (
            "no_summaries"
            if not chosen
            else "lagging"
            if lag > 3 * SLICE_SECONDS + settings["lateness"]
            else "gaps"
            if missing
            else "ok"
        )
        return {
            **row,
            "status": status,
            "fingerprint": fp,
            "newest_summary_end": newest,
            "lag_seconds": lag,
            "slices_24h": len(chosen),
            "due_slices_24h": len(due),
            "missing_slices_24h": len(missing),
            "oldest_missing": missing[0] if missing else None,
            "newest_missing": missing[-1] if missing else None,
            "empty_slices_24h": sum(1 for c in chosen.values() if c["status"] != "ok"),
            "superseded_or_incomplete_runs": len(excluded),
            "duplicated_runs": len(duplicated),
        }

    def _network_config(self, config, profile):
        network_section = (
            dict(config["network"]) if config.has_section("network") else {}
        )
        flag = network_section.get("enabled", "false").strip().lower()
        if flag not in ("true", "false", "1", "0"):
            raise SearchError("Invalid network enabled flag.")
        if flag not in ("true", "1"):
            return None
        from adm_identity_lib.network_graph import configuration

        try:
            return configuration(
                {
                    "enabled": True,
                    "profiles": json.loads(network_section.get("profiles_json", "[]")),
                    "frontends": json.loads(
                        network_section.get("frontends_json", "[]")
                    ),
                },
                profile,
            )
        except (ValueError, KeyError, configparser.Error) as exc:
            raise SearchError("Invalid attested network configuration.") from exc

    def _native(self):
        session = self.metadata.searchinfo.session_key
        if not isinstance(session, str) or not session:
            raise SearchError("Caller session key is unavailable.")
        return NativeSearch(
            lambda method, path, data=None: self._request(session, method, path, data)
        )

    def _fetch(self, build, start, end, allow_empty=False):
        """Evidence rows for [start, end); truncated reads are split in halves."""
        try:
            return self._native().run(build(start, end), allow_empty=allow_empty)
        except SearchError as exc:
            over = "truncated" in str(exc) or "result budget" in str(exc)
            if not over or end - start < 2 * ROLLUP_MIN_SPLIT:
                raise
        middle = start + (end - start) // 2
        rows = self._fetch(build, start, middle, True) + self._fetch(
            build, middle, end, True
        )
        if len(rows) > ROLLUP_MAX_ROWS:
            raise SearchError("Summary evidence exceeds its per-slice budget.")
        if not rows and not allow_empty:
            raise SearchError("identity evidence is empty")
        return rows

    def _rollup(self, profile, config, now):
        """Write-side: qualified summary documents for whole closed slices."""
        settings = self._settings(config)
        if not settings["enabled"]:
            raise SearchError("Qualified summaries are disabled.")
        info = self.metadata.searchinfo
        try:
            start = int(float(self.start or getattr(info, "earliest_time", None)))
            end = int(float(self.as_of or getattr(info, "latest_time", None)))
            lateness = int(self.lateness or settings["lateness"])
        except (TypeError, ValueError, OverflowError):
            raise SearchError("Summary bounds must be finite epochs.") from None
        if not 0 <= lateness <= 86400:
            raise SearchError("Summary lateness must be between 0 and 86400 seconds.")
        try:
            windows = rollup.slices_of(start, end)
        except rollup.SummaryError as exc:
            raise SearchError(str(exc)) from None
        if len(windows) > 288:
            raise SearchError("A summary run covers at most 288 slices (one day).")
        network = self._network_config(config, profile)
        fp = rollup.fingerprint(profile, network)
        index = settings["index"]
        existing = self._native().run(
            f'search index={index} source="{rollup.SOURCE}" q_fp={fp} '
            f"earliest={start} latest={end} "
            "| stats count AS rows dc(q_doc) AS docs max(q_expected) AS expected by q_run",
            allow_empty=True,
            evidence=False,
            max_rows=10 * len(windows) + 10,
        )
        done = {
            r.get("q_run")
            for r in existing
            if str(r.get("docs")) == str(r.get("expected")) and r.get("expected")
        }
        closed = [w for w in windows if w[1] + lateness <= now - VISIBILITY_MARGIN]
        if len(windows) == 1 and not closed:
            raise SearchError("Summary slice is not closed yet.")
        pending = [
            w
            for w in closed
            if rollup.run_id(w[0], w[1], w[1] + lateness, fp) not in done
        ]

        def one(window):
            try:
                return self._summary_slice(
                    profile, network, window[0], window[1], window[1] + lateness, fp
                ), None
            except (SearchError, ValueError) as exc:
                return None, str(exc)

        if len(pending) == 1:
            results = [one(pending[0])]
        else:
            from concurrent.futures import ThreadPoolExecutor

            with ThreadPoolExecutor(max_workers=self._workers(profile)) as pool:
                results = list(pool.map(one, pending))
        output = []
        for window, (docs, error) in zip(pending, results):
            if error is not None:
                if len(windows) == 1:
                    raise SearchError(error)
                self.write_warning(f"Slice {window[0]} not summarized: {error[:200]}")
                continue
            output.extend(docs)
        # Declare the union of fields before emitting (fixed CSV columns).
        fields = sorted({key for doc in output for key in doc})
        for doc in output:
            yield {key: doc.get(key) for key in fields}

    def _summary_slice(self, profile, network, start, end, horizon, fp):
        from adm_identity_lib.native_network import normalize_records
        from adm_identity_lib.qualified import qualify

        try:
            rows = self._fetch(
                lambda a, b: bounded_query(
                    profile, "graph", start=a, as_of=b, horizon=horizon
                ),
                start,
                end,
            )
        except SearchError as exc:
            if "empty" not in str(exc):
                raise
            return rollup.summarize(
                None, None, network, start, end, horizon, fp, status="empty"
            )
        result = qualify(rows, profile, start, end, horizon, ROLLUP_MAX_ROWS)
        if not result.get("complete"):
            return rollup.summarize(
                None, None, network, start, end, horizon, fp, status="incomplete"
            )
        decoded, counts = None, {"identity": len(rows)}
        if network is not None:
            native = self._fetch(
                lambda a, b: bounded_network_query(
                    network["profiles"], profile, a, b, horizon
                ),
                start,
                end,
                allow_empty=True,
            )
            counts["native"] = len(native)
            decoded = normalize_records(
                native,
                network["profiles"],
                start,
                end,
                horizon=horizon,
                max_rows=ROLLUP_MAX_ROWS,
                max_bytes=400 * 1024 * 1024,
            )
        return rollup.summarize(
            result, decoded, network, start, end, horizon, fp, native_rows=counts
        )

    def _summarized(self, profile, config, selection, start, as_of):
        """Read-side: summaries for closed slices, raw for the newest tail."""
        from concurrent.futures import ThreadPoolExecutor
        from adm_identity_lib.qualified import service_id

        settings = self._settings(config)
        if not settings["enabled"] or not all(selection.values()):
            return None
        tail_mode = self.tail or "raw"
        if tail_mode not in ("raw", "deferred"):
            raise SearchError("tail must be raw or deferred.")
        first, last = start - start % SLICE_SECONDS, as_of - as_of % SLICE_SECONDS
        if last <= first or as_of - first > 8 * 86400:
            return None
        network = self._network_config(config, profile)
        fp = rollup.fingerprint(profile, network)
        root_sid = service_id(selection)
        root = rollup.root_token(root_sid)
        index = settings["index"]
        workers = self._workers(profile)

        def aggregate(exclude=(), dedup=False):
            try:
                query = rollup.aggregate_query(
                    index, fp, first, last, root, sorted(exclude), dedup
                )
                return rollup.split_runs(
                    self._native().run(
                        query,
                        allow_empty=True,
                        evidence=False,
                        max_rows=200000 + rollup.MAX_READ_SLICES,
                    )
                )
            except rollup.SummaryError as exc:
                raise SearchError(str(exc)) from None

        pool = ThreadPoolExecutor(max_workers=workers)
        try:
            # The aggregate normally needs no run exclusions, so it starts
            # beside the manifest read and is repeated only when the runs it
            # read differ from the runs the manifest chose (see below).
            optimistic = pool.submit(aggregate)
            try:
                manifests = self._native().run(
                    rollup.manifest_query(index, fp, first, last, root),
                    allow_empty=True,
                    evidence=False,
                    max_rows=4 * rollup.MAX_READ_SLICES,
                )
                chosen, excluded, duplicated = rollup.choose_runs(
                    manifests, first, last
                )
            except rollup.SummaryError as exc:
                raise SearchError(str(exc)) from None
            if not chosen:
                return None
            newest = max(chosen)
            missing = [s for s in range(first, last, SLICE_SECONDS) if s not in chosen]
            tail = [s for s in missing if s > newest]
            gaps = [s for s in missing if s < newest]
            if len(tail) > MAX_TAIL_SLICES:
                gaps += tail[:-MAX_TAIL_SLICES]
                tail = tail[-MAX_TAIL_SLICES:]
            gaps_read = sample_gaps(gaps)
            raw_windows = [(s, s + SLICE_SECONDS) for s in tail]
            if as_of > last:
                raw_windows.append((last, as_of))
            raw_windows += [(s, s + SLICE_SECONDS) for s in gaps_read]
            pending, unread = [], []
            if tail_mode == "deferred":
                pending, raw_windows = raw_windows, []

            def raw(window):
                try:
                    return self._window(profile, config, selection, *window)
                except (SearchError, ValueError) as exc:
                    if any(marker in str(exc) for marker in EMPTY_MARKERS):
                        return None
                    if "budget" in str(exc) or "truncated" in str(exc):
                        # Over the interactive evidence budget: not read, and
                        # coverage says so; summaries split such slices.
                        unread.append(window)
                        return None
                    raise

            raw_futures = [pool.submit(raw, window) for window in raw_windows]
            rows, seen = optimistic.result()
            rows = reconcile_runs(rows, seen, chosen, excluded, duplicated, aggregate)
            try:
                summary_output = rollup.render(
                    rows,
                    selection,
                    root_sid,
                    chosen,
                    profile["scope"],
                    profile["cluster"],
                    network is not None,
                )
            except rollup.SummaryError as exc:
                raise SearchError(str(exc)) from None
            raw_outputs = [future.result() for future in raw_futures]
        finally:
            pool.shutdown(wait=True, cancel_futures=True)
        outputs = [o for o in [summary_output, *raw_outputs] if o]
        if not outputs:
            raise SearchError(
                "Selected service has no qualified observations in this window."
            )
        raw_windows = [w for w in raw_windows if w not in unread]
        read = [(s, s + SLICE_SECONDS) for s in sorted(chosen)] + raw_windows
        total = -(-(as_of - first) // SLICE_SECONDS)
        try:
            merged = merge_slices(outputs, first, as_of, total, read)
        except ValueError as exc:
            raise SearchError(str(exc)) from None
        meta = merged[-1]
        window_seconds = as_of - first
        summary_seconds = SLICE_SECONDS * len(chosen)
        raw_seconds = sum(b - a for a, b in raw_windows)
        tail_seconds = sum(b - a for a, b in raw_windows if a > newest)
        complete = len(gaps_read) == len(gaps) and not pending and not unread
        meta.update(
            raw_pending_seconds=sum(b - a for a, b in pending),
            summary_slices=len(chosen),
            summary_seconds=summary_seconds,
            summary_through=newest + SLICE_SECONDS,
            raw_seconds=raw_seconds,
            raw_tail_seconds=tail_seconds,
            window_slices_read=len(read),
            window_seconds_read=summary_seconds + raw_seconds,
            read_coverage=100
            if complete
            else min(99, (summary_seconds + raw_seconds) * 100 // window_seconds),
        )
        warnings = [w for w in meta["warnings"] if not w.startswith("Read ")]
        if pending:
            note = (
                f"Summaries: {len(chosen)} five-minute slices; newest "
                f"{sum(b - a for a, b in pending) // 60} min not yet read."
            )
        elif complete:
            note = (
                f"Exact totals: {len(chosen)} summarized five-minute slices"
                + (f", {len(gaps)} unsummarized slices read raw" if gaps else "")
                + f"; newest {tail_seconds // 60} min read raw."
            )
        else:
            note = (
                f"Summary coverage {meta['read_coverage']}%: {len(gaps)} unsummarized slices, "
                f"{len(gaps_read) - len(unread)} read"
                + (f", {len(unread)} over the raw evidence budget" if unread else "")
                + "; counts describe the slices read."
            )
        if first != start:
            # Summaries count whole five-minute slices: say where the counted
            # window starts when the request did not start on a slice.
            note += (
                f" Counted from {first} (the five-minute slice boundary at or "
                f"before the requested start {start})."
            )
        meta["warnings"] = [note, *warnings]
        return merged

    def _window(self, profile, config, selection, start, as_of):
        query = bounded_query(
            profile,
            self.mode,
            self.service,
            self.environment,
            self.namespace,
            self.cluster,
            start,
            as_of,
        )
        service = self.metadata.searchinfo.session_key
        if not isinstance(service, str) or not service:
            raise SearchError("Caller session key is unavailable.")
        if self.mode == "graph" and not all(selection.values()):
            raise SearchError("Graph requires a complete service identity.")
        network = (
            self._network_config(config, profile) if self.mode == "graph" else None
        )
        if network is not None:
            network_query = bounded_network_query(
                network["profiles"], profile, start, as_of
            )
        rows = NativeSearch(
            lambda method, path, data=None: self._request(service, method, path, data)
        ).run(query)
        if network is not None:
            native_rows = NativeSearch(
                lambda method, path, data=None: self._request(
                    service, method, path, data
                )
            ).run(network_query, allow_empty=True)
            return reduce_network_rows(
                rows, native_rows, profile, network, start, as_of, selection
            )
        return reduce_rows(rows, profile, self.mode, start, as_of, selection)

    def _request(self, session_key, method, path, data=None):
        import splunk.rest

        try:
            endpoint = urlsplit(path)
            if (
                endpoint.scheme
                or endpoint.netloc
                or not endpoint.path.startswith("/services")
            ):
                raise SearchError("Invalid local management resource.")
            args = dict(parse_qsl(endpoint.query, strict_parsing=True))
            args["output_mode"] = "json"
            response, body = splunk.rest.simpleRequest(
                endpoint.path,
                sessionKey=session_key,
                method=method,
                getargs=args,
                token=session_key.startswith("eyJ") and session_key.count(".") == 2,
                postargs=data,
                rawResult=True,
                raiseAllErrors=True,
                timeout=15,
            )
            status = int(response.status)
            if not 200 <= status < 300 or len(body) > 48 * 1024 * 1024:
                raise SearchError(
                    "identity management response failed or exceeded its bound"
                )
            return {} if method == "DELETE" else json.loads(body)
        except Exception as exc:
            # Report only the exception class, never transport content or tokens.
            raise SearchError(
                "identity management request failed (" + type(exc).__name__ + ")"
            ) from None


if __name__ == "__main__":
    dispatch(AdmQualified, sys.argv, sys.stdin, sys.stdout, __name__)
