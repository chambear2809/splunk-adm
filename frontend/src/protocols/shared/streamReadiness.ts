import { optionalJobs } from "../../data/optionalJobs";
import {
  SearchAccessDeniedError,
  requireNoSearchErrors,
  type SearchClient,
} from "../../data/searchClient";

export type StreamReadinessState = "enabled" | "estimate_only" | "unknown";

export interface StreamReadinessEntry {
  streamId: string;
  state: StreamReadinessState;
  detail: string;
  estimateHosts?: string[];
  enabledHosts?: string[];
}

const STREAM_ID_RE = /^[a-z0-9_]{1,32}$/;

/**
 * Explicit on-demand check of Splunk Stream `stream:stats` (`_internal`) to
 * detect streams stuck in Estimate mode (`statsOnly=true`) per forwarder host.
 *
 * Uses the Splunk App for Stream 8.1.6 JSON event structure
 * (`senders{}.streams{}.id` and `senders{}.streams{}.stats_only`), matching
 * `macros.conf` (`stream_stats_estimate`).
 *
 * Never dispatched automatically on page load. If the caller lacks `_internal`
 * access or no `stream:stats` rows exist, fails safely to `"unknown"`.
 */
export async function checkStreamEstimateMode(
  client: SearchClient,
  streamIds: readonly string[],
  signal: AbortSignal,
): Promise<StreamReadinessEntry[]> {
  const validIds = streamIds.filter((id) => STREAM_ID_RE.test(id));
  if (!validIds.length) return [];
  const deadline = AbortSignal.timeout(20000);
  const searchSignal = AbortSignal.any([signal, deadline]);
  const idList = validIds.map((id) => `"${id}"`).join(", ");
  const spl =
    `search index=_internal sourcetype="stream:stats" ` +
    `| eval _pairs=mvzip('senders{}.streams{}.id', 'senders{}.streams{}.stats_only', "|") ` +
    `| mvexpand _pairs ` +
    `| eval stream_id=mvindex(split(_pairs, "|"), 0), stats_only=mvindex(split(_pairs, "|"), 1) ` +
    `| where stream_id IN (${idList}) ` +
    `| stats latest(stats_only) as stats_only by host stream_id ` +
    `| head 256`;
  try {
    const result = await optionalJobs.run(
      "protocol_stream_readiness",
      `stream-readiness:${validIds.join(",")}`,
      client,
      {
        search: spl,
        earliest: "-15m",
        latest: "now",
        maxRows: 256,
        allowEmpty: true,
        overflow: "truncate",
        signal: searchSignal,
      },
    );
    requireNoSearchErrors(result, "Stream Estimate-mode check");
    const byStream = new Map<
      string,
      { estimateHosts: string[]; enabledHosts: string[] }
    >();
    for (const row of result.rows) {
      const id =
        typeof row.stream_id === "string"
          ? row.stream_id.trim().toLowerCase()
          : "";
      const host =
        typeof row.host === "string" && row.host.trim()
          ? row.host.trim()
          : "unknown-host";
      const statsOnly = String(row.stats_only ?? "")
        .trim()
        .toLowerCase();
      if (!id || (statsOnly !== "true" && statsOnly !== "false")) continue;
      const bucket = byStream.get(id) ?? {
        estimateHosts: [],
        enabledHosts: [],
      };
      if (statsOnly === "true") bucket.estimateHosts.push(host);
      else bucket.enabledHosts.push(host);
      byStream.set(id, bucket);
    }
    return validIds.map((streamId): StreamReadinessEntry => {
      const observed = byStream.get(streamId);
      if (!observed) {
        return {
          streamId,
          state: "unknown",
          detail: "No recent stream:stats telemetry observed for this stream.",
        };
      }
      if (
        observed.estimateHosts.length > 0 &&
        observed.enabledHosts.length > 0
      ) {
        return {
          streamId,
          state: "estimate_only",
          estimateHosts: observed.estimateHosts,
          enabledHosts: observed.enabledHosts,
          detail: `Mixed: Estimate mode (statsOnly=true) on ${observed.estimateHosts.length} forwarder(s), Enabled on ${observed.enabledHosts.length}.`,
        };
      }
      if (observed.estimateHosts.length > 0) {
        return {
          streamId,
          state: "estimate_only",
          estimateHosts: observed.estimateHosts,
          detail:
            "Stream is in Estimate mode (statsOnly=true); switch to Enabled to emit protocol events.",
        };
      }
      return {
        streamId,
        state: "enabled",
        enabledHosts: observed.enabledHosts,
        detail: `Stream is Enabled on ${observed.enabledHosts.length} forwarder(s) (statsOnly=false).`,
      };
    });
  } catch (error) {
    if (signal.aborted) throw error;
    const detail =
      error instanceof SearchAccessDeniedError
        ? "Caller lacks _internal search access; Stream mode is unknown."
        : "Stream mode check could not complete; Stream mode is unknown.";
    return validIds.map((streamId) => ({
      streamId,
      state: "unknown",
      detail,
    }));
  }
}
