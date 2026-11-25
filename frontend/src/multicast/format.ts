import type { FlowGroupSummary, ProfileSummary } from "./contract";

export const formatTime = (seconds: number, timezone?: string) => {
  try {
    return new Intl.DateTimeFormat(undefined, {
      dateStyle: "medium",
      timeStyle: "medium",
      timeZone: timezone,
    }).format(new Date(seconds * 1000));
  } catch {
    return new Date(seconds * 1000).toISOString();
  }
};

const count = new Intl.NumberFormat("en-US");

/**
 * One exporter's flow evidence, on its own line. Never sum packets or bytes
 * across exporters: different sampling intervals, replication positions or
 * counter meanings (delta vs total) do not combine into one quantity.
 */
export const flowEvidenceLine = (flow: FlowGroupSummary): string => {
  const counts =
    flow.packets !== undefined && flow.bytes !== undefined
      ? `${count.format(flow.packets)} packets, ${count.format(flow.bytes)} bytes`
      : "counts not reported";
  const replication =
    flow.replication === "unknown"
      ? "replication unknown"
      : `${flow.replication} replication`;
  return `${flow.observer} · ${flow.direction}: ${counts} · sampling 1:${flow.samplingInterval} · ${replication} · ${flow.counters} counters`;
};

/** Cap notice using the profile's own reason, never claiming the group limit was reached. */
export const cappedNotice = (profile: ProfileSummary): string => {
  const label = profile.outcome.profile ?? profile.outcome.source;
  const noun = profile.droppedGroups === 1 ? "group" : "groups";
  const detail = profile.outcome.detail ? ` ${profile.outcome.detail}` : "";
  return `${profile.droppedGroups} ${noun} not shown for ${label}.${detail}`;
};

/** The empty-scope message, distinguishing "nothing observed" from "nothing searched". */
export const emptyScopeNotice = (profiles: ProfileSummary[]): string =>
  profiles.some((profile) => profile.outcome.state === "complete")
    ? "No caller-visible multicast groups in this window. This does not establish that none exist."
    : "No source in this scope completed its search. This does not establish that no groups exist.";
