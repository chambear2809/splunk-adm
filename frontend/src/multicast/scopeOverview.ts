import type { SearchClient } from "../data/searchClient";
import {
  MULTICAST_VERSION,
  type MulticastConfiguration,
  type ProfileSummary,
  type ScopeWindow,
  type StreamProfile,
} from "./contract";
import { deriveGroupRows, type GroupRow } from "./flags";
import { loadGroupSummary } from "./groupSummary";
import { validateScopeWindow } from "./inputs";
import {
  MulticastConfigurationChangedError,
  readMulticastConfiguration,
} from "./investigation";

export type ScopeComparison =
  | { state: "not-run" }
  | { state: "complete" }
  | { state: "unavailable"; reason: string };

export interface ScopeOverviewResult {
  version: 1;
  window: ScopeWindow;
  profiles: ProfileSummary[];
  rows: GroupRow[];
  comparison: ScopeComparison;
  capturedAt: number;
  configurationFingerprint: string;
}

const NOT_COVERED = "Source verification does not cover the previous window.";
const INCOMPLETE = "The previous-window search did not complete.";

function previousWindow(window: ScopeWindow): ScopeWindow | undefined {
  try {
    return validateScopeWindow({
      ...window,
      earliest: window.earliest - (window.latest - window.earliest),
      latest: window.earliest,
    });
  } catch {
    return undefined;
  }
}

export async function investigateScope(
  client: SearchClient,
  input: ScopeWindow,
  configuration: MulticastConfiguration,
  signal: AbortSignal,
  options: { comparePrevious?: boolean } = {},
): Promise<ScopeOverviewResult> {
  const window = validateScopeWindow(input);
  signal.throwIfAborted();
  const current = await readMulticastConfiguration(signal);
  if (current.fingerprint !== configuration.fingerprint)
    throw new MulticastConfigurationChangedError();
  const profiles = current.profiles.filter(
    (profile): profile is StreamProfile =>
      profile.source !== "multicast_nxos" && profile.scope === window.scope,
  );
  if (!profiles.length) {
    const forwardingOnly = current.profiles.some(
      (profile) =>
        profile.source === "multicast_nxos" && profile.scope === window.scope,
    );
    throw new Error(
      forwardingOnly
        ? "This scope has only a verified forwarding snapshot. Overview and Matrix summarise Stream IGMP and NetFlow; open a group link to inspect the snapshot."
        : "Choose a routing scope with a verified multicast source.",
    );
  }

  const deadline = AbortSignal.timeout(45000);
  const searchSignal = AbortSignal.any([signal, deadline]);
  const summarise = (target: ScopeWindow) =>
    Promise.all(
      profiles.map(async (profile): Promise<ProfileSummary> => {
        try {
          return await loadGroupSummary(client, profile, target, searchSignal);
        } catch {
          signal.throwIfAborted();
          return {
            summaries: [],
            droppedGroups: 0,
            outcome: {
              source: profile.source,
              profile: profile.id,
              state: "unavailable",
              detail: deadline.aborted
                ? "The investigation reached its search time limit."
                : "The source search could not be completed.",
            },
          };
        }
      }),
    );

  const summaries = await summarise(window);
  signal.throwIfAborted();
  let comparison: ScopeComparison = { state: "not-run" };
  let previous: ProfileSummary[] | "unavailable" | undefined;
  if (options.comparePrevious) {
    const earlier = previousWindow(window);
    if (
      !earlier ||
      profiles.some(
        (profile) =>
          profile.validFrom > earlier.earliest ||
          profile.validUntil < earlier.latest,
      )
    ) {
      comparison = { state: "unavailable", reason: NOT_COVERED };
      previous = "unavailable";
    } else {
      const outcomes = await summarise(earlier);
      signal.throwIfAborted();
      if (outcomes.every(({ outcome }) => outcome.state === "complete")) {
        comparison = { state: "complete" };
        previous = outcomes;
      } else {
        comparison = { state: "unavailable", reason: INCOMPLETE };
        previous = "unavailable";
      }
    }
  }

  try {
    const verified = await readMulticastConfiguration(signal);
    if (verified.fingerprint !== current.fingerprint)
      throw new MulticastConfigurationChangedError();
  } catch {
    signal.throwIfAborted();
    throw new MulticastConfigurationChangedError();
  }
  return {
    version: MULTICAST_VERSION,
    window,
    profiles: summaries,
    rows: deriveGroupRows(summaries, previous),
    comparison,
    capturedAt: Date.now() / 1000,
    configurationFingerprint: current.fingerprint,
  };
}
