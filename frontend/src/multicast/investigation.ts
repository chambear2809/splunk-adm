import { fingerprint } from "../data/evidence";
import { multicastConfigClient } from "../data/evidenceConfig";
import {
  SearchAccessDeniedError,
  type SearchClient,
} from "../data/searchClient";
import { loadMulticastSource } from "./adapters";
import { loadMulticastForwarding } from "./forwardingSource";
import {
  MULTICAST_VERSION,
  type MulticastAdjacency,
  type MulticastConfiguration,
  type MulticastEvidence,
  type MulticastRequest,
  type MulticastResult,
  type SourceOutcome,
} from "./contract";
import { correlateMulticast } from "./correlation";
import { parseProfiles, validateRequest } from "./inputs";

export class MulticastConfigurationChangedError extends Error {
  constructor() {
    super(
      "Multicast source verification changed. Refresh sources and investigate again.",
    );
    this.name = "MulticastConfigurationChangedError";
  }
}

export async function readMulticastConfiguration(
  signal?: AbortSignal,
): Promise<MulticastConfiguration> {
  const profiles = parseProfiles(
    await multicastConfigClient.readMulticastProfileDocument(signal),
  );
  signal?.throwIfAborted();
  return {
    profiles,
    fingerprint: await fingerprint([MULTICAST_VERSION, profiles]),
  };
}

export async function investigateMulticast(
  client: SearchClient,
  input: MulticastRequest,
  configuration: MulticastConfiguration,
  signal: AbortSignal,
): Promise<MulticastResult> {
  const request = validateRequest(input);
  signal.throwIfAborted();
  const current = await readMulticastConfiguration(signal);
  if (current.fingerprint !== configuration.fingerprint)
    throw new MulticastConfigurationChangedError();
  const profiles = current.profiles.filter(
    (profile) => profile.scope === request.scope,
  );
  if (!profiles.length)
    throw new Error("Choose a routing scope with a verified multicast source.");

  const deadline = AbortSignal.timeout(45000);
  const searchSignal = AbortSignal.any([signal, deadline]);
  const completed = await Promise.all(
    profiles.map(
      async (
        profile,
      ): Promise<{
        evidence: MulticastEvidence[];
        adjacency?: MulticastAdjacency[];
        outcome: SourceOutcome;
      }> => {
        const outcome: SourceOutcome = {
          source: profile.source,
          profile: profile.id,
          state: "unavailable",
        };
        if (
          request.earliest < profile.validFrom ||
          request.latest > profile.validUntil
        )
          return {
            evidence: [],
            outcome: {
              ...outcome,
              detail:
                "Source verification does not cover the selected time window.",
            },
          };
        try {
          if (profile.source === "multicast_nxos")
            return await loadMulticastForwarding(
              client,
              profile,
              request,
              searchSignal,
            );
          return await loadMulticastSource(
            client,
            profile,
            request,
            searchSignal,
          );
        } catch (error) {
          signal.throwIfAborted();
          return {
            evidence: [],
            outcome:
              error instanceof SearchAccessDeniedError
                ? {
                    ...outcome,
                    state: "blocked" as const,
                    detail: "The caller’s search access was denied.",
                  }
                : {
                    ...outcome,
                    detail: deadline.aborted
                      ? "The investigation reached its search time limit."
                      : "The source search could not be completed.",
                  },
          };
        }
      },
    ),
  );
  signal.throwIfAborted();
  try {
    const verified = await readMulticastConfiguration(signal);
    if (verified.fingerprint !== current.fingerprint)
      throw new MulticastConfigurationChangedError();
  } catch {
    signal.throwIfAborted();
    throw new MulticastConfigurationChangedError();
  }
  return {
    ...correlateMulticast(
      request,
      [
        ...completed
          .filter(({ adjacency }) => adjacency)
          .flatMap(({ evidence }) => evidence),
        ...completed
          .filter(({ adjacency }) => !adjacency)
          .flatMap(({ evidence }) => evidence),
      ],
      completed.flatMap(({ adjacency }) => adjacency ?? []),
    ),
    version: MULTICAST_VERSION,
    request,
    capturedAt: Date.now() / 1000,
    configurationFingerprint: current.fingerprint,
    outcomes: [
      ...completed.map(({ outcome }) => outcome),
      ...(profiles.some((profile) => profile.source === "multicast_nxos")
        ? []
        : [
            {
              source: "device_state" as const,
              state: "unavailable" as const,
              detail:
                "This scope has no active NX-OS forwarding snapshot profile.",
            },
          ]),
    ],
  };
}
