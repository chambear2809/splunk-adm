import type { Graph } from "../graph";
import type { CatalogRow } from "../data/catalog";
import { checkedIdentityContext } from "../data/identityContext";
import { BusinessOwnershipContext } from "./BusinessOwnershipContext";
import type { NativeServiceIdentity } from "./bindings";
import type { ObservationTime } from "./ownership";

type Input = {
  graph?: Graph;
  catalogRow?: CatalogRow;
  unavailableReason?: string;
};
const validKey = (key: NativeServiceIdentity["key"]) =>
  Object.values(key).every(
    (v) => typeof v === "string" && v.length > 0 && v === v.trim(),
  );

/** Only explicit, source-qualified tuples become native references. Labels and IDs are never parsed. */
export function ownershipEvidence({
  graph,
  catalogRow,
  unavailableReason,
}: Input): {
  nativeIdentities: NativeServiceIdentity[];
  time: ObservationTime;
  unavailableReason?: string;
} {
  const window = graph
    ? {
        start: Date.parse(graph.window.start) / 1000,
        end: Date.parse(graph.window.end) / 1000,
      }
    : {
        start: catalogRow?.window_start ?? NaN,
        end: catalogRow?.window_end ?? NaN,
      };
  const time: ObservationTime =
    Number.isSafeInteger(window.start) &&
    Number.isSafeInteger(window.end) &&
    window.end > window.start
      ? { kind: "interval", from: window.start, to: window.end }
      : { kind: "point", at: 0 };
  const unavailable = (reason: string) => ({
    nativeIdentities: [],
    time,
    unavailableReason: reason,
  });
  if (unavailableReason) return unavailable(unavailableReason);
  if (graph?.demo)
    return unavailable(
      "Demo observations do not establish a live ownership binding.",
    );
  if (catalogRow && catalogRow.identity_contract !== "qualified_v2")
    return unavailable(
      "This catalog row has no qualified native identity provenance.",
    );
  try {
    const context = checkedIdentityContext(
      graph?.identityContext ?? catalogRow?.identityContext,
      window,
    );
    const keys = graph
      ? graph.nodes
          .filter((n) => n.kind === "service")
          .map((n) => ({
            service: n.attributes?.service ?? "",
            environment: n.attributes?.environment ?? "",
            cluster: n.cluster ?? "",
            namespace: n.namespace ?? "",
          }))
      : catalogRow
        ? [
            {
              service: catalogRow.service,
              environment: catalogRow.environment,
              cluster: catalogRow.cluster,
              namespace: catalogRow.namespace,
            },
          ]
        : [];
    const nativeIdentities = [
      ...new Map(
        keys.filter(validKey).map((key) => [
          JSON.stringify(key),
          {
            kind: "service" as const,
            contract: context.contract,
            authority: context.authority,
            scope: context.scope,
            configRevision: context.configRevision,
            observedWindow: context.observedWindow,
            key,
          },
        ]),
      ).values(),
    ];
    if (!nativeIdentities.length)
      return unavailable(
        "No explicit qualified service tuple is available in this capture.",
      );
    return { nativeIdentities, time };
  } catch {
    return unavailable(
      "Qualified source identity provenance is unavailable for this capture. Imported names cannot establish ownership.",
    );
  }
}

export function OwnershipEvidence(props: Input) {
  return <BusinessOwnershipContext {...ownershipEvidence(props)} compact />;
}
