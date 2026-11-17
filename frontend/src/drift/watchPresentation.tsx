import type { WatchStatus } from "./client";
import type { Finding } from "./model";

const kindLabels: Record<Finding["kind"], string> = {
  new_destination_port: "Newly observed destination or port",
  changed_dependency: "Changed dependency observed",
  newly_blocked: "Newly reported blocked",
  lost_redundancy: "Fewer observed failure domains",
  not_observed: "Not observed in this window",
};

interface WatchIdentity {
  authority: string;
  scope: string;
  source: string;
  destination: string;
  protocol: string;
  port: number;
  relation: string;
  direction: string;
}

const present = (value: unknown): value is string =>
  typeof value === "string" &&
  value.length > 0 &&
  value.length <= 1024 &&
  value.trim() === value &&
  !/[\uD800-\uDFFF]/u.test(value) &&
  ![...value].some((character) => {
    const code = character.charCodeAt(0);
    return code < 32 || code === 127;
  });

/** Decode only the exact versioned identity tuple; never infer a finding kind. */
export function watchIdentity(signature: string): WatchIdentity | undefined {
  if (typeof signature !== "string" || signature.length > 4096)
    return undefined;
  try {
    const value: unknown = JSON.parse(signature);
    if (!Array.isArray(value) || value.length !== 9 || value[0] !== 1)
      return undefined;
    const [
      ,
      authority,
      scope,
      source,
      destination,
      protocol,
      port,
      relation,
      direction,
    ] = value;
    if (
      ![
        authority,
        scope,
        source,
        destination,
        protocol,
        relation,
        direction,
      ].every(present) ||
      typeof port !== "number" ||
      !Number.isInteger(port) ||
      port < 1 ||
      port > 65535
    )
      return undefined;
    return {
      authority,
      scope,
      source,
      destination,
      protocol,
      port,
      relation,
      direction,
    } as WatchIdentity;
  } catch {
    return undefined;
  }
}

export function WatchDependency({
  signature,
  details = true,
  changeKinds,
  baselineVersion,
}: {
  signature: string;
  details?: boolean;
  changeKinds?: Finding["kind"][];
  baselineVersion?: number;
}) {
  const value = watchIdentity(signature);
  return (
    <>
      <span>
        {value ? (
          <>
            {!changeKinds && "Dependency change recorded: "}
            {value.source} → {value.destination} · {value.protocol}/{value.port}
          </>
        ) : (
          "Dependency change recorded; identity details unavailable."
        )}
      </span>
      {changeKinds && (
        <>
          <p>{changeKinds.map((kind) => kindLabels[kind]).join(" · ")}</p>
          <p>Compared with baseline version {baselineVersion}</p>
        </>
      )}
      {details && value && (
        <details>
          <summary>Source and relationship details</summary>
          <p>
            Authority: {value.authority} · Scope: {value.scope} · Relationship:{" "}
            {value.relation} · Direction: {value.direction}
          </p>
        </details>
      )}
    </>
  );
}

export function WatchStatusSummary({
  signature,
  at,
  value,
}: {
  signature: string;
  at: number;
  value: WatchStatus;
}) {
  return (
    <section aria-label="Authorized watch status">
      <WatchDependency signature={signature} details={false} />
      <p>
        Counts distinct recorded windows with any qualifying change for this
        dependency, across change types.
      </p>
      <p>
        Checked at {new Date(at * 1000).toISOString()}: {value.count} distinct
        observation {value.count === 1 ? "window" : "windows"}; threshold{" "}
        {value.thresholdMet ? "met" : "not yet met"}; expected window{" "}
        {value.expected ? "active" : "inactive"}; cooldown{" "}
        {value.coolingDown ? "active" : "inactive"}.
      </p>
    </section>
  );
}
