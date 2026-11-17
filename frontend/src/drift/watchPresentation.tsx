import type { WatchStatus } from "./client";

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
}: {
  signature: string;
  details?: boolean;
}) {
  const value = watchIdentity(signature);
  if (!value)
    return (
      <span>Dependency change recorded; identity details unavailable.</span>
    );
  return (
    <>
      <span>
        Dependency change recorded: {value.source} → {value.destination} ·{" "}
        {value.protocol}/{value.port}
      </span>
      {details && (
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
        Checked at {new Date(at * 1000).toISOString()}: {value.count} distinct
        observation {value.count === 1 ? "window" : "windows"}; threshold{" "}
        {value.thresholdMet ? "met" : "not yet met"}; expected window{" "}
        {value.expected ? "active" : "inactive"}; cooldown{" "}
        {value.coolingDown ? "active" : "inactive"}.
      </p>
    </section>
  );
}
