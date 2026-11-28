import type { ProtocolStatus } from "../contract";
import { StatusChip } from "./StatusChip";

export type BannerState =
  | "loading"
  | "empty"
  | "partial"
  | "unavailable"
  | "blocked"
  | "stale_config"
  | "estimate_only";

const DEFAULTS: Record<
  BannerState,
  { status?: ProtocolStatus; text: string; action?: string }
> = {
  loading: {
    text: "Searching…",
  },
  empty: {
    text: "No matching events in this UTC window.",
  },
  partial: {
    status: "attention",
    text: "Result capped or source partial — narrow the window or filter.",
  },
  unavailable: {
    status: "not_covered",
    text: "Not covered — no configured profile matches this scope and UTC window.",
  },
  blocked: {
    status: "unknown",
    text: "Access denied for one or more source indexes.",
  },
  stale_config: {
    status: "attention",
    text: "Source configuration changed during search; late evidence discarded.",
    action: "Refresh & retry",
  },
  estimate_only: {
    status: "attention",
    text: "Stream is in Estimate mode (statsOnly=true) — enable stream in Splunk Stream.",
  },
};

export function ProtocolStateBanner({
  state,
  reason,
  onAction,
  actionLabel,
}: {
  state: BannerState;
  reason?: string;
  onAction?: () => void;
  actionLabel?: string;
}) {
  const def = DEFAULTS[state];
  const label = actionLabel ?? def.action;
  return (
    <div
      className={`pl-banner pl-banner-${state}`}
      role={
        state === "blocked" || state === "stale_config" ? "alert" : "status"
      }
      data-testid={`protocol-state-${state}`}
    >
      {state === "loading" ? (
        <span className="pl-spinner" aria-hidden="true" />
      ) : def.status ? (
        <StatusChip status={def.status} />
      ) : null}
      <span className="pl-banner-text">{reason || def.text}</span>
      {onAction && label ? (
        <button type="button" className="pl-btn-secondary" onClick={onAction}>
          {label}
        </button>
      ) : null}
    </div>
  );
}
