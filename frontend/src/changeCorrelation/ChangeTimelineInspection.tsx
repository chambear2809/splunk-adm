import { useCallback, useEffect, useRef, useState } from "react";
import type { SearchClient } from "../data/searchClient";
import { changeTimelineConfigurationClient } from "./configuration";
import {
  loadChangeActivation,
  loadChangeTimeline,
  validateTimelineView,
} from "./history";
import { ChangeTimeline } from "./ChangeTimeline";
import type {
  ChangeTimelineConfigurationClient,
  ChangeTimelineContext,
  ChangeTimelineResult,
  ChangeTimelineWindow,
} from "./types";

export interface ChangeTimelineInspectionProps {
  client: SearchClient;
  view: { scope: string; window: ChangeTimelineWindow };
  context?: ChangeTimelineContext;
  configurationClient?: ChangeTimelineConfigurationClient;
}

type InspectionValue =
  | {
      status:
        | "idle"
        | "loading_configuration"
        | "loading_activation"
        | "loading_history"
        | "cancelled";
    }
  | { status: "not_selected" }
  | { status: "configuration_unavailable" }
  | { status: "history_unavailable" }
  | { status: "loaded"; result: ChangeTimelineResult };

interface InspectionState {
  key: string;
  value: InspectionValue;
}

export async function runChangeTimelineInspection({
  client,
  view,
  configurationClient,
  signal,
  onPhase,
}: {
  client: SearchClient;
  view: ChangeTimelineInspectionProps["view"];
  configurationClient: ChangeTimelineConfigurationClient;
  signal: AbortSignal;
  onPhase?: (phase: "configuration" | "activation" | "history") => void;
}): Promise<
  | { status: "not_selected" }
  | { status: "loaded"; result: ChangeTimelineResult }
> {
  const ensureActive = () => {
    if (signal.aborted) throw new DOMException("Aborted", "AbortError");
  };
  validateTimelineView(view);
  ensureActive();
  onPhase?.("configuration");
  const configuration = await configurationClient.read(signal);
  ensureActive();
  if (configuration.state === "not_selected") return { status: "not_selected" };
  onPhase?.("activation");
  ensureActive();
  const activation = await loadChangeActivation(
    client,
    configuration.index,
    configuration.activation_id,
    signal,
  );
  ensureActive();
  onPhase?.("history");
  ensureActive();
  const result = await loadChangeTimeline(
    client,
    { activation, ...view },
    signal,
  );
  return { status: "loaded", result };
}

function selectionKey(view: ChangeTimelineInspectionProps["view"]): string {
  return JSON.stringify([view.scope, view.window.start, view.window.end]);
}

function statusText(state: InspectionValue): string {
  switch (state.status) {
    case "loading_configuration":
      return "Reading caller-visible shared history configuration…";
    case "loading_activation":
      return "Resolving the administrator-selected activation…";
    case "loading_history":
      return "Reading and validating the complete activated generation…";
    case "not_selected":
      return "Configuration history is not selected. No history data search was sent.";
    case "configuration_unavailable":
      return "Shared configuration is unavailable to this caller. No history data search was sent.";
    case "history_unavailable":
      return "The selected activation or its complete history is unavailable, denied or incomplete. No demo evidence was substituted.";
    case "cancelled":
      return "Configuration history inspection was cancelled. Optional search cleanup may still be pending.";
    default:
      return "The optional history source has not been queried.";
  }
}

export function ChangeTimelineInspection({
  client,
  view,
  context,
  configurationClient = changeTimelineConfigurationClient,
}: ChangeTimelineInspectionProps) {
  const key = selectionKey(view);
  const [state, setState] = useState<InspectionState>(() => ({
    key,
    value: { status: "idle" },
  }));
  const active = useRef<AbortController>();
  const activeToken = useRef<symbol>();
  const currentState =
    state.key === key ? state.value : { status: "idle" as const };
  const updateState = useCallback(
    (value: InspectionValue) => setState({ key, value }),
    [key],
  );

  const invalidate = useCallback(() => {
    activeToken.current = undefined;
    active.current?.abort();
    active.current = undefined;
  }, []);

  useEffect(() => {
    invalidate();
    updateState({ status: "idle" });
    const onPageHide = () => {
      if (!active.current) return;
      invalidate();
      updateState({ status: "cancelled" });
    };
    window.addEventListener("pagehide", onPageHide);
    return () => {
      invalidate();
      window.removeEventListener("pagehide", onPageHide);
    };
  }, [client, configurationClient, invalidate, key, updateState]);

  const busy = currentState.status.startsWith("loading_");
  const inspect = async () => {
    if (busy) return;
    try {
      validateTimelineView(view);
    } catch {
      updateState({ status: "history_unavailable" });
      return;
    }
    invalidate();
    const controller = new AbortController();
    const token = Symbol("configuration-history-inspection");
    active.current = controller;
    activeToken.current = token;
    updateState({ status: "loading_configuration" });
    let phase: "configuration" | "activation" | "history" = "configuration";
    try {
      const outcome = await runChangeTimelineInspection({
        client,
        view,
        configurationClient,
        signal: controller.signal,
        onPhase: (next) => {
          phase = next;
          updateState({
            status:
              next === "configuration"
                ? "loading_configuration"
                : next === "activation"
                  ? "loading_activation"
                  : "loading_history",
          });
        },
      });
      if (activeToken.current !== token || controller.signal.aborted) return;
      if (outcome.status === "not_selected") {
        updateState({ status: "not_selected" });
        return;
      }
      if (activeToken.current === token && !controller.signal.aborted)
        updateState({ status: "loaded", result: outcome.result });
    } catch (cause) {
      if (activeToken.current === token && !controller.signal.aborted) {
        updateState({
          status:
            phase === "configuration" ||
            (cause instanceof Error &&
              /shared configuration/i.test(cause.message))
              ? "configuration_unavailable"
              : "history_unavailable",
        });
      }
    } finally {
      if (activeToken.current === token && active.current === controller) {
        active.current = undefined;
        activeToken.current = undefined;
      }
    }
  };

  const cancel = () => {
    activeToken.current = undefined;
    active.current?.abort();
    active.current = undefined;
    updateState({ status: "cancelled" });
  };

  if (currentState.status === "loaded")
    return (
      <ChangeTimeline
        mode="result"
        result={currentState.result}
        view={view}
        context={context}
      />
    );

  return (
    <section
      className="change-timeline"
      aria-label="Optional configuration change timeline"
    >
      <h3>Configuration change timeline</h3>
      <p className="change-timeline__intro">
        Inspect caller-visible history using the administrator-selected index
        and activation. The complete activated generation is validated before
        scope and time filters are applied.
      </p>
      <div className="change-timeline__actions">
        <button type="button" onClick={() => void inspect()} disabled={busy}>
          {busy
            ? "Inspecting configuration history…"
            : "Inspect configuration history"}
        </button>
        {busy && (
          <button type="button" onClick={cancel}>
            Cancel history inspection
          </button>
        )}
        <span
          role={
            currentState.status === "history_unavailable" ||
            currentState.status === "configuration_unavailable"
              ? "alert"
              : "status"
          }
        >
          {statusText(currentState)}
        </span>
      </div>
    </section>
  );
}
