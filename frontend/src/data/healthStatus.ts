import {
  createContext,
  createElement,
  useContext,
  useEffect,
  useMemo,
  useRef,
  useState,
  type ReactNode,
} from "react";
import {
  jobStatus,
  loadHealth,
  sourceStatus,
  type HealthReport,
} from "../health";
import type { SearchClient } from "./searchClient";

export type HealthIndicator =
  "unknown" | "loading" | "error" | "healthy" | "attention";

export interface HealthState {
  report?: HealthReport;
  error?: string;
  busy: boolean;
  refresh: () => void;
}
const HealthContext = createContext<HealthState | undefined>(undefined);
export const shouldPollHealth = (live: boolean, visible: boolean) =>
  live && visible;

export function HealthProvider({
  client,
  live,
  children,
}: {
  client?: SearchClient;
  live: boolean;
  children: ReactNode;
}) {
  const [report, setReport] = useState<HealthReport>();
  const [error, setError] = useState<string>();
  const [busy, setBusy] = useState(false);
  const [revision, setRevision] = useState(0);
  const [visible, setVisible] = useState(
    () =>
      typeof document === "undefined" || document.visibilityState !== "hidden",
  );
  const active = useRef<AbortController>();
  useEffect(() => {
    if (typeof document === "undefined") return;
    const changed = () => {
      const nextVisible = document.visibilityState !== "hidden";
      if (!nextVisible) active.current?.abort();
      setVisible(nextVisible);
    };
    document.addEventListener("visibilitychange", changed);
    return () => document.removeEventListener("visibilitychange", changed);
  }, []);
  useEffect(() => {
    if (!shouldPollHealth(live, visible) || !client) {
      active.current?.abort();
      setReport(undefined);
      setError(undefined);
      setBusy(false);
      return;
    }
    const controller = new AbortController();
    active.current = controller;
    setBusy(true);
    setError(undefined);
    setReport(undefined);
    loadHealth(client, controller.signal)
      .then((result) => {
        if (!controller.signal.aborted) setReport(result);
      })
      .catch((reason: unknown) => {
        if (!controller.signal.aborted)
          setError(
            reason instanceof Error ? reason.message : "Health check failed.",
          );
      })
      .finally(() => {
        if (!controller.signal.aborted) setBusy(false);
      });
    return () => {
      controller.abort();
      if (active.current === controller) active.current = undefined;
    };
  }, [client, live, revision, visible]);
  useEffect(() => {
    if (!shouldPollHealth(live, visible) || !client) return;
    const timer = setInterval(
      () => setRevision((current) => current + 1),
      5 * 60 * 1000,
    );
    return () => clearInterval(timer);
  }, [client, live, visible]);
  const value = useMemo<HealthState>(
    () => ({
      report,
      error,
      busy,
      refresh: () => setRevision((current) => current + 1),
    }),
    [busy, error, report],
  );
  return createElement(HealthContext.Provider, { value }, children);
}
export const useHealthStatus = () => useContext(HealthContext);

export function healthIndicator(
  report: HealthReport | undefined,
  loading: boolean,
  error: string | undefined,
  live: boolean,
): HealthIndicator {
  if (!live) return "unknown";
  if (loading) return "loading";
  if (error) return "error";
  if (!report) return "unknown";
  if (!report.sources.some((source) => source.records !== undefined))
    return "unknown";
  if (
    report.warnings.length ||
    report.quality.issues.length ||
    !report.quality.evaluated
  )
    return "attention";

  if (
    report.sources.some(
      (source) =>
        sourceStatus(source, report.checkedAt) !==
        "Data received within 20 minutes",
    )
  )
    return "attention";
  const builders = report.jobs.filter(
    (job) => !job.name.toLowerCase().includes("prune"),
  );
  if (!builders.length) return "unknown";
  if (
    builders.some(
      (job) => jobStatus(job, report.checkedAt) !== "Recent successful run",
    )
  )
    return "attention";
  return "healthy";
}
