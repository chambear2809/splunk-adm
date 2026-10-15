import {
  createContext,
  createElement,
  useContext,
  useEffect,
  useMemo,
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
  useEffect(() => {
    if (!live || !client) {
      setReport(undefined);
      setError(undefined);
      setBusy(false);
      return;
    }
    const controller = new AbortController();
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
    return () => controller.abort();
  }, [client, live, revision]);
  useEffect(() => {
    if (!live || !client) return;
    const timer = setInterval(
      () => setRevision((current) => current + 1),
      5 * 60 * 1000,
    );
    return () => clearInterval(timer);
  }, [client, live]);
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
