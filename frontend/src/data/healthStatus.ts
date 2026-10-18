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
  jobAssessment,
  loadHealth,
  sourceAssessment,
  type HealthReport,
} from "../health";
import type { SearchClient } from "./searchClient";
import {
  applicableJobs,
  expectationFor,
  selectedQualitySources,
  type DeploymentSnapshot,
} from "./deploymentHealth";
import type { DeploymentClient } from "./deploymentHealth";

export type HealthIndicator =
  "unknown" | "loading" | "error" | "healthy" | "attention";

export interface HealthState {
  report?: HealthReport;
  deployment?: DeploymentSnapshot;
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
  scope = "full",
  deploymentClient,
  children,
}: {
  client?: SearchClient;
  live: boolean;
  scope?: "full" | "jobs";
  deploymentClient?: DeploymentClient;
  children: ReactNode;
}) {
  const [deployment, setDeployment] = useState<DeploymentSnapshot>();
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
      setDeployment(undefined);
      setError(undefined);
      setBusy(false);
      return;
    }
    const controller = new AbortController();
    active.current = controller;
    setBusy(true);
    setError(undefined);
    setReport(undefined);
    const load = async () => {
      const settings: DeploymentSnapshot = deploymentClient
        ? await deploymentClient.read(controller.signal).catch(() => ({
            state: "unavailable" as const,
            canWrite: false,
            error: "Deployment settings could not be read.",
          }))
        : {
            state: "unavailable",
            canWrite: false,
            error: "Deployment settings are unavailable.",
          };
      if (controller.signal.aborted) return undefined;
      setDeployment(settings);
      return loadHealth(client, controller.signal, settings, scope);
    };
    load()
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
  }, [client, live, revision, visible, deploymentClient, scope]);
  useEffect(() => {
    if (!shouldPollHealth(live, visible) || !client || scope === "jobs") return;
    const timer = setInterval(
      () => setRevision((current) => current + 1),
      5 * 60 * 1000,
    );
    return () => clearInterval(timer);
  }, [client, live, visible, scope]);
  const value = useMemo<HealthState>(
    () => ({
      report,
      deployment,
      error,
      busy,
      refresh: () => setRevision((current) => current + 1),
    }),
    [busy, error, report, deployment],
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
  if (
    report.deployment?.state !== "configured" ||
    !report.deployment.activeContract
  )
    return "unknown";
  if (
    report.jobs.some(
      (job) =>
        jobAssessment(job, report.checkedAt).reason === "contract_conflict",
    )
  )
    return "attention";
  if (report.scope === "jobs") return "unknown";
  const sources = report.sources.filter(
    (source) =>
      source.id !== undefined &&
      expectationFor(report.deployment, source.id) === "active",
  );
  if (!sources.length) return "unknown";
  const qualityRequired =
    report.qualityRequired ??
    selectedQualitySources(report.deployment).length > 0;
  if (qualityRequired && report.quality.issues.length) return "attention";
  const sourceStates = sources.map(
    (source) => sourceAssessment(source, report.checkedAt).state,
  );
  if (sourceStates.includes("attention")) return "attention";
  const requiredJobs = applicableJobs(report.deployment).filter(
    (job) => job.required,
  );
  const jobs = requiredJobs.map((definition) =>
    report.jobs.find((job) => job.name === definition.name),
  );
  if (jobs.some((job) => !job)) return "unknown";
  const jobStates = jobs.map(
    (job) => jobAssessment(job!, report.checkedAt).state,
  );
  if (jobStates.includes("attention")) return "attention";
  if (
    sourceStates.some((state) => state !== "healthy") ||
    jobStates.some((state) => state !== "healthy")
  )
    return "unknown";
  if (
    qualityRequired &&
    (!report.quality.evaluated ||
      report.quality.incomplete ||
      report.quality.excluded === undefined)
  )
    return "unknown";
  if (report.warnings.length) return "attention";
  return "healthy";
}
