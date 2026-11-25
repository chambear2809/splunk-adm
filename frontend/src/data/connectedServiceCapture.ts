import type { GraphArgs } from "../rows";
import type { CompleteDemoCaptureResult } from "./demoCapture";

export const CONNECTED_SERVICE_RESULT_KEYS = [
  "graph.baseline",
  "graph.change",
  "graph.impact",
  "graph.recovery",
  "topology.baseline",
  "topology.impact",
  "topology.recovery",
  "catalog.selected",
  "find.service",
] as const;

export type ConnectedServiceResultKey =
  (typeof CONNECTED_SERVICE_RESULT_KEYS)[number];

export interface ConnectedServiceInvestigation {
  application: GraphArgs;
  results: Record<ConnectedServiceResultKey, CompleteDemoCaptureResult>;
}

export interface ConnectedServiceCapture {
  status: "complete";
  investigations: [
    ConnectedServiceInvestigation,
    ConnectedServiceInvestigation,
  ];
}

export interface ConnectedServiceCaptureValidationContext {
  declaredScopes: readonly GraphArgs[];
  primaryApplication: GraphArgs;
  validateApplication: (raw: unknown, label: string) => GraphArgs;
  validateResult: (
    key: ConnectedServiceResultKey,
    raw: unknown,
    application: GraphArgs,
    queryNamespace: string,
  ) => Promise<CompleteDemoCaptureResult>;
}

const isObject = (value: unknown): value is Record<string, unknown> =>
  !!value && typeof value === "object" && !Array.isArray(value);

function exactKeys(
  value: Record<string, unknown>,
  expected: readonly string[],
  label: string,
): void {
  const actual = Object.keys(value).sort();
  const wanted = [...expected].sort();
  if (
    actual.length !== wanted.length ||
    actual.some((key, i) => key !== wanted[i])
  )
    throw new Error(
      `Connected service ${label} has unsupported or missing fields.`,
    );
}

function graphArgs(value: unknown, label: string): GraphArgs {
  if (!isObject(value))
    throw new Error(`Connected service ${label} is invalid.`);
  exactKeys(value, ["service", "environment", "cluster", "namespace"], label);
  for (const key of [
    "service",
    "environment",
    "cluster",
    "namespace",
  ] as const) {
    if (typeof value[key] !== "string" || value[key].length === 0)
      throw new Error(`Connected service ${label}.${key} is invalid.`);
  }
  return {
    service: value.service as string,
    environment: value.environment as string,
    cluster: value.cluster as string,
    namespace: value.namespace as string,
  };
}

function sameArgs(left: GraphArgs, right: GraphArgs): boolean {
  return (
    left.service === right.service &&
    left.environment === right.environment &&
    left.cluster === right.cluster &&
    left.namespace === right.namespace
  );
}

function validateDeclaredScopes(
  context: ConnectedServiceCaptureValidationContext,
): [GraphArgs, GraphArgs] {
  if (context.declaredScopes.length !== 2)
    throw new Error(
      "Connected service scopes must contain exactly two applications.",
    );
  const primary = graphArgs(context.primaryApplication, "primary application");
  const scopes = context.declaredScopes.map((scope, index) =>
    graphArgs(scope, `declared scope ${index}`),
  );
  if (sameArgs(scopes[0], scopes[1]))
    throw new Error("Connected service scopes must be distinct.");
  if (scopes.some((scope) => sameArgs(scope, primary)))
    throw new Error(
      "Connected service scope duplicates the primary application.",
    );
  if (scopes[0].service !== "inventory" || scopes[1].service !== "pricing")
    throw new Error(
      "Connected service scopes must be ordered inventory then pricing.",
    );
  if (
    scopes.some(
      (scope) =>
        scope.environment !== primary.environment ||
        scope.cluster !== primary.cluster ||
        scope.namespace !== primary.namespace,
    )
  )
    throw new Error(
      "Connected service scopes must share the primary environment, cluster, and namespace.",
    );
  return scopes as [GraphArgs, GraphArgs];
}

function requireQualifiedRows(
  result: CompleteDemoCaptureResult,
  application: GraphArgs,
  label: string,
): void {
  if (!Array.isArray(result.rows) || result.rows.length === 0)
    throw new Error(`Connected service ${label} must contain actual rows.`);
  for (const [index, row] of result.rows.entries()) {
    if (!isObject(row))
      throw new Error(`Connected service ${label} row ${index} is invalid.`);
    for (const key of [
      "service",
      "environment",
      "cluster",
      "namespace",
    ] as const) {
      if (row[key] !== application[key])
        throw new Error(
          `Connected service ${label} row ${index} has a foreign scope.`,
        );
    }
  }
}

export async function validateConnectedServiceCapture(
  raw: unknown,
  context: ConnectedServiceCaptureValidationContext,
): Promise<ConnectedServiceCapture> {
  if (!isObject(raw)) throw new Error("Connected service capture is invalid.");
  exactKeys(raw, ["status", "investigations"], "capture");
  if (raw.status !== "complete" || !Array.isArray(raw.investigations))
    throw new Error("Connected service capture is incomplete.");
  const scopes = validateDeclaredScopes(context);
  if (raw.investigations.length !== scopes.length)
    throw new Error(
      "Connected service capture has an unexpected investigation count.",
    );

  const investigations = [] as ConnectedServiceInvestigation[];
  for (const [index, expected] of scopes.entries()) {
    const candidate = raw.investigations[index];
    if (!isObject(candidate))
      throw new Error(`Connected service investigation ${index} is invalid.`);
    exactKeys(candidate, ["application", "results"], `investigation ${index}`);
    const application = context.validateApplication(
      candidate.application,
      `connected investigation ${index} application`,
    );
    const validatedApplication = graphArgs(
      application,
      `connected investigation ${index} application`,
    );
    if (!sameArgs(validatedApplication, expected))
      throw new Error(
        `Connected service investigation ${index} has an undeclared scope.`,
      );
    if (!isObject(candidate.results))
      throw new Error(
        `Connected service investigation ${index} results are invalid.`,
      );
    exactKeys(
      candidate.results,
      CONNECTED_SERVICE_RESULT_KEYS,
      `investigation ${index} results`,
    );

    const results = {} as Record<
      ConnectedServiceResultKey,
      CompleteDemoCaptureResult
    >;
    for (const key of CONNECTED_SERVICE_RESULT_KEYS) {
      const result = await context.validateResult(
        key,
        candidate.results[key],
        validatedApplication,
        `connected.${validatedApplication.service}`,
      );
      if (!isObject(result) || result.status !== "complete")
        throw new Error(`Connected service ${key} is not complete.`);
      if (key === "find.service") {
        if (result.args !== undefined || !isObject(result.input))
          throw new Error("Connected service Find result has invalid input.");
        exactKeys(result.input, ["field", "value"], "connected Find input");
        if (
          result.input.field !== "service" ||
          result.input.value !== validatedApplication.service
        )
          throw new Error(
            "Connected service Find input is not service-scoped.",
          );
      } else if (
        !result.args ||
        !sameArgs(graphArgs(result.args, `${key} args`), validatedApplication)
      )
        throw new Error(
          `Connected service ${key} has mismatched application args.`,
        );
      if (key === "catalog.selected" || key === "find.service")
        requireQualifiedRows(result, validatedApplication, key);
      results[key] = result;
    }
    investigations.push({ application: validatedApplication, results });
  }
  return {
    status: "complete",
    investigations: investigations as [
      ConnectedServiceInvestigation,
      ConnectedServiceInvestigation,
    ],
  };
}

export function connectedServiceInvestigationFor(
  validated: ConnectedServiceCapture,
  application: GraphArgs,
): ConnectedServiceInvestigation {
  const requested = graphArgs(application, "requested application");
  const investigation = validated.investigations.find((item) =>
    sameArgs(item.application, requested),
  );
  if (!investigation)
    throw new Error(
      "Connected service application is not present in the capture.",
    );
  return investigation;
}
