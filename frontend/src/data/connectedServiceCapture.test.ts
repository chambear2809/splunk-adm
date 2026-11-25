import { describe, expect, it, vi } from "vitest";
import {
  CONNECTED_SERVICE_RESULT_KEYS,
  connectedServiceInvestigationFor,
  validateConnectedServiceCapture,
  type ConnectedServiceCaptureValidationContext,
} from "./connectedServiceCapture";
import type { CompleteDemoCaptureResult } from "./demoCapture";
import type { GraphArgs } from "../rows";

const primary: GraphArgs = {
  service: "checkout",
  environment: "prod",
  cluster: "cluster-a",
  namespace: "shop",
};
const scopes: GraphArgs[] = [
  { ...primary, service: "inventory" },
  { ...primary, service: "pricing" },
];

function result(
  application: GraphArgs,
  rows: Record<string, unknown>[] = [],
  find = false,
) {
  return {
    status: "complete" as const,
    ...(find
      ? { input: { field: "service", value: application.service } }
      : { args: application }),
    window: { earliest: 1, latest: 2, basis: "source_time" as const },
    query: { literal: "| makeresults", sha256: "a".repeat(64) },
    readback: {
      complete: true,
      result_count: rows.length,
      index_time_bounds: { earliest: 1, latest: 2 },
      receipt_fingerprints: [],
      source: "splunk_rest" as const,
      execution_id: "execution",
      plan_sha256: "b".repeat(64),
    },
    rows,
  } satisfies CompleteDemoCaptureResult;
}

function fixture(
  overrides: Partial<ConnectedServiceCaptureValidationContext> = {},
) {
  const validateResult = vi.fn(async (key, _raw, application) =>
    result(
      application,
      key === "catalog.selected" || key === "find.service"
        ? [{ ...application }]
        : [],
      key === "find.service",
    ),
  );
  return {
    declaredScopes: scopes,
    primaryApplication: primary,
    validateApplication: (raw: unknown) => raw as GraphArgs,
    validateResult,
    ...overrides,
  } satisfies ConnectedServiceCaptureValidationContext;
}

function rawCapture() {
  return {
    status: "complete",
    investigations: scopes.map((application) => ({
      application,
      results: Object.fromEntries(
        CONNECTED_SERVICE_RESULT_KEYS.map((key) => [key, {}]),
      ),
    })),
  };
}

describe("connected service capture validation", () => {
  it("routes each exact child key through the callback and preserves values", async () => {
    const context = fixture();
    const capture = await validateConnectedServiceCapture(
      rawCapture(),
      context,
    );
    expect(context.validateResult).toHaveBeenCalledTimes(18);
    expect(
      (context.validateResult as ReturnType<typeof vi.fn>).mock.calls,
    ).toEqual(
      scopes.flatMap((application) =>
        CONNECTED_SERVICE_RESULT_KEYS.map((key) => [
          key,
          expect.anything(),
          application,
          `connected.${application.service}`,
        ]),
      ),
    );
    expect(
      capture.investigations.map(({ application }) => application.service),
    ).toEqual(["inventory", "pricing"]);
    expect(
      capture.investigations[0].results["graph.baseline"].query.literal,
    ).toBe("| makeresults");
  });

  it("rejects missing/extra keys, duplicate or primary scopes, and callback failures", async () => {
    const missing = rawCapture();
    delete missing.investigations[0].results["graph.change"];
    await expect(
      validateConnectedServiceCapture(missing, fixture()),
    ).rejects.toThrow();

    await expect(
      validateConnectedServiceCapture(
        rawCapture(),
        fixture({ declaredScopes: [scopes[0], scopes[0]] }),
      ),
    ).rejects.toThrow(/distinct/);

    for (const altered of [
      [{ ...scopes[0], cluster: "cluster-b" }, scopes[1]],
      [{ ...scopes[0], environment: "stage" }, scopes[1]],
      [{ ...scopes[0], namespace: "other" }, scopes[1]],
      [scopes[1], scopes[0]],
      [primary, scopes[1]],
    ]) {
      await expect(
        validateConnectedServiceCapture(
          rawCapture(),
          fixture({ declaredScopes: altered }),
        ),
      ).rejects.toThrow();
    }

    const callbackError = new Error("caller boundary");
    await expect(
      validateConnectedServiceCapture(
        rawCapture(),
        fixture({ validateResult: vi.fn().mockRejectedValue(callbackError) }),
      ),
    ).rejects.toBe(callbackError);
  });

  it("requires qualified rows and refuses unknown lookup without fallback", async () => {
    const badRows = fixture({
      validateResult: vi.fn(async (key, _raw, application) =>
        result(
          application,
          key === "catalog.selected"
            ? [{ ...primary }]
            : key === "find.service"
              ? [{ ...application }]
              : [],
        ),
      ),
    });
    await expect(
      validateConnectedServiceCapture(rawCapture(), badRows),
    ).rejects.toThrow(/foreign scope/);
    await expect(
      validateConnectedServiceCapture(
        rawCapture(),
        fixture({
          validateResult: vi.fn(async (key, _raw, application) =>
            key === "graph.baseline"
              ? ({ ...result(application), status: "partial" } as never)
              : result(
                  application,
                  key === "catalog.selected" || key === "find.service"
                    ? [{ ...application }]
                    : [],
                  key === "find.service",
                ),
          ),
        }),
      ),
    ).rejects.toThrow(/not complete/);
    await expect(
      validateConnectedServiceCapture(
        rawCapture(),
        fixture({
          validateResult: vi.fn(async (key, _raw, application) =>
            result(
              key === "graph.baseline"
                ? { ...application, service: "wrong" }
                : application,
              key === "catalog.selected" || key === "find.service"
                ? [{ ...application }]
                : [],
              key === "find.service",
            ),
          ),
        }),
      ),
    ).rejects.toThrow(/mismatched application args/);
    const capture = await validateConnectedServiceCapture(
      rawCapture(),
      fixture(),
    );
    expect(() => connectedServiceInvestigationFor(capture, primary)).toThrow();
    expect(() =>
      connectedServiceInvestigationFor(capture, {
        ...scopes[0],
        service: "unknown",
      }),
    ).toThrow();
  });
});
