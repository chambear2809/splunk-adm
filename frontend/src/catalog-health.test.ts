import { expect, it } from "vitest";
import { jobStatus } from "./health";
import { catalogFreshnessWarning } from "./data/catalog";
it("keeps a successful hourly catalog run current between hourly refreshes", () => {
  const now = 1791374400;
  expect(
    jobStatus(
      {
        name: "ADM - Application catalog",
        disabled: false,
        lastStatus: "success",
        lastRun: now - 2400,
        lastSuccess: now - 2400,
      },
      now,
    ),
  ).toBe("Recent successful run");
  expect(
    jobStatus(
      {
        name: "ADM - Application catalog",
        disabled: false,
        lastStatus: "success",
        lastRun: now - 7201,
        lastSuccess: now - 7201,
      },
      now,
    ),
  ).toBe("Successful run is overdue");
});

it("warns when a retained catalog snapshot exceeds the hourly grace window", () => {
  const now = 1_791_374_400;
  expect(catalogFreshnessWarning([{ updated: now - 7_201 }], now)).toMatch(
    /Catalog snapshot is stale/,
  );
  expect(
    catalogFreshnessWarning([{ updated: now - 3_600 }], now),
  ).toBeUndefined();
  expect(
    catalogFreshnessWarning(
      [{ updated: now - 3_600 }, { updated: now - 4_601 }],
      now,
    ),
  ).toMatch(/Catalog snapshot is stale/);
});

it("does not claim freshness when catalog rows lack writer timestamps", () => {
  expect(catalogFreshnessWarning([{}], 1_791_374_400)).toMatch(
    /freshness is unknown/,
  );
});
