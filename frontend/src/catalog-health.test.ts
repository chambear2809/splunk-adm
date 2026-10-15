import { expect, it } from "vitest";
import { jobStatus } from "./health";
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
