import { expect, it } from "vitest";
import { revalidatesOwner } from "./ownership";
import type { IdentityRecord } from "./dnsAdapters";
const owner = (
  entity_id: string,
  valid_from: number,
  valid_end: number,
): IdentityRecord => ({
  ip: "10.0.0.1",
  scope: "prod",
  entity_kind: "pod",
  entity_id,
  valid_from,
  valid_end,
});
it("rejects partial-overlap target reuse even when the selected owner covers the full flow", () => {
  const covering = owner("selected", 0, 1000);
  expect(
    revalidatesOwner([covering], "10.0.0.1", "prod", "selected", 100, 200, 0),
  ).toBe(true);
  expect(
    revalidatesOwner(
      [covering, owner("reused", 110, 120)],
      "10.0.0.1",
      "prod",
      "selected",
      100,
      200,
      0,
    ),
  ).toBe(false);
  expect(
    revalidatesOwner(
      [covering, owner("reused", 205, 210)],
      "10.0.0.1",
      "prod",
      "selected",
      100,
      200,
      10,
    ),
  ).toBe(false);
  expect(
    revalidatesOwner(
      [covering],
      "10.0.0.1",
      "prod",
      "selected",
      100,
      200,
      undefined,
    ),
  ).toBe(false);
});
