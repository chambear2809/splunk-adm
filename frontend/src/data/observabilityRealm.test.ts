import { describe, expect, it } from "vitest";
import {
  isObservabilityRealm,
  observabilityRealmOrigin,
} from "./observabilityRealm";

describe("Observability realm validator", () => {
  it.each(["us0", "us1", "eu0", "au0", "jp0", "a", "us012345"])(
    "accepts documented realm %s",
    (realm) => {
      expect(isObservabilityRealm(realm)).toBe(true);
      expect(observabilityRealmOrigin(realm)).toBe(
        `https://app.${realm}.observability.splunkcloud.com`,
      );
    },
  );

  it.each([
    "",
    "US0",
    "us-0",
    "us0-east",
    "../map",
    "us0123456",
    "us0.example",
  ])("rejects invalid realm %s at configuration time", (realm) => {
    expect(isObservabilityRealm(realm)).toBe(false);
    expect(observabilityRealmOrigin(realm)).toBeUndefined();
  });
});
