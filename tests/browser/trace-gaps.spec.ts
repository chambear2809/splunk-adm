import { expect, test } from "@playwright/test";

test("a deep-linked trace badges the enforcing leaf per port and narrows the vPC", async ({
  page,
}) => {
  await page.goto("/tests/browser/trace-gaps.html?case=acl");
  const trace = page.getByRole("region", {
    name: "Trace 192.0.2.3 to 198.51.100.2",
  });
  await expect(trace).toContainText("k8s-vm-01 → app-vm-02");
  // Service ports only; client ports stay out of the summary.
  await expect(trace).toContainText("tcp/47001 +1");
  await expect(trace.locator("header")).not.toContainText("47110");
  await expect(trace).toContainText("Blocked tcp/47003 (ACI contract)");
  await expect(trace).toContainText("tcp/47001 not blocked");
  const hops = trace.getByRole("list", { name: "Hops" }).getByRole("button");
  await expect(hops).toHaveCount(7);
  const leaf = hops.nth(3);
  await expect(leaf).toHaveAccessibleName(
    "Leaf fab1-leaf102, blocked tcp/47003 by ACI contract",
  );
  await expect(leaf.locator(".atlas-hop-badge.blocked")).toHaveText(
    "Blocked tcp/47003",
  );
  await leaf.click();
  const detail = trace.getByRole("complementary", { name: "Hop fab1-leaf102" });
  await expect(detail).toContainText(
    "Drop logged (ACI contract) for tcp/47003",
  );
  await expect(detail).toContainText("Not seen");
  await expect(
    detail.getByRole("link", { name: "fab1-leaf101" }),
  ).toBeVisible();
  // Client ports appear only in the endpoint detail.
  await hops.first().click();
  const source = trace.getByRole("complementary", { name: "Hop k8s-vm-01" });
  await expect(source).toContainText("Client ports");
  await expect(source).toContainText("47110, 47111, 47112");
});

test("a pod trace shows the Kubernetes policy drop at the Cilium node", async ({
  page,
}) => {
  await page.goto("/tests/browser/trace-gaps.html?case=pod");
  const trace = page.getByRole("region", {
    name: "Trace 10.244.1.10 to 10.244.2.20",
  });
  await expect(trace).toContainText("web-1 → api-1");
  await expect(trace).toContainText("Blocked tcp/8080 (Kubernetes policy)");
  await expect(trace).not.toContainText("ACI contract");
  const hops = trace.getByRole("list", { name: "Hops" }).getByRole("button");
  // Nine hops collapse their middle; the blocked node stays visible.
  await expect(
    hops.filter({ hasText: "Blocked tcp/8080" }).first(),
  ).toBeVisible();
  await hops.filter({ hasText: /^\+\d+ hops$/ }).click();
  await expect(hops).toHaveCount(9);
  const node = hops.nth(7);
  await expect(node).toHaveAccessibleName(
    "Host k8s-node-2, blocked tcp/8080 by Kubernetes policy",
  );
  await node.click();
  const detail = trace.getByRole("complementary", { name: "Hop k8s-node-2" });
  await expect(detail).toContainText("Drop logged (Kubernetes policy)");
  await expect(detail).toContainText("POLICY_DENIED");
  await expect(detail).toContainText("Hubble");
});
