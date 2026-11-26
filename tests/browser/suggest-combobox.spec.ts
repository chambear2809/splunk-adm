import { expect, test } from "@playwright/test";

test("trace endpoints offer page suggestions by keyboard and keep free text", async ({
  page,
}) => {
  await page.goto("/tests/browser/browser.html?page=map&mode=demo");
  const form = page.getByRole("form", { name: "Trace path" });
  const source = form.getByRole("combobox", { name: "Trace source" });
  await source.fill("orders");
  await expect(source).toHaveAttribute("aria-expanded", "true");
  const listbox = form.getByRole("listbox", { name: "Suggestions" }).first();
  const option = listbox.getByRole("option", { name: /orders-db-01/ });
  await expect(option).toBeVisible();
  await source.press("ArrowDown");
  const active = await source.getAttribute("aria-activedescendant");
  expect(active).toBeTruthy();
  await expect(page.locator(`[id="${active}"]`)).toHaveAttribute(
    "aria-selected",
    "true",
  );
  await source.press("Enter");
  await expect(source).toHaveValue(/orders/);
  await expect(source).toHaveAttribute("aria-expanded", "false");
  await expect(page).not.toHaveURL(/trace_src=/);

  await source.fill("orders");
  await source.press("Escape");
  await expect(source).toHaveAttribute("aria-expanded", "false");
  await source.fill("10.0.0.250");
  const destination = form.getByRole("combobox", {
    name: "Trace destination",
  });
  await destination.fill("orders-db-01");
  await destination.press("Enter");
  await expect(page).toHaveURL(/trace_src=10.0.0.250&trace_dst=orders-db-01/);
});
