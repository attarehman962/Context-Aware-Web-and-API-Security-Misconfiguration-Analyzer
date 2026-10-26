import { expect, test } from "@playwright/test";

test("home page shows the product name", async ({ page }) => {
  await page.goto("/");
  await expect(page).toHaveTitle("CAWASMA");
  await expect(
    page.getByRole("heading", { level: 1, name: "CAWASMA" }),
  ).toBeVisible();
  await expect(page.getByRole("button", { name: "API docs" })).toHaveAttribute(
    "href",
    /\/docs$/,
  );
});

test("app shell has the nav and shows the API mode", async ({ page }) => {
  await page.goto("/");
  const nav = page.getByRole("navigation", { name: "Main" });
  await expect(nav.getByRole("link", { name: "New scan" })).toHaveAttribute(
    "aria-current",
    "page",
  );
  await nav.getByRole("link", { name: "History" }).click();
  await expect(
    page.getByRole("heading", { level: 1, name: "Scan history" }),
  ).toBeVisible();
  await expect(page.getByRole("contentinfo")).toContainText(/API: (live|mock)/);
});
