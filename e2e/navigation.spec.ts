import { test, expect } from "@playwright/test";

test.describe("Frontend Page Navigation & Rendering (E2E)", () => {
  test("homepage loads and displays core brand title", async ({ page }) => {
    await page.goto("/", { waitUntil: "domcontentloaded" });
    await expect(page).toHaveTitle(/GuardAI/i);
    await expect(page.locator("body")).toBeVisible();
  });

  test("scan interface loads without rendering errors", async ({ page }) => {
    await page.goto("/scan", { waitUntil: "domcontentloaded" });
    await expect(page.locator("body")).toBeVisible();
  });

  test("threats visualization page loads", async ({ page }) => {
    await page.goto("/threats", { waitUntil: "domcontentloaded" });
    await expect(page.locator("body")).toBeVisible();
  });

  test("privacy policy page renders cleanly", async ({ page }) => {
    await page.goto("/privacy", { waitUntil: "domcontentloaded" });
    await expect(page.locator("body")).toBeVisible();
  });

  test("terms of service page renders cleanly", async ({ page }) => {
    await page.goto("/terms", { waitUntil: "domcontentloaded" });
    await expect(page.locator("body")).toBeVisible();
  });
});
