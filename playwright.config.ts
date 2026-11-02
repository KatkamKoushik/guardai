import { defineConfig, devices } from "@playwright/test";

export default defineConfig({
  testDir: "./e2e",
  fullyParallel: true,
  forbidOnly: !!process.env.CI,
  retries: process.env.CI ? 2 : 0,
  workers: process.env.CI ? 1 : 2,
  reporter: "list",
  use: {
    baseURL: process.env.PLAYWRIGHT_TEST_BASE_URL || "http://localhost:3000",
    trace: "on-first-retry",
    screenshot: "only-on-failure",
  },
  projects: [
    {
      name: "chromium",
      use: { ...devices["Desktop Chrome"] },
    },
  ],
  webServer: {
    command: "npm run start",
    url: "http://localhost:3000/api/health",
    reuseExistingServer: !process.env.CI,
    timeout: 60 * 1000,
    env: {
      DATABASE_URL: process.env.DATABASE_URL || "postgresql://guardai_user:guardai_pass@localhost:5432/guardai_ci",
      NEXTAUTH_URL: "http://localhost:3000",
      NEXTAUTH_SECRET: process.env.NEXTAUTH_SECRET || "local-test-secret-at-least-32-chars-long",
    },
  },
});
