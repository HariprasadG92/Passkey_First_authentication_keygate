import { defineConfig, devices } from "@playwright/test";

/**
 * End-to-end tests against the full docker compose stack (gateway, web, api, postgres,
 * redis, mailpit). Start it first with `make up`; run with `make test-e2e`.
 */
export default defineConfig({
  testDir: "./e2e/stack",
  globalSetup: "./e2e/stack/global-setup.ts",
  fullyParallel: false,
  workers: 1,
  forbidOnly: !!process.env.CI,
  retries: process.env.CI ? 1 : 0,
  reporter: process.env.CI ? [["github"], ["html", { open: "never" }]] : "list",
  timeout: 60_000,
  use: {
    baseURL: process.env.KEYGATE_E2E_URL ?? "http://localhost",
    trace: "retain-on-failure",
  },
  projects: [{ name: "chromium", use: { ...devices["Desktop Chrome"] } }],
});
