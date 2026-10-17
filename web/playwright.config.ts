import { defineConfig, devices } from "@playwright/test";

// End-to-end test against a running coordinator; see e2e/enroll.spec.ts for
// the environment variables it needs (test/e2e/run.sh sets them up).
export default defineConfig({
  testDir: "e2e",
  timeout: 180_000,
  expect: { timeout: 30_000 },
  retries: 0,
  reporter: [["list"]],
  outputDir: "e2e-results",
  use: {
    baseURL: process.env.E2E_BASE_URL ?? "http://127.0.0.1:8080",
    trace: "retain-on-failure",
    screenshot: "only-on-failure",
    launchOptions: process.env.PW_CHROMIUM_PATH ? { executablePath: process.env.PW_CHROMIUM_PATH } : {},
  },
  projects: [{ name: "chromium", use: { ...devices["Desktop Chrome"] } }],
});
