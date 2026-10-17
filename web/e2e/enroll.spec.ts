import { execSync, spawn, type ChildProcess } from "node:child_process";

import { expect, test } from "@playwright/test";

// Phase 3 exit criterion: a fresh coordinator is set up and a device is
// enrolled using nothing but the web UI.
//
// Environment:
//   E2E_BASE_URL     URL of the coordinator UI (playwright baseURL)
//   E2E_SETUP_CODE   the setup code the coordinator was started with
//   E2E_PUBLIC_URL   coordinator URL as the agent must use it
//   E2E_AGENT_CMD    shell command starting an agent; $AUTHKEY and
//                    $COORDINATOR are exported to it
//   E2E_AGENT_STOP   optional shell command run at the end to stop it
//   E2E_SCREENSHOTS  optional directory for page screenshots

const env = (k: string) => {
  const v = process.env[k];
  if (!v) throw new Error(`${k} must be set`);
  return v;
};

const password = "e2e password 1234";
let agent: ChildProcess | undefined;

test.afterAll(() => {
  agent?.kill("SIGTERM");
  if (process.env.E2E_AGENT_STOP) execSync(process.env.E2E_AGENT_STOP, { stdio: "inherit" });
});

async function shot(page: import("@playwright/test").Page, name: string) {
  const dir = process.env.E2E_SCREENSHOTS;
  if (dir) await page.screenshot({ path: `${dir}/${name}.png`, fullPage: true });
}

test("set up the coordinator and enroll a device from the UI", async ({ page }) => {
  // A fresh coordinator sends every page to the setup wizard.
  await page.goto("/nodes");
  await expect(page).toHaveURL(/\/setup$/);
  await expect(page.getByText("Welcome to Transporter")).toBeVisible();
  await shot(page, "1-setup");

  await page.getByLabel("Setup code").fill("WRONG-CODE");
  await page.getByRole("button", { name: /next/i }).click();
  await page.getByLabel("Username").fill("admin");
  await page.getByLabel("Password", { exact: true }).fill(password);
  await page.getByLabel("Confirm password").fill(password);
  await page.getByRole("button", { name: /next/i }).click();
  await page.getByLabel("Coordinator URL").fill(env("E2E_PUBLIC_URL"));
  await page.getByRole("button", { name: /finish setup/i }).click();
  await expect(page.getByRole("alert")).toContainText("wrong setup code");

  // Go back to the first step and enter the real code.
  await page.getByRole("button", { name: /back/i }).click();
  await page.getByRole("button", { name: /back/i }).click();
  await page.getByLabel("Setup code").fill(env("E2E_SETUP_CODE"));
  for (let i = 0; i < 2; i++) await page.getByRole("button", { name: /next/i }).click();
  await page.getByRole("button", { name: /finish setup/i }).click();

  // Setup lands on the enrollment page.
  await expect(page.getByRole("heading", { name: "Enroll device" })).toBeVisible();
  await page.getByLabel("Description").fill("e2e device");
  await page.getByRole("button", { name: "1 hour" }).click();
  await page.getByRole("button", { name: "Create key" }).click();
  const secret = (await page.getByTestId("authkey-secret").textContent())?.trim() ?? "";
  expect(secret).toMatch(/^trk_/);
  await expect(page.getByText(`--authkey ${secret}`)).toBeVisible();
  await shot(page, "2-enroll");

  // Run the agent with the key from the page.
  agent = spawn("sh", ["-c", env("E2E_AGENT_CMD")], {
    stdio: "inherit",
    env: { ...process.env, AUTHKEY: secret, COORDINATOR: env("E2E_PUBLIC_URL") },
  });

  // The page notices the enrollment by itself (live updates).
  await expect(page.getByTestId("enrolled-count")).toContainText("1 device enrolled", { timeout: 90_000 });

  await page.getByRole("link", { name: "View nodes" }).click();
  const row = page.getByRole("row").filter({ hasText: "online" });
  await expect(row).toHaveCount(1);
  await shot(page, "3-nodes");

  // Rename it from the node dialog.
  await row.getByRole("button").first().click();
  await page.getByLabel("Name").fill("e2e-renamed");
  await page.getByRole("button", { name: "Rename" }).click();
  await expect(page.getByRole("dialog").getByRole("heading")).toContainText("e2e-renamed");
  await shot(page, "4-node-dialog");
  await page.keyboard.press("Escape");

  // Dashboard reflects the node.
  await page.getByRole("link", { name: "Dashboard" }).click();
  await expect(page.getByTestId("stat-online")).toHaveText("1");
  await shot(page, "5-dashboard");

  await page.getByRole("link", { name: "Settings" }).click();
  await expect(page.getByLabel("Public URL")).toHaveValue(env("E2E_PUBLIC_URL").replace(/\/$/, ""));
  await shot(page, "6-settings");

  // Sign out and back in.
  await page.getByRole("button", { name: /sign out/i }).first().click();
  await expect(page).toHaveURL(/\/login/);
  await page.getByLabel("Username").fill("admin");
  await page.getByLabel("Password").fill(password);
  await page.getByRole("button", { name: "Sign in" }).click();
  await expect(page.getByRole("heading", { name: "Dashboard" })).toBeVisible();
});
