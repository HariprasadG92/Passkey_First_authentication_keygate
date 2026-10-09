import { execFileSync } from "node:child_process";
import { expect, test, uniqueEmail, VirtualAuthenticator } from "./fixtures";
import { signUp, waitForSignInPage } from "./helpers";

/** The real bootstrap path: the operator CLI inside the API container. */
function grantRole(email: string, role: "admin" | "auditor") {
  execFileSync(
    "docker",
    [
      "compose",
      "exec",
      "-T",
      "api",
      "python",
      "-m",
      "keygate.cli",
      "grant-role",
      "--email",
      email,
      "--role",
      role,
    ],
    { cwd: "../..", stdio: "pipe" },
  );
}

test("an admin finds and suspends a user, which ends their session and is audited", async ({
  page,
  authenticator,
  browser,
}) => {
  expect(authenticator.id).toBeTruthy();
  const adminEmail = uniqueEmail("admin");
  await signUp(page, adminEmail);
  grantRole(adminEmail, "admin");

  // The target user, signed in in another browser.
  const victimEmail = uniqueEmail("victim");
  const other = await browser.newContext();
  const victimPage = await other.newPage();
  await VirtualAuthenticator.attach(victimPage);
  await signUp(victimPage, victimEmail);

  await page.goto("/admin");
  await page.getByLabel("Search users").fill(victimEmail);
  await page.getByRole("button", { name: "Search" }).click();
  await page.getByRole("link", { name: victimEmail }).click();
  await expect(page.getByTestId("admin-user-email")).toContainText(victimEmail);
  await expect(page.getByTestId("admin-session-list").locator("li")).toHaveCount(1);

  await page.getByLabel("Suspension reason").fill("E2E abuse report");
  await page.getByRole("button", { name: "Suspend" }).click();
  await expect(page.getByTestId("admin-user-email")).toContainText("suspended");

  // The victim's open session is gone immediately.
  await victimPage.reload();
  await waitForSignInPage(victimPage);
  await other.close();

  await page.goto("/admin/audit");
  await page.getByLabel("Event type").fill("user.suspend");
  await expect(page.getByTestId("audit-table")).toContainText("E2E abuse report");
});

test("a normal user can't see admin pages, and the nav hides admin links", async ({
  page,
  authenticator,
}) => {
  expect(authenticator.id).toBeTruthy();
  await signUp(page, uniqueEmail("plain"));
  await expect(page.getByRole("navigation").getByRole("link", { name: "Users" })).toHaveCount(0);
  await page.goto("/admin");
  await expect(page.getByRole("alert").filter({ hasText: "don't have permission" })).toBeVisible();
  // And the API itself refuses, whatever the UI does.
  const resp = await page.request.get("/api/admin/users");
  expect(resp.status()).toBe(403);
});
