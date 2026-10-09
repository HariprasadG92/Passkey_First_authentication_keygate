import { expect, expireStepUp, test, totp, uniqueEmail, VirtualAuthenticator } from "./fixtures";
import { signOut, signUp } from "./helpers";

test("set up an authenticator app and sign in with a code", async ({ page, authenticator }) => {
  expect(authenticator.id).toBeTruthy();
  const email = uniqueEmail("totp");
  await signUp(page, email);

  await page.getByRole("button", { name: "Set up authenticator app" }).click();
  await expect(page.getByAltText(/QR code/)).toBeVisible();
  const secret = (await page.getByTestId("totp-secret").textContent())!.trim();
  await page.getByLabel("Enter the 6-digit code").fill(totp(secret));
  await page.getByRole("button", { name: "Turn on" }).click();
  await expect(page.getByText("On", { exact: true })).toBeVisible();

  await signOut(page);
  await page.getByRole("button", { name: "Use authenticator app" }).click();
  const form = page.getByTestId("totp-form");
  await form.getByLabel("Email").fill(email);
  // Next time step: the enrolment code's step can't be replayed.
  await form.getByLabel("Authenticator code").fill(totp(secret, Date.now() + 30_000));
  await form.getByRole("button", { name: "Sign in with code" }).click();
  await expect(page.getByTestId("account-heading")).toBeVisible();
});

test("recovery codes are shown once and sign you in exactly once", async ({
  page,
  authenticator,
}) => {
  expect(authenticator.id).toBeTruthy();
  const email = uniqueEmail("recovery");
  await signUp(page, email);

  await page.getByRole("button", { name: "Generate recovery codes" }).click();
  const items = page.getByTestId("recovery-codes").locator("li");
  await expect(items).toHaveCount(10);
  const codes = (await items.allTextContents()).map((c) => c.trim());
  await page.getByRole("button", { name: "I've saved them" }).click();
  await expect(page.getByTestId("recovery-codes")).toHaveCount(0);

  const useRecoveryCode = async () => {
    await page.getByRole("button", { name: "Use a recovery code" }).click();
    const form = page.getByTestId("recovery-form");
    await form.getByLabel("Email").fill(email);
    await form.getByLabel("Recovery code").fill(codes[0]);
    await form.getByRole("button", { name: "Sign in with recovery code" }).click();
    return form;
  };

  // First use: signs in, and one code is gone.
  await signOut(page);
  await useRecoveryCode();
  await expect(page.getByTestId("recovery-remaining")).toHaveText("9");

  // Second use of the same code: rejected.
  await signOut(page);
  const form = await useRecoveryCode();
  await expect(form.getByRole("alert")).toContainText("don't match");
  await expect(page).toHaveURL(/\/signin$/);
});

test("sensitive actions ask you to confirm with your passkey", async ({ page, authenticator }) => {
  expect(authenticator.id).toBeTruthy();
  await signUp(page, uniqueEmail("stepup"));
  expireStepUp();

  await page.getByRole("button", { name: "Generate recovery codes" }).click();
  const dialog = page.getByRole("dialog");
  await expect(dialog).toContainText("Confirm it's you");
  await dialog.getByRole("button", { name: "Use a passkey" }).click();
  await expect(dialog).toBeHidden();
  await expect(page.getByTestId("recovery-codes").locator("li")).toHaveCount(10);
});

test("the last sign-in method can't be removed", async ({ page, authenticator }) => {
  expect(authenticator.id).toBeTruthy();
  await signUp(page, uniqueEmail("last"), "Only key");
  page.once("dialog", (d) => d.accept());
  await page.getByRole("button", { name: "Remove Only key" }).click();
  // (Next.js renders its own empty role=alert route announcer, so filter by text.)
  await expect(page.getByRole("alert").filter({ hasText: "only way to sign in" })).toBeVisible();
  await expect(page.getByTestId("passkey-list")).toContainText("Only key");
});

test("sign out everywhere else", async ({ page, authenticator, browser }) => {
  expect(authenticator.id).toBeTruthy();
  const email = uniqueEmail("sessions");
  await signUp(page, email);
  await page.getByRole("button", { name: "Set up authenticator app" }).click();
  const secret = (await page.getByTestId("totp-secret").textContent())!.trim();
  await page.getByLabel("Enter the 6-digit code").fill(totp(secret));
  await page.getByRole("button", { name: "Turn on" }).click();

  // A second browser signs in with the authenticator app.
  const other = await browser.newContext();
  const otherPage = await other.newPage();
  await VirtualAuthenticator.attach(otherPage);
  await otherPage.goto("/signin");
  await otherPage.getByRole("button", { name: "Use authenticator app" }).click();
  const form = otherPage.getByTestId("totp-form");
  await form.getByLabel("Email").fill(email);
  await form.getByLabel("Authenticator code").fill(totp(secret, Date.now() + 30_000));
  await form.getByRole("button", { name: "Sign in with code" }).click();
  await expect(otherPage.getByTestId("account-heading")).toBeVisible();

  await page.reload();
  await expect(page.getByTestId("session-list").locator("li")).toHaveCount(2);
  await page.getByRole("button", { name: "Sign out everywhere else" }).click();
  await expect(page.getByTestId("session-list").locator("li")).toHaveCount(1);

  await otherPage.reload();
  await expect(otherPage).toHaveURL(/\/signin$/);
  await other.close();
});
