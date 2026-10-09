import { expect, magicLinkFor, test, uniqueEmail } from "./fixtures";

async function signUp(page: import("@playwright/test").Page, email: string, keyName: string) {
  await page.goto("/signup");
  await page.getByLabel("Email").fill(email);
  await page.getByRole("button", { name: "Send confirmation link" }).click();
  await expect(page.getByTestId("signup-sent")).toBeVisible();

  const link = await magicLinkFor(email);
  // The token is in the fragment, so it's never sent to the server or logged.
  expect(new URL(link).search).toBe("");
  await page.goto(new URL(link).pathname + new URL(link).hash);
  // The page removes the token from the address bar immediately.
  await expect(page).toHaveURL(/\/verify-email$/);

  await page.getByRole("button", { name: "Confirm email" }).click();
  await page.getByLabel("Name this passkey").fill(keyName);
  await page.getByRole("button", { name: "Create passkey" }).click();
  await expect(page.getByTestId("account-heading")).toBeVisible();
}

test("sign up with a magic link, create a passkey, sign out and back in (usernameless)", async ({
  page,
  authenticator,
}) => {
  const email = uniqueEmail("signup");
  await signUp(page, email, "Virtual Touch ID");

  await expect(page.getByTestId("passkey-list")).toContainText("Virtual Touch ID");
  const [credential] = await authenticator.credentials();
  expect(credential.isResidentCredential).toBe(true);

  await page.getByRole("button", { name: "Sign out" }).click();
  await expect(page).toHaveURL(/\/signin$/);
  expect(
    (await page.context().cookies()).find((c) => c.name.endsWith("kg_session")),
  ).toBeUndefined();

  await page.getByRole("button", { name: "Sign in with a passkey" }).click();
  await expect(page.getByTestId("account-heading")).toBeVisible();
  await expect(page.getByText(email)).toBeVisible();
});

test("email-first sign-in", async ({ page, authenticator }) => {
  const email = uniqueEmail("emailfirst");
  await signUp(page, email, "Key");
  await page.getByRole("button", { name: "Sign out" }).click();

  await page.getByLabel("Email").fill(email);
  await page.getByRole("button", { name: "Continue" }).click();
  await expect(page.getByTestId("account-heading")).toBeVisible();
  expect((await authenticator.credentials())[0].signCount).toBeGreaterThan(0);
});

test("session cookie is HttpOnly and never readable by page scripts", async ({
  page,
  authenticator,
}) => {
  expect(authenticator.id).toBeTruthy();
  await signUp(page, uniqueEmail("cookie"), "Key");
  const session = (await page.context().cookies()).find((c) => c.name.endsWith("kg_session"));
  expect(session?.httpOnly).toBe(true);
  expect(session?.sameSite).toBe("Lax");
  expect(await page.evaluate(() => document.cookie)).not.toContain("kg_session");
});

test("account page redirects to sign-in when signed out", async ({ page }) => {
  await page.goto("/account");
  await expect(page).toHaveURL(/\/signin$/);
});
