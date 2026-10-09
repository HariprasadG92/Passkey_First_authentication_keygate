import { expect, type Page } from "@playwright/test";
import { magicLinkFor } from "./fixtures";

export async function signUp(page: Page, email: string, keyName = "Virtual key") {
  await page.goto("/signup");
  await page.getByLabel("Email").fill(email);
  await page.getByRole("button", { name: "Send confirmation link" }).click();
  await expect(page.getByTestId("signup-sent")).toBeVisible();
  const link = new URL(await magicLinkFor(email));
  // The token is in the fragment, so it's never sent to the server or logged...
  expect(link.search).toBe("");
  await page.goto(link.pathname + link.hash);
  // ...and the page removes it from the address bar immediately.
  await expect(page).toHaveURL(/\/verify-email$/);
  await page.getByRole("button", { name: "Confirm email" }).click();
  await page.getByLabel("Name this passkey").fill(keyName);
  await page.getByRole("button", { name: "Create passkey" }).click();
  await expect(page.getByTestId("account-heading")).toBeVisible();
}

export async function signOut(page: Page) {
  await page.getByRole("button", { name: "Sign out", exact: true }).first().click();
  await waitForSignInPage(page);
}

/** The sign-in page is interactive once hydrated: the nav's "Sign in" link is rendered by a
 * client effect, so typing before it appears could be wiped by hydration. */
export async function waitForSignInPage(page: Page) {
  await expect(page).toHaveURL(/\/signin$/);
  await expect(page.getByRole("navigation").getByRole("link", { name: "Sign in" })).toBeVisible();
}
