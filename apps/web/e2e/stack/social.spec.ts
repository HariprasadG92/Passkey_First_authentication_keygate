import { expect, test } from "./fixtures";
import { waitForSignInPage } from "./helpers";

// Real provider round-trips can't run in CI without credentials; the API suite covers
// the protocol with mocked providers. These check the UI wiring.

test("no social buttons when no provider is configured", async ({ page }) => {
  const providers = await (await page.request.get("/api/auth/social/providers")).json();
  test.skip(providers.length > 0, "a provider is configured in this environment");
  await page.goto("/signin");
  await waitForSignInPage(page);
  await expect(page.getByTestId("social-buttons")).toHaveCount(0);
});

test("explains why a social sign-in was refused", async ({ page }) => {
  await page.goto("/signin?error=social_email_in_use");
  await expect(
    page.getByRole("alert").filter({ hasText: "already uses that email" }),
  ).toBeVisible();
  // The error code is removed from the address bar.
  await expect(page).toHaveURL(/\/signin$/);
});
