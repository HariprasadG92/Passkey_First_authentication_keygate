import { expect, test, uniqueEmail } from "./fixtures";
import { signOut, signUp } from "./helpers";

const NOTES = process.env.KEYGATE_E2E_NOTES_URL ?? "http://127.0.0.1:3001";

test("Notes: sign in with Keygate, consent, use the API, sign out everywhere", async ({
  page,
  authenticator,
}) => {
  expect(authenticator.id).toBeTruthy();
  const email = uniqueEmail("notes");
  await signUp(page, email); // a Keygate account with a passkey (still signed in)
  await signOut(page); // start the OIDC flow signed out, like a first-time visitor

  await page.goto(NOTES);
  await page.getByRole("link", { name: "Sign in with Keygate" }).click();

  // Keygate asks for a sign-in first, then returns to the authorization request.
  await expect(page).toHaveURL(/localhost\/signin\?next=%2Foauth2%2Fauthorize/);
  await page.getByRole("button", { name: "Sign in with a passkey" }).click();

  // Consent screen lists exactly what Notes asked for.
  await expect(page.getByTestId("consent-scopes")).toContainText("Read your notes");
  await expect(page.getByTestId("consent-scopes")).toContainText("notes:write");
  await page.getByRole("button", { name: "Allow" }).click();

  // Back in Notes, signed in with claims from the ID token.
  await expect(page).toHaveURL(`${NOTES}/`);
  await expect(page.getByTestId("profile")).toContainText(email);
  await expect(page.getByTestId("profile")).toContainText("notes:read notes:write");

  // The Notes UI calls its BFF, which calls the resource API with the access token.
  await page.getByLabel("New note").fill("Passkeys beat passwords");
  await page.getByRole("button", { name: "Add" }).click();
  await expect(page.getByTestId("notes")).toContainText("Passkeys beat passwords");

  // The browser never holds a readable token: only an encrypted (JWE), HttpOnly cookie.
  const notesCookies = (await page.context().cookies(NOTES)).filter(
    (c) => !c.name.startsWith("__next"), // dev-server hot-reload cookie
  );
  expect(notesCookies.map((c) => c.name)).toEqual(["notes_session"]);
  expect(notesCookies[0].httpOnly).toBe(true);
  expect(notesCookies[0].value.split(".")).toHaveLength(5); // JWE, not a signed JWT
  for (const c of await page.context().cookies()) {
    expect(c.value.split(".").length, `${c.name} looks like a plain JWT`).not.toBe(3);
  }

  // RP-initiated logout ends both the Notes and the Keygate session.
  await page.getByRole("button", { name: "Sign out" }).click();
  await expect(page).toHaveURL(`${NOTES}/`);
  await expect(page.getByRole("link", { name: "Sign in with Keygate" })).toBeVisible();
  await page.goto("/account");
  await expect(page).toHaveURL(/\/signin/);
});

test("Notes: consent is remembered, and denial is handled", async ({ page, authenticator }) => {
  expect(authenticator.id).toBeTruthy();
  await signUp(page, uniqueEmail("deny"));

  await page.goto(NOTES);
  await page.getByRole("link", { name: "Sign in with Keygate" }).click();
  await page.getByRole("button", { name: "Deny" }).click();
  await expect(page).toHaveURL(`${NOTES}/`);
  await expect(page.getByRole("alert").filter({ hasText: "access_denied" })).toBeVisible();

  await page.getByRole("link", { name: "Sign in with Keygate" }).click();
  await page.getByRole("button", { name: "Allow" }).click();
  await expect(page.getByTestId("profile")).toBeVisible();

  // Second sign-in: already signed in to Keygate and consented, so no prompts at all.
  await page.context().clearCookies({ domain: "127.0.0.1" });
  await page.goto(NOTES);
  await page.getByRole("link", { name: "Sign in with Keygate" }).click();
  await expect(page.getByTestId("profile")).toBeVisible();
});

test("Notes resource API rejects requests without a valid access token", async ({ request }) => {
  const none = await request.get(`${NOTES}/api/notes`);
  expect(none.status()).toBe(401);
  const forged = await request.get(`${NOTES}/api/notes`, {
    headers: { Authorization: "Bearer eyJhbGciOiJub25lIn0.eyJzdWIiOiJ4In0." },
  });
  expect(forged.status()).toBe(401);
});

test("an unregistered redirect URI gets an error page, never a redirect", async ({ page }) => {
  await page.goto(
    "/oauth2/authorize?response_type=code&client_id=notes-demo&redirect_uri=" +
      encodeURIComponent("https://evil.example/callback"),
  );
  await expect(page).toHaveURL(/\/oauth\/error/);
  await expect(page.getByTestId("oauth-error")).toContainText("won't follow it");
});

test("sign-in ignores an open-redirect ?next", async ({ page, authenticator }) => {
  expect(authenticator.id).toBeTruthy();
  await signUp(page, uniqueEmail("next"));
  await signOut(page);
  await page.goto("/signin?next=" + encodeURIComponent("//evil.example/"));
  await page.getByRole("button", { name: "Sign in with a passkey" }).click();
  await expect(page).toHaveURL(/localhost\/account$/);
});
