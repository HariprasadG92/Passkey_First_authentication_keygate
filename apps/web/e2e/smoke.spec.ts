import { expect, test } from "@playwright/test";

test("home page renders", async ({ page }) => {
  await page.goto("/");
  await expect(page.getByRole("heading", { level: 1 })).toHaveText("Sign in without passwords.");
  await expect(page).toHaveTitle("Keygate");
});

test("sends a nonce-based CSP and security headers", async ({ request }) => {
  const res = await request.get("/");
  const headers = res.headers();
  const csp = headers["content-security-policy"];

  expect(csp).toMatch(/script-src 'self' 'nonce-[A-Za-z0-9+/=]+' 'strict-dynamic'/);
  expect(csp).toContain("frame-ancestors 'none'");
  expect(csp).toContain("object-src 'none'");
  expect(csp).not.toContain("unsafe-eval");
  expect(headers["x-content-type-options"]).toBe("nosniff");
  expect(headers["x-frame-options"]).toBe("DENY");
  expect(headers["x-powered-by"]).toBeUndefined();
});

test("nonce is fresh on every request", async ({ request }) => {
  const nonceOf = async () =>
    (await request.get("/")).headers()["content-security-policy"].match(/'nonce-([^']+)'/)?.[1];
  const [a, b] = [await nonceOf(), await nonceOf()];
  expect(a).toBeTruthy();
  expect(a).not.toBe(b);
});

test("page hydrates without CSP violations", async ({ page }) => {
  const violations: string[] = [];
  page.on("console", (msg) => {
    if (msg.type() === "error" && /Content Security Policy/i.test(msg.text())) {
      violations.push(msg.text());
    }
  });
  await page.goto("/");
  // The API status widget is a client component: it only renders a state once React hydrated.
  await expect(page.getByTestId("api-status")).not.toHaveText("Checking API…");
  expect(violations).toEqual([]);
});
