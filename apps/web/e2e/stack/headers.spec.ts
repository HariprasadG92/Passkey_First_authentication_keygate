import { expect, test } from "@playwright/test";

/**
 * Security headers as users actually receive them: through the gateway, for the UI, the
 * API and the OIDC endpoints, plus the Notes demo. (Unit tests cover each app alone.)
 */
const NOTES = process.env.KEYGATE_E2E_NOTES_URL ?? "http://127.0.0.1:3001";

const common = (h: Record<string, string>, label: string) => {
  expect(h["x-content-type-options"], label).toBe("nosniff");
  expect(h["x-frame-options"], label).toBe("DENY");
  expect(h["x-powered-by"], label).toBeUndefined();
  expect(h["server"], label).toBeUndefined(); // gateway strips it
};

test("Keygate UI: nonce CSP, framing denied, no server fingerprint", async ({ request }) => {
  const h = (await request.get("/signin")).headers();
  common(h, "ui");
  expect(h["content-security-policy"]).toMatch(/script-src 'self' 'nonce-[^']+' 'strict-dynamic'/);
  expect(h["content-security-policy"]).toContain("frame-ancestors 'none'");
  expect(h["content-security-policy"]).toContain("object-src 'none'");
  expect(h["content-security-policy"]).toContain("base-uri 'none'");
  expect(h["referrer-policy"]).toBe("strict-origin-when-cross-origin");
});

for (const path of ["/api/health", "/api/auth/session", "/.well-known/openid-configuration"]) {
  test(`API ${path}: locked-down CSP`, async ({ request }) => {
    const h = (await request.get(path)).headers();
    common(h, path);
    expect(h["content-security-policy"]).toBe(
      "default-src 'none'; frame-ancestors 'none'; base-uri 'none'",
    );
    expect(h["referrer-policy"]).toBe("no-referrer");
  });
}

test("API: auth responses are never cached", async ({ request }) => {
  const h = (await request.get("/api/auth/session")).headers();
  expect(h["cache-control"]).toBe("no-store");
});

test("Notes demo: CSP, framing denied, no-store", async ({ request }) => {
  const h = (await request.get(NOTES)).headers();
  expect(h["x-content-type-options"]).toBe("nosniff");
  expect(h["x-frame-options"]).toBe("DENY");
  expect(h["x-powered-by"]).toBeUndefined();
  expect(h["content-security-policy"]).toContain("frame-ancestors 'none'");
  expect(h["cache-control"]).toContain("no-store");
});
