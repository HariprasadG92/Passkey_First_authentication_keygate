import { test as base, expect, type CDPSession, type Page } from "@playwright/test";

const MAILPIT = process.env.KEYGATE_E2E_MAILPIT ?? "http://localhost:8025";

/**
 * A Chrome DevTools Protocol virtual authenticator: a platform authenticator with
 * resident keys and user verification, like Touch ID or Windows Hello.
 */
export class VirtualAuthenticator {
  private constructor(
    private readonly cdp: CDPSession,
    readonly id: string,
  ) {}

  static async attach(page: Page): Promise<VirtualAuthenticator> {
    const cdp = await page.context().newCDPSession(page);
    await cdp.send("WebAuthn.enable");
    const { authenticatorId } = await cdp.send("WebAuthn.addVirtualAuthenticator", {
      options: {
        protocol: "ctap2",
        transport: "internal",
        hasResidentKey: true,
        hasUserVerification: true,
        isUserVerified: true,
        automaticPresenceSimulation: true,
      },
    });
    return new VirtualAuthenticator(cdp, authenticatorId);
  }

  async credentials() {
    const { credentials } = await this.cdp.send("WebAuthn.getCredentials", {
      authenticatorId: this.id,
    });
    return credentials;
  }
}

export function uniqueEmail(prefix = "e2e"): string {
  return `${prefix}-${Date.now()}-${Math.floor(Math.random() * 1e6)}@example.com`;
}

/** Poll Mailpit for the newest message to `email` and return its magic link. */
export async function magicLinkFor(email: string): Promise<string> {
  for (let attempt = 0; attempt < 30; attempt++) {
    const search = await fetch(
      `${MAILPIT}/api/v1/search?query=${encodeURIComponent(`to:"${email}"`)}`,
    ).then((r) => r.json());
    const id: string | undefined = search.messages?.[0]?.ID;
    if (id) {
      const message = await fetch(`${MAILPIT}/api/v1/message/${id}`).then((r) => r.json());
      const link = (message.Text as string).match(/https?:\/\/\S+#token=[A-Za-z0-9_-]+/)?.[0];
      if (link) return link;
    }
    await new Promise((r) => setTimeout(r, 250));
  }
  throw new Error(`No magic link for ${email} in Mailpit`);
}

export const test = base.extend<{ authenticator: VirtualAuthenticator }>({
  authenticator: async ({ page }, use) => {
    await use(await VirtualAuthenticator.attach(page));
  },
});

export { expect };
