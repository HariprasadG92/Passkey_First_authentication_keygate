/** Server-only configuration (never imported by client components). Read lazily so the
 * app can be built without runtime secrets present. */
import "server-only";

function required(name: string): string {
  const value = process.env[name];
  if (!value) throw new Error(`Missing environment variable ${name}`);
  return value;
}

export const config = {
  /** Keygate's public issuer: what the browser sees and what tokens must say in `iss`. */
  get issuer() {
    return process.env.KEYGATE_ISSUER ?? "http://localhost";
  },
  /** How this server reaches Keygate on the internal network (same service, other URL). */
  get internalUrl() {
    return process.env.KEYGATE_INTERNAL_URL ?? "http://localhost";
  },
  get clientId() {
    return required("NOTES_CLIENT_ID");
  },
  get clientSecret() {
    return required("NOTES_CLIENT_SECRET");
  },
  get baseUrl() {
    return process.env.NOTES_BASE_URL ?? "http://127.0.0.1:3001";
  },
  get sessionSecret() {
    return required("NOTES_SESSION_SECRET");
  },
  audience: "notes-api",
  scope: "openid profile email notes:read notes:write",
};
