/** The OpenID Connect client (openid-client). */
import "server-only";
import * as client from "openid-client";
import { config } from "@/lib/config";

let cached: Promise<client.Configuration> | null = null;

/**
 * Server-to-server calls go to Keygate's internal URL, while every *validation* still uses
 * the public issuer (http://localhost): discovery must claim that issuer, and ID tokens
 * must be signed for it. Only the network location is swapped.
 */
const internalFetch: client.CustomFetch = (url, options) => {
  const rewritten = url.startsWith(config.issuer)
    ? config.internalUrl + url.slice(config.issuer.length)
    : url;
  // CustomFetchOptions types `body` more broadly than the DOM lib; the runtime values match.
  return fetch(rewritten, options as RequestInit);
};

export function oidcConfig(): Promise<client.Configuration> {
  cached ??= client
    .discovery(
      new URL(config.issuer),
      config.clientId,
      undefined,
      client.ClientSecretBasic(config.clientSecret),
      {
        [client.customFetch]: internalFetch,
        // Local development runs Keygate on plain http://localhost.
        execute: config.issuer.startsWith("http://") ? [client.allowInsecureRequests] : [],
      },
    )
    .then((cfg) => {
      cfg[client.customFetch] = internalFetch;
      return cfg;
    })
    .catch((err) => {
      cached = null; // retry next time (Keygate may still be starting)
      throw err;
    });
  return cached;
}

export const redirectUri = () => `${config.baseUrl}/api/auth/callback`;
export { client };
