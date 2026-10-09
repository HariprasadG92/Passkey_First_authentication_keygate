/** Helpers for the browser-facing BFF routes. */
import "server-only";
import { config } from "@/lib/config";
import { client, oidcConfig } from "@/lib/oidc";
import { clearSession, getSession, saveSession, type NotesSession } from "@/lib/session";

/** CSRF defence for cookie-authenticated BFF writes: same-origin requests only. */
export function sameOrigin(request: Request): boolean {
  const origin = request.headers.get("origin");
  return origin === config.baseUrl;
}

/** The session, with the access token refreshed (rotating the refresh token) if needed. */
export async function activeSession(): Promise<NotesSession | null> {
  const session = await getSession();
  if (!session) return null;
  if (session.expiresAt - 30 > Date.now() / 1000) return session;
  if (!session.refreshToken) return null;
  try {
    const tokens = await client.refreshTokenGrant(await oidcConfig(), session.refreshToken);
    const refreshed: NotesSession = {
      ...session,
      accessToken: tokens.access_token,
      refreshToken: tokens.refresh_token ?? session.refreshToken,
      idToken: tokens.id_token ?? session.idToken,
      expiresAt: Math.floor(Date.now() / 1000) + (tokens.expiresIn() ?? 0),
    };
    await saveSession(refreshed);
    return refreshed;
  } catch {
    // Revoked (e.g. reuse detected, user suspended, signed out of Keygate): start over.
    await clearSession();
    return null;
  }
}

/** Call the Notes resource API exactly like a third party would: with a Bearer token. */
export function callNotesApi(path: string, session: NotesSession, init: RequestInit = {}) {
  return fetch(`http://127.0.0.1:${process.env.PORT ?? 3000}/api/notes${path}`, {
    ...init,
    headers: {
      ...(init.headers ?? {}),
      Authorization: `Bearer ${session.accessToken}`,
      "Content-Type": "application/json",
    },
    cache: "no-store",
  });
}
