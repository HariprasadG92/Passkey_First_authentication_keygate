/**
 * Where to go after signing in. Only a relative `/oauth2/authorize?...` path is accepted:
 * anything else (absolute URLs, `//host`, backslash tricks, other paths) is ignored, so
 * `?next=` can't be turned into an open redirect.
 */
export function safeNext(value: string | null): string | null {
  if (!value) return null;
  if (!value.startsWith("/oauth2/authorize?")) return null;
  if (value.includes("\\") || /[\u0000-\u001f]/.test(value)) return null;
  try {
    const url = new URL(value, window.location.origin);
    return url.origin === window.location.origin && url.pathname === "/oauth2/authorize"
      ? url.pathname + url.search
      : null;
  } catch {
    return null;
  }
}

/** Continue to `next` (a full navigation: /oauth2 is served by the API), else go home. */
export function continueAfterSignIn(next: string | null, fallback: () => void): void {
  if (next) window.location.assign(next);
  else fallback();
}
