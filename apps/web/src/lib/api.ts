/**
 * Client for the Keygate API (same origin, behind the gateway at /api).
 *
 * - Cookies are HttpOnly and sent automatically; JS never sees the session token.
 * - Every state-changing request echoes the CSRF cookie in the X-CSRF-Token header
 *   (signed double-submit; the server verifies it's bound to the current session).
 */

const CSRF_COOKIES = ["__Host-kg_csrf", "kg_csrf"];
const UNSAFE = new Set(["POST", "PUT", "PATCH", "DELETE"]);

export class ApiError extends Error {
  constructor(
    public readonly status: number,
    message: string,
    public readonly code?: string,
  ) {
    super(message);
  }
}

function readCsrfCookie(): string | undefined {
  const cookies = document.cookie.split("; ");
  for (const name of CSRF_COOKIES) {
    const match = cookies.find((c) => c.startsWith(`${name}=`));
    if (match) return decodeURIComponent(match.slice(name.length + 1));
  }
  return undefined;
}

async function ensureCsrfToken(): Promise<string> {
  const existing = readCsrfCookie();
  if (existing) return existing;
  await fetch("/api/auth/session", { cache: "no-store" });
  const token = readCsrfCookie();
  if (!token) throw new ApiError(0, "Could not establish a secure session. Reload the page.");
  return token;
}

export async function api<T>(
  path: string,
  init: { method?: string; body?: unknown } = {},
): Promise<T> {
  const method = init.method ?? "GET";
  const headers: Record<string, string> = { Accept: "application/json" };
  if (init.body !== undefined) headers["Content-Type"] = "application/json";
  if (UNSAFE.has(method)) headers["X-CSRF-Token"] = await ensureCsrfToken();

  const res = await fetch(`/api${path}`, {
    method,
    headers,
    body: init.body === undefined ? undefined : JSON.stringify(init.body),
    cache: "no-store",
  });
  if (res.status === 204) return undefined as T;

  const data: unknown = await res.json().catch(() => null);
  if (!res.ok) {
    const error = (data as { error?: { message?: string; code?: string } } | null)?.error;
    throw new ApiError(res.status, error?.message ?? "Something went wrong.", error?.code);
  }
  return data as T;
}

export type User = { id: string; email: string; email_verified: boolean; display_name: string };

export type SessionInfo = {
  authenticated: boolean;
  level: "registration" | "full" | null;
  user: User | null;
  csrf_token: string;
};

export type Passkey = {
  id: string;
  friendly_name: string;
  created_at: string;
  last_used_at: string | null;
  backup_eligible: boolean;
  backup_state: boolean;
  transports: string[];
};

export type Account = { user: User; passkeys: Passkey[] };
