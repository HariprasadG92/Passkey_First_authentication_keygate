/**
 * Backend-for-frontend session: tokens live server-side only, inside an encrypted
 * (A256GCM), HttpOnly, SameSite=Lax cookie. Browser JavaScript never sees a token, so an
 * XSS bug in Notes can't steal one.
 */
import "server-only";
import { createHash } from "node:crypto";
import { EncryptJWT, jwtDecrypt } from "jose";
import { cookies } from "next/headers";
import { config } from "@/lib/config";

const SESSION_COOKIE = "notes_session";
const TX_COOKIE = "notes_oidc_tx";
const key = () => createHash("sha256").update(config.sessionSecret).digest();
const secure = () => config.baseUrl.startsWith("https://");

export type NotesSession = {
  sub: string;
  name?: string;
  email?: string;
  scope: string;
  idToken: string;
  accessToken: string;
  refreshToken?: string;
  expiresAt: number; // epoch seconds
};

/** Per-login secrets that must survive the round trip to Keygate. */
export type LoginTransaction = { state: string; nonce: string; verifier: string };

async function seal(payload: Record<string, unknown>, ttlSeconds: number): Promise<string> {
  return new EncryptJWT(payload)
    .setProtectedHeader({ alg: "dir", enc: "A256GCM" })
    .setIssuedAt()
    .setExpirationTime(`${ttlSeconds}s`)
    .encrypt(key());
}

async function unseal<T>(value: string | undefined): Promise<T | null> {
  if (!value) return null;
  try {
    const { payload } = await jwtDecrypt(value, key());
    return payload as T;
  } catch {
    return null; // tampered, expired or from another key
  }
}

const cookieOptions = (maxAge: number) => ({
  httpOnly: true,
  secure: secure(),
  sameSite: "lax" as const,
  path: "/",
  maxAge,
});

export async function getSession(): Promise<NotesSession | null> {
  return unseal<NotesSession>((await cookies()).get(SESSION_COOKIE)?.value);
}

export async function saveSession(session: NotesSession): Promise<void> {
  const maxAge = 60 * 60 * 8;
  (await cookies()).set(SESSION_COOKIE, await seal(session, maxAge), cookieOptions(maxAge));
}

export async function clearSession(): Promise<void> {
  (await cookies()).delete(SESSION_COOKIE);
}

export async function saveTransaction(tx: LoginTransaction): Promise<void> {
  (await cookies()).set(TX_COOKIE, await seal(tx, 600), cookieOptions(600));
}

export async function takeTransaction(): Promise<LoginTransaction | null> {
  const store = await cookies();
  const tx = await unseal<LoginTransaction>(store.get(TX_COOKIE)?.value);
  store.delete(TX_COOKIE);
  return tx;
}
