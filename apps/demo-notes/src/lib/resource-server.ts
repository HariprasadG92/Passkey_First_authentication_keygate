/**
 * The Notes API as an OAuth resource server: it trusts nothing but a valid Keygate
 * access token. Checks: ES256 signature against Keygate's JWKS, `typ: at+jwt` (an ID
 * token can't be used instead), issuer, audience `notes-api`, expiry, and scopes.
 */
import "server-only";
import { createRemoteJWKSet, jwtVerify, type JWTPayload } from "jose";
import { config } from "@/lib/config";

let jwks: ReturnType<typeof createRemoteJWKSet> | null = null;
const keySet = () => (jwks ??= createRemoteJWKSet(new URL(`${config.internalUrl}/oauth2/jwks`)));

export class AuthError extends Error {
  constructor(
    public readonly status: 401 | 403,
    public readonly code: string,
  ) {
    super(code);
  }
}

export type AccessClaims = JWTPayload & { sub: string; scope: string; client_id: string };

export async function authenticate(request: Request, requiredScope: string): Promise<AccessClaims> {
  const [scheme, token] = (request.headers.get("authorization") ?? "").split(" ");
  if (scheme?.toLowerCase() !== "bearer" || !token) throw new AuthError(401, "invalid_request");
  let payload: JWTPayload;
  try {
    ({ payload } = await jwtVerify(token, keySet(), {
      issuer: config.issuer,
      audience: config.audience,
      algorithms: ["ES256"],
      typ: "at+jwt",
      requiredClaims: ["sub", "exp", "scope"],
    }));
  } catch {
    throw new AuthError(401, "invalid_token");
  }
  const scopes = String(payload.scope ?? "").split(" ");
  if (!scopes.includes(requiredScope)) throw new AuthError(403, "insufficient_scope");
  return payload as AccessClaims;
}

export function authErrorResponse(err: unknown): Response {
  if (err instanceof AuthError) {
    return Response.json(
      { error: err.code },
      { status: err.status, headers: { "WWW-Authenticate": `Bearer error="${err.code}"` } },
    );
  }
  throw err;
}
