import { NextResponse, type NextRequest } from "next/server";
import { config } from "@/lib/config";
import { client, oidcConfig } from "@/lib/oidc";
import { saveSession, takeTransaction } from "@/lib/session";

/**
 * Keygate sends the browser back here with ?code&state&iss. openid-client verifies the
 * state and `iss`, redeems the code with our PKCE verifier and client secret, and
 * validates the ID token (signature, issuer, audience, expiry, nonce).
 */
export async function GET(request: NextRequest) {
  const tx = await takeTransaction();
  const failed = (reason: string) =>
    NextResponse.redirect(`${config.baseUrl}/?error=${encodeURIComponent(reason)}`);
  if (!tx) return failed("login_expired");
  if (request.nextUrl.searchParams.get("error")) {
    return failed(request.nextUrl.searchParams.get("error") ?? "access_denied");
  }

  // The URL as the browser saw it (we may be behind a port mapping).
  const currentUrl = new URL(request.nextUrl.pathname + request.nextUrl.search, config.baseUrl);
  try {
    const tokens = await client.authorizationCodeGrant(await oidcConfig(), currentUrl, {
      pkceCodeVerifier: tx.verifier,
      expectedState: tx.state,
      expectedNonce: tx.nonce,
      idTokenExpected: true,
    });
    const claims = tokens.claims()!;
    await saveSession({
      sub: claims.sub,
      name: claims.name as string | undefined,
      email: claims.email as string | undefined,
      scope: tokens.scope ?? "",
      idToken: tokens.id_token!,
      accessToken: tokens.access_token,
      refreshToken: tokens.refresh_token,
      expiresAt: Math.floor(Date.now() / 1000) + (tokens.expiresIn() ?? 0),
    });
  } catch (err) {
    console.error("OIDC callback failed:", (err as Error).name, (err as Error).message);
    return failed("login_failed");
  }
  return NextResponse.redirect(`${config.baseUrl}/`);
}
