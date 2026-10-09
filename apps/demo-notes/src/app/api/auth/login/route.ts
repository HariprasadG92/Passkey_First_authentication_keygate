import { NextResponse } from "next/server";
import { config } from "@/lib/config";
import { client, oidcConfig, redirectUri } from "@/lib/oidc";
import { saveTransaction } from "@/lib/session";

/** Start "Sign in with Keygate": Authorization Code + PKCE (S256), state and nonce. */
export async function GET() {
  const verifier = client.randomPKCECodeVerifier();
  const state = client.randomState();
  const nonce = client.randomNonce();
  await saveTransaction({ state, nonce, verifier });

  const url = client.buildAuthorizationUrl(await oidcConfig(), {
    redirect_uri: redirectUri(),
    scope: config.scope,
    code_challenge: await client.calculatePKCECodeChallenge(verifier),
    code_challenge_method: "S256",
    state,
    nonce,
  });
  return NextResponse.redirect(url);
}
