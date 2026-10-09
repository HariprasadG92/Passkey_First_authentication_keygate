import { NextResponse } from "next/server";
import { config } from "@/lib/config";
import { client, oidcConfig } from "@/lib/oidc";
import { clearSession, getSession } from "@/lib/session";

/** RP-initiated logout: clear our session, then end the Keygate session too. */
export async function POST(request: Request) {
  if (request.headers.get("origin") !== config.baseUrl) {
    return NextResponse.json({ error: "forbidden" }, { status: 403 });
  }
  const session = await getSession();
  await clearSession();
  if (!session) return NextResponse.redirect(`${config.baseUrl}/`, 303);
  const url = client.buildEndSessionUrl(await oidcConfig(), {
    id_token_hint: session.idToken,
    post_logout_redirect_uri: `${config.baseUrl}/`,
  });
  return NextResponse.redirect(url, 303);
}
