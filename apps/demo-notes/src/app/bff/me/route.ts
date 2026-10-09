import { activeSession } from "@/lib/bff";

/** What the UI may know: profile and granted scopes. Never tokens. */
export async function GET() {
  const session = await activeSession();
  if (!session) return Response.json({ signedIn: false });
  return Response.json({
    signedIn: true,
    sub: session.sub,
    name: session.name,
    email: session.email,
    scopes: session.scope.split(" "),
  });
}
