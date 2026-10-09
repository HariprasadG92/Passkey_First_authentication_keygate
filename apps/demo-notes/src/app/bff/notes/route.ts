import { activeSession, callNotesApi, sameOrigin } from "@/lib/bff";

export async function GET() {
  const session = await activeSession();
  if (!session) return Response.json({ error: "signed_out" }, { status: 401 });
  const resp = await callNotesApi("", session);
  return new Response(resp.body, {
    status: resp.status,
    headers: { "Content-Type": "application/json" },
  });
}

export async function POST(request: Request) {
  if (!sameOrigin(request)) return Response.json({ error: "forbidden" }, { status: 403 });
  const session = await activeSession();
  if (!session) return Response.json({ error: "signed_out" }, { status: 401 });
  const resp = await callNotesApi("", session, { method: "POST", body: await request.text() });
  return new Response(resp.body, {
    status: resp.status,
    headers: { "Content-Type": "application/json" },
  });
}
