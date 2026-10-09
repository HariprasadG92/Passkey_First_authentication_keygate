import { activeSession, callNotesApi, sameOrigin } from "@/lib/bff";

export async function DELETE(request: Request, { params }: { params: Promise<{ id: string }> }) {
  if (!sameOrigin(request)) return Response.json({ error: "forbidden" }, { status: 403 });
  const session = await activeSession();
  if (!session) return Response.json({ error: "signed_out" }, { status: 401 });
  const { id } = await params;
  const resp = await callNotesApi(`/${encodeURIComponent(id)}`, session, { method: "DELETE" });
  return new Response(resp.status === 204 ? null : resp.body, { status: resp.status });
}
