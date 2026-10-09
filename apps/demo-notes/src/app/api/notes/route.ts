import { authenticate, authErrorResponse } from "@/lib/resource-server";
import { notes } from "@/lib/notes-store";

/** Resource API: list notes (needs `notes:read`). */
export async function GET(request: Request) {
  try {
    const claims = await authenticate(request, "notes:read");
    return Response.json({ notes: notes.list(claims.sub) });
  } catch (err) {
    return authErrorResponse(err);
  }
}

/** Resource API: create a note (needs `notes:write`). */
export async function POST(request: Request) {
  try {
    const claims = await authenticate(request, "notes:write");
    const body = (await request.json().catch(() => null)) as { text?: unknown } | null;
    const text = typeof body?.text === "string" ? body.text.trim() : "";
    if (!text || text.length > 500) {
      return Response.json({ error: "invalid_note" }, { status: 400 });
    }
    return Response.json({ note: notes.add(claims.sub, text) }, { status: 201 });
  } catch (err) {
    return authErrorResponse(err);
  }
}
