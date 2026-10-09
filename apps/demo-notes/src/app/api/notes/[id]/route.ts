import { authenticate, authErrorResponse } from "@/lib/resource-server";
import { notes } from "@/lib/notes-store";

/** Resource API: delete a note (needs `notes:write`); only your own notes. */
export async function DELETE(request: Request, { params }: { params: Promise<{ id: string }> }) {
  try {
    const claims = await authenticate(request, "notes:write");
    const { id } = await params;
    return notes.remove(claims.sub, id)
      ? new Response(null, { status: 204 })
      : Response.json({ error: "not_found" }, { status: 404 });
  } catch (err) {
    return authErrorResponse(err);
  }
}
