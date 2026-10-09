"use client";

import { useCallback, useEffect, useState } from "react";

type Me =
  | { signedIn: false }
  | { signedIn: true; sub: string; name?: string; email?: string; scopes: string[] };
type Note = { id: string; text: string; createdAt: string };

export default function Home() {
  const [me, setMe] = useState<Me | null>(null);
  const [notes, setNotes] = useState<Note[]>([]);
  const [text, setText] = useState("");
  const [error, setError] = useState<string | null>(null);

  const load = useCallback(async () => {
    const profile: Me = await fetch("/bff/me", { cache: "no-store" }).then((r) => r.json());
    setMe(profile);
    if (profile.signedIn) {
      const resp = await fetch("/bff/notes", { cache: "no-store" });
      if (resp.ok) setNotes((await resp.json()).notes);
    }
  }, []);

  useEffect(() => {
    const params = new URLSearchParams(window.location.search);
    if (params.get("error")) {
      setError(`Sign-in didn't complete (${params.get("error")}).`);
      window.history.replaceState(null, "", "/");
    }
    void load();
  }, [load]);

  if (!me) return <p className="p-8 text-gray-500">Loading…</p>;

  return (
    <main className="mx-auto max-w-xl space-y-6 p-8">
      <header className="flex items-center justify-between">
        <h1 className="text-2xl font-bold">📝 Notes</h1>
        {me.signedIn && (
          <form action="/api/auth/logout" method="post">
            <button className="rounded border px-3 py-1 text-sm hover:bg-gray-50">Sign out</button>
          </form>
        )}
      </header>
      <p className="text-sm text-gray-500">
        A demo app that signs in only through Keygate (OpenID Connect, Authorization Code + PKCE).
      </p>
      {error && (
        <p role="alert" className="rounded bg-red-50 p-3 text-sm text-red-700">
          {error}
        </p>
      )}

      {!me.signedIn ? (
        <a
          href="/api/auth/login"
          className="inline-block rounded bg-black px-4 py-2 font-medium text-white"
        >
          Sign in with Keygate
        </a>
      ) : (
        <>
          <section className="rounded border p-4 text-sm" data-testid="profile">
            <p className="font-medium">{me.name}</p>
            <p>{me.email}</p>
            <p className="text-xs text-gray-500">
              Keygate subject: <code>{me.sub}</code>
            </p>
            <p className="text-xs text-gray-500">Granted: {me.scopes.join(" ")}</p>
          </section>

          {me.scopes.includes("notes:write") && (
            <form
              className="flex gap-2"
              onSubmit={async (e) => {
                e.preventDefault();
                if (!text.trim()) return;
                const resp = await fetch("/bff/notes", {
                  method: "POST",
                  headers: { "Content-Type": "application/json" },
                  body: JSON.stringify({ text }),
                });
                if (resp.ok) {
                  setText("");
                  void load();
                } else setError("Couldn't save the note.");
              }}
            >
              <input
                aria-label="New note"
                className="flex-1 rounded border px-3 py-2"
                placeholder="Write a note…"
                maxLength={500}
                value={text}
                onChange={(e) => setText(e.target.value)}
              />
              <button className="rounded bg-black px-4 py-2 text-white">Add</button>
            </form>
          )}

          <ul className="divide-y rounded border" data-testid="notes">
            {notes.length === 0 && <li className="p-3 text-sm text-gray-500">No notes yet.</li>}
            {notes.map((n) => (
              <li key={n.id} className="flex items-center justify-between p-3">
                <span>{n.text}</span>
                <button
                  className="text-sm text-gray-500 hover:text-red-600"
                  aria-label={`Delete ${n.text}`}
                  onClick={async () => {
                    await fetch(`/bff/notes/${n.id}`, { method: "DELETE" });
                    void load();
                  }}
                >
                  Delete
                </button>
              </li>
            ))}
          </ul>
        </>
      )}
    </main>
  );
}
