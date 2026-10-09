"use client";

import { useState } from "react";
import { KeyRound, Pencil, Trash2 } from "lucide-react";
import { FormError } from "@/components/form-message";
import { useStepUp } from "@/components/step-up";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Input } from "@/components/ui/input";
import { api, type Passkey } from "@/lib/api";
import { addPasskey, describePasskeyError } from "@/lib/passkeys";
import { passkeyNameSchema } from "@/lib/validation";

const fmt = new Intl.DateTimeFormat(undefined, { dateStyle: "medium", timeStyle: "short" });

export function PasskeysCard({
  passkeys,
  onChange,
}: {
  passkeys: Passkey[];
  onChange: () => void;
}) {
  const runWithStepUp = useStepUp();
  const [editing, setEditing] = useState<string | null>(null);
  const [name, setName] = useState("");
  const [newName, setNewName] = useState("");
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);

  async function act(fn: () => Promise<unknown>) {
    setBusy(true);
    setError(null);
    try {
      await fn();
      onChange();
    } catch (err) {
      setError(describePasskeyError(err));
    } finally {
      setBusy(false);
    }
  }

  return (
    <Card>
      <CardHeader>
        <CardTitle>Passkeys</CardTitle>
        <CardDescription>
          Devices and password managers that can sign you in. Add more than one so you never get
          locked out.
        </CardDescription>
      </CardHeader>
      <CardContent className="space-y-4">
        <ul className="divide-y" data-testid="passkey-list">
          {passkeys.map((p) => (
            <li key={p.id} className="flex items-center gap-3 py-3">
              <KeyRound className="size-5 shrink-0 text-muted-foreground" aria-hidden />
              <div className="min-w-0 flex-1">
                {editing === p.id ? (
                  <form
                    className="flex gap-2"
                    onSubmit={(e) => {
                      e.preventDefault();
                      const parsed = passkeyNameSchema.min(1).safeParse(name);
                      if (!parsed.success) return setError("Enter a name (max 64 characters).");
                      void act(async () => {
                        await api(`/account/passkeys/${p.id}`, {
                          method: "PATCH",
                          body: { friendly_name: parsed.data },
                        });
                        setEditing(null);
                      });
                    }}
                  >
                    <Input
                      aria-label="Passkey name"
                      value={name}
                      maxLength={64}
                      onChange={(e) => setName(e.target.value)}
                    />
                    <Button type="submit" size="sm" disabled={busy}>
                      Save
                    </Button>
                  </form>
                ) : (
                  <>
                    <p className="flex items-center gap-2 font-medium">
                      {p.friendly_name}
                      {p.backup_state && <Badge variant="secondary">Synced</Badge>}
                    </p>
                    <p className="text-xs text-muted-foreground">
                      Added {fmt.format(new Date(p.created_at))}
                      {p.last_used_at && ` · Last used ${fmt.format(new Date(p.last_used_at))}`}
                    </p>
                  </>
                )}
              </div>
              <Button
                variant="ghost"
                size="icon"
                aria-label={`Rename ${p.friendly_name}`}
                onClick={() => {
                  setEditing(p.id);
                  setName(p.friendly_name);
                }}
              >
                <Pencil />
              </Button>
              <Button
                variant="ghost"
                size="icon"
                aria-label={`Remove ${p.friendly_name}`}
                disabled={busy}
                onClick={() => {
                  if (
                    !window.confirm(`Remove "${p.friendly_name}"? It will no longer sign you in.`)
                  )
                    return;
                  void act(() =>
                    runWithStepUp(() => api(`/account/passkeys/${p.id}`, { method: "DELETE" })),
                  );
                }}
              >
                <Trash2 />
              </Button>
            </li>
          ))}
        </ul>
        <form
          className="flex gap-2"
          onSubmit={(e) => {
            e.preventDefault();
            void act(async () => {
              await runWithStepUp(() => addPasskey(newName.trim()));
              setNewName("");
            });
          }}
        >
          <Input
            aria-label="New passkey name"
            placeholder="Name for a new passkey (optional)"
            value={newName}
            maxLength={64}
            onChange={(e) => setNewName(e.target.value)}
          />
          <Button type="submit" disabled={busy}>
            Add passkey
          </Button>
        </form>
        <FormError message={error} />
      </CardContent>
    </Card>
  );
}
