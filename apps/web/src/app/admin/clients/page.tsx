"use client";

import { useCallback, useEffect, useState } from "react";
import { FormError } from "@/components/form-message";
import { RequirePermission } from "@/components/require-permission";
import { StepUpProvider, useStepUp } from "@/components/step-up";
import { Alert, AlertDescription } from "@/components/ui/alert";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { api } from "@/lib/api";

type OAuthClient = {
  id: string;
  client_id: string;
  name: string;
  confidential: boolean;
  redirect_uris: string[];
  post_logout_redirect_uris: string[];
  allowed_scopes: string[];
  disabled: boolean;
};

const SCOPES = ["openid", "profile", "email", "notes:read", "notes:write"];
const lines = (v: string) => v.split(/\s+/).filter(Boolean);

function Clients() {
  const runWithStepUp = useStepUp();
  const [clients, setClients] = useState<OAuthClient[]>([]);
  const [secret, setSecret] = useState<{ clientId: string; secret: string } | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [form, setForm] = useState({
    name: "",
    confidential: true,
    redirects: "",
    logoutRedirects: "",
    scopes: ["openid", "profile", "email"],
  });

  const load = useCallback(() => {
    api<OAuthClient[]>("/admin/clients").then(setClients, (e: Error) => setError(e.message));
  }, []);
  useEffect(load, [load]);

  async function act<T>(fn: () => Promise<T>): Promise<T | undefined> {
    setError(null);
    try {
      const result = await runWithStepUp(fn);
      load();
      return result;
    } catch (err) {
      setError((err as Error).message);
      return undefined;
    }
  }

  return (
    <div className="space-y-6">
      <h1 className="text-2xl font-bold">Apps (OpenID Connect clients)</h1>
      {secret && (
        <Alert>
          <AlertDescription className="space-y-2">
            <p className="font-medium">
              Client secret for <code>{secret.clientId}</code>. Copy it now: it won&apos;t be shown
              again.
            </p>
            <code className="block rounded bg-muted p-2 break-all" data-testid="client-secret">
              {secret.secret}
            </code>
            <Button size="sm" onClick={() => setSecret(null)}>
              Done
            </Button>
          </AlertDescription>
        </Alert>
      )}
      <FormError message={error} />

      <Card>
        <CardHeader>
          <CardTitle>Register an app</CardTitle>
        </CardHeader>
        <CardContent>
          <form
            className="space-y-3"
            onSubmit={async (e) => {
              e.preventDefault();
              const created = await act(() =>
                api<OAuthClient & { client_secret: string | null }>("/admin/clients", {
                  method: "POST",
                  body: {
                    name: form.name,
                    confidential: form.confidential,
                    redirect_uris: lines(form.redirects),
                    post_logout_redirect_uris: lines(form.logoutRedirects),
                    allowed_scopes: form.scopes,
                  },
                }),
              );
              if (created?.client_secret)
                setSecret({ clientId: created.client_id, secret: created.client_secret });
            }}
          >
            <div className="space-y-1">
              <Label htmlFor="c-name">Name</Label>
              <Input
                id="c-name"
                value={form.name}
                onChange={(e) => setForm({ ...form, name: e.target.value })}
              />
            </div>
            <div className="space-y-1">
              <Label htmlFor="c-redirects">Redirect URIs (one per line, exact match)</Label>
              <textarea
                id="c-redirects"
                className="w-full rounded-md border bg-background p-2 font-mono text-sm"
                rows={2}
                value={form.redirects}
                onChange={(e) => setForm({ ...form, redirects: e.target.value })}
              />
            </div>
            <div className="space-y-1">
              <Label htmlFor="c-logout">Post-logout redirect URIs</Label>
              <textarea
                id="c-logout"
                className="w-full rounded-md border bg-background p-2 font-mono text-sm"
                rows={1}
                value={form.logoutRedirects}
                onChange={(e) => setForm({ ...form, logoutRedirects: e.target.value })}
              />
            </div>
            <fieldset className="flex flex-wrap gap-4 text-sm">
              <legend className="mb-1 text-sm font-medium">Allowed scopes</legend>
              {SCOPES.map((s) => (
                <label key={s} className="flex items-center gap-1">
                  <input
                    type="checkbox"
                    checked={form.scopes.includes(s)}
                    disabled={s === "openid"}
                    onChange={(e) =>
                      setForm({
                        ...form,
                        scopes: e.target.checked
                          ? [...form.scopes, s]
                          : form.scopes.filter((x) => x !== s),
                      })
                    }
                  />
                  {s}
                </label>
              ))}
            </fieldset>
            <label className="flex items-center gap-2 text-sm">
              <input
                type="checkbox"
                checked={!form.confidential}
                onChange={(e) => setForm({ ...form, confidential: !e.target.checked })}
              />
              Public client (SPA/mobile: no secret, PKCE only)
            </label>
            <Button type="submit">Register</Button>
          </form>
        </CardContent>
      </Card>

      <ul className="space-y-3" data-testid="client-list">
        {clients.map((c) => (
          <li key={c.id}>
            <Card>
              <CardContent className="space-y-2 pt-4 text-sm">
                <p className="flex items-center gap-2 font-medium">
                  {c.name} <code className="text-xs">{c.client_id}</code>
                  <Badge variant="secondary">{c.confidential ? "confidential" : "public"}</Badge>
                  {c.disabled && <Badge variant="destructive">disabled</Badge>}
                </p>
                <p className="font-mono text-xs break-all">{c.redirect_uris.join("  ")}</p>
                <p className="text-xs text-muted-foreground">{c.allowed_scopes.join(" ")}</p>
                {!c.disabled && (
                  <div className="flex gap-2">
                    {c.confidential && (
                      <Button
                        size="sm"
                        variant="outline"
                        onClick={async () => {
                          const r = await act(() =>
                            api<{ client_id: string; client_secret: string }>(
                              `/admin/clients/${c.id}/secret`,
                              { method: "POST" },
                            ),
                          );
                          if (r) setSecret({ clientId: r.client_id, secret: r.client_secret });
                        }}
                      >
                        Rotate secret
                      </Button>
                    )}
                    <Button
                      size="sm"
                      variant="outline"
                      onClick={() =>
                        act(() => api(`/admin/clients/${c.id}/disable`, { method: "POST" }))
                      }
                    >
                      Disable
                    </Button>
                  </div>
                )}
              </CardContent>
            </Card>
          </li>
        ))}
      </ul>
    </div>
  );
}

export default function ClientsPage() {
  return (
    <RequirePermission permission="clients:read">
      {() => (
        <StepUpProvider totpEnabled={false}>
          <Clients />
        </StepUpProvider>
      )}
    </RequirePermission>
  );
}
