"use client";

import { useEffect, useState } from "react";
import { ShieldCheck } from "lucide-react";
import { FormError } from "@/components/form-message";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { api, ApiError } from "@/lib/api";

type Details = {
  client_name: string;
  client_id: string;
  redirect_host: string;
  scopes: { name: string; description: string }[];
};

/** OpenID Connect consent: which app, where it sends you back, and exactly what it gets. */
export default function ConsentPage() {
  const [requestId, setRequestId] = useState<string | null>(null);
  const [details, setDetails] = useState<Details | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);

  useEffect(() => {
    const id = new URLSearchParams(window.location.hash.slice(1)).get("request");
    window.history.replaceState(null, "", window.location.pathname);
    if (!id) return setError("This sign-in request is invalid.");
    setRequestId(id);
    api<Details>("/oauth2/consent/details", { method: "POST", body: { request_id: id } }).then(
      setDetails,
      (err: unknown) =>
        setError(
          err instanceof ApiError && err.status === 401
            ? "Your session ended. Go back to the app and sign in again."
            : (err as Error).message,
        ),
    );
  }, []);

  async function decide(approve: boolean) {
    setBusy(true);
    setError(null);
    try {
      const { redirect_to } = await api<{ redirect_to: string }>("/oauth2/consent", {
        method: "POST",
        body: { request_id: requestId, approve },
      });
      window.location.assign(redirect_to);
    } catch (err) {
      setError((err as Error).message);
      setBusy(false);
    }
  }

  return (
    <Card className="mx-auto max-w-md">
      <CardHeader>
        <CardTitle className="flex items-center gap-2 text-xl">
          <ShieldCheck className="size-5" aria-hidden />
          {details ? `${details.client_name} wants to use your Keygate account` : "Authorize app"}
        </CardTitle>
        {details && (
          <CardDescription>
            You&apos;ll be sent back to <strong>{details.redirect_host}</strong>.
          </CardDescription>
        )}
      </CardHeader>
      <CardContent className="space-y-4">
        {details && (
          <ul className="space-y-2 text-sm" data-testid="consent-scopes">
            {details.scopes.map((s) => (
              <li key={s.name} className="flex gap-2">
                <span aria-hidden>•</span>
                <span>
                  {s.description} <code className="text-xs text-muted-foreground">{s.name}</code>
                </span>
              </li>
            ))}
          </ul>
        )}
        <FormError message={error} />
        <div className="flex gap-2">
          <Button onClick={() => decide(true)} disabled={!details || busy}>
            Allow
          </Button>
          <Button variant="outline" onClick={() => decide(false)} disabled={!details || busy}>
            Deny
          </Button>
        </div>
      </CardContent>
    </Card>
  );
}
