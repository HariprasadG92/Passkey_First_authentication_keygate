"use client";

import { useRouter } from "next/navigation";
import { useEffect, useState } from "react";
import { FormError } from "@/components/form-message";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { api, ApiError } from "@/lib/api";

export default function ConfirmEmailChangePage() {
  const router = useRouter();
  const [token, setToken] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);

  useEffect(() => {
    const value = new URLSearchParams(window.location.hash.slice(1)).get("token");
    window.history.replaceState(null, "", window.location.pathname);
    if (value) setToken(value);
    else setError("This link is invalid.");
  }, []);

  async function confirm() {
    if (!token) return;
    setBusy(true);
    setError(null);
    try {
      await api("/account/email/confirm", { method: "POST", body: { token } });
      router.push("/account");
    } catch (err) {
      if (err instanceof ApiError && err.status === 401)
        setError("Sign in to the account that requested this change, then open the link again.");
      else setError((err as Error).message);
    } finally {
      setBusy(false);
    }
  }

  return (
    <Card className="mx-auto max-w-md">
      <CardHeader>
        <CardTitle className="text-xl">Confirm new email</CardTitle>
        <CardDescription>You must be signed in to the account that asked for this.</CardDescription>
      </CardHeader>
      <CardContent className="space-y-4">
        <FormError message={error} />
        <Button className="w-full" onClick={confirm} disabled={busy || !token}>
          Confirm new email
        </Button>
      </CardContent>
    </Card>
  );
}
