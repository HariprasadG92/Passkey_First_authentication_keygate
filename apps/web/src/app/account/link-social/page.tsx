"use client";

import { useRouter } from "next/navigation";
import { useEffect, useState } from "react";
import { FormError } from "@/components/form-message";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { api, isStepUpRequired } from "@/lib/api";

type Preview = { provider: string; email: string | null; display_name: string | null };

/** Explicit confirmation before a provider identity can sign in to this account. */
export default function LinkSocialPage() {
  const router = useRouter();
  const [pendingId, setPendingId] = useState<string | null>(null);
  const [preview, setPreview] = useState<Preview | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);

  useEffect(() => {
    const id = new URLSearchParams(window.location.hash.slice(1)).get("pending");
    window.history.replaceState(null, "", window.location.pathname);
    if (!id) {
      setError("This link request is invalid.");
      return;
    }
    setPendingId(id);
    api<Preview>("/account/social/pending", { method: "POST", body: { pending_id: id } }).then(
      setPreview,
      (err: unknown) =>
        setError(
          isStepUpRequired(err)
            ? "This request took too long. Start linking again from your account page."
            : (err as Error).message,
        ),
    );
  }, []);

  async function confirm() {
    setBusy(true);
    setError(null);
    try {
      await api("/account/social/confirm", { method: "POST", body: { pending_id: pendingId } });
      router.push("/account");
    } catch (err) {
      setError((err as Error).message);
    } finally {
      setBusy(false);
    }
  }

  return (
    <Card className="mx-auto max-w-md">
      <CardHeader>
        <CardTitle className="text-xl">Link account?</CardTitle>
        <CardDescription>
          After linking, this account can sign in to your Keygate account.
        </CardDescription>
      </CardHeader>
      <CardContent className="space-y-4">
        {preview && (
          <div className="rounded border p-3 text-sm" data-testid="link-preview">
            <p className="font-medium capitalize">{preview.provider}</p>
            <p>{preview.display_name}</p>
            <p className="text-muted-foreground">{preview.email}</p>
          </div>
        )}
        <FormError message={error} />
        <div className="flex gap-2">
          <Button onClick={confirm} disabled={!preview || busy}>
            Link this account
          </Button>
          <Button variant="outline" onClick={() => router.push("/account")}>
            Cancel
          </Button>
        </div>
      </CardContent>
    </Card>
  );
}
