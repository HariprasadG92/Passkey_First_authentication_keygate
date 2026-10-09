"use client";

import { useRouter } from "next/navigation";
import { useEffect, useState } from "react";
import { FormError } from "@/components/form-message";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { api } from "@/lib/api";
import { describePasskeyError, registerFirstPasskey } from "@/lib/passkeys";
import { passkeyNameSchema } from "@/lib/validation";

type Step = "confirm" | "passkey" | "invalid";

export default function VerifyEmailPage() {
  const router = useRouter();
  const [token, setToken] = useState<string | null>(null);
  const [step, setStep] = useState<Step>("confirm");
  const [email, setEmail] = useState("");
  const [name, setName] = useState("");
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);

  useEffect(() => {
    // The token is in the URL fragment (#token=...), which browsers never send to servers.
    // Read it once, then remove it from the address bar and history.
    const value = new URLSearchParams(window.location.hash.slice(1)).get("token");
    window.history.replaceState(null, "", window.location.pathname);
    if (value) setToken(value);
    else setStep("invalid");
  }, []);

  // Consuming the link needs an explicit click: a link preview or a cross-site page
  // that merely loads this URL can't spend it.
  async function confirmEmail() {
    if (!token) return;
    setBusy(true);
    setError(null);
    try {
      const res = await api<{ email: string }>("/auth/email/verify", {
        method: "POST",
        body: { token },
      });
      setEmail(res.email);
      setStep("passkey");
    } catch (err) {
      setError((err as Error).message);
      setStep("invalid");
    } finally {
      setBusy(false);
    }
  }

  async function createPasskey(event: React.FormEvent) {
    event.preventDefault();
    const parsed = passkeyNameSchema.safeParse(name);
    if (!parsed.success) {
      setError(parsed.error.issues[0]?.message ?? "Invalid name.");
      return;
    }
    setBusy(true);
    setError(null);
    try {
      await registerFirstPasskey(parsed.data);
      router.push("/account");
    } catch (err) {
      setError(describePasskeyError(err));
    } finally {
      setBusy(false);
    }
  }

  return (
    <Card className="mx-auto max-w-md">
      {step === "confirm" && (
        <>
          <CardHeader>
            <CardTitle className="text-xl">Confirm your email</CardTitle>
            <CardDescription>Continue to verify your address and set up sign-in.</CardDescription>
          </CardHeader>
          <CardContent className="space-y-4">
            <FormError message={error} />
            <Button onClick={confirmEmail} className="w-full" disabled={busy || !token}>
              {busy ? "Confirming…" : "Confirm email"}
            </Button>
          </CardContent>
        </>
      )}
      {step === "passkey" && (
        <>
          <CardHeader>
            <CardTitle className="text-xl">Create your passkey</CardTitle>
            <CardDescription>
              {email} is confirmed. Now create a passkey with your fingerprint, face or device PIN.
              It&apos;s how you&apos;ll sign in.
            </CardDescription>
          </CardHeader>
          <CardContent>
            <form onSubmit={createPasskey} className="space-y-4">
              <div className="space-y-2">
                <Label htmlFor="name">Name this passkey (optional)</Label>
                <Input
                  id="name"
                  placeholder="e.g. MacBook Touch ID"
                  value={name}
                  maxLength={64}
                  onChange={(e) => setName(e.target.value)}
                />
              </div>
              <FormError message={error} />
              <Button type="submit" className="w-full" disabled={busy}>
                {busy ? "Waiting for your device…" : "Create passkey"}
              </Button>
            </form>
          </CardContent>
        </>
      )}
      {step === "invalid" && (
        <>
          <CardHeader>
            <CardTitle className="text-xl">Link not valid</CardTitle>
            <CardDescription>
              {error ?? "This link is invalid or has expired."} You can request a new one.
            </CardDescription>
          </CardHeader>
          <CardContent>
            <Button onClick={() => router.push("/signup")} className="w-full">
              Request a new link
            </Button>
          </CardContent>
        </>
      )}
    </Card>
  );
}
