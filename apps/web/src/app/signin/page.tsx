"use client";

import Link from "next/link";
import { useRouter } from "next/navigation";
import { useEffect, useState } from "react";
import { Fingerprint } from "lucide-react";
import { CodeSignIn } from "@/components/code-sign-in";
import { FormError } from "@/components/form-message";
import { SocialButtons } from "@/components/social-buttons";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { describePasskeyError, signInWithPasskey } from "@/lib/passkeys";
import { SOCIAL_ERRORS } from "@/lib/social";
import { emailSchema } from "@/lib/validation";

export default function SignInPage() {
  const router = useRouter();
  const [email, setEmail] = useState("");
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  const [alt, setAlt] = useState<"totp" | "recovery" | null>(null);

  // Errors passed back from a social-login redirect (?error=...).
  useEffect(() => {
    const code = new URLSearchParams(window.location.search).get("error");
    if (code) {
      setError(SOCIAL_ERRORS[code] ?? SOCIAL_ERRORS.social_failed);
      window.history.replaceState(null, "", "/signin");
    }
  }, []);

  async function run(withEmail?: string) {
    setBusy(true);
    setError(null);
    try {
      await signInWithPasskey(withEmail);
      router.push("/account");
    } catch (err) {
      setError(describePasskeyError(err));
    } finally {
      setBusy(false);
    }
  }

  function onEmailSubmit(event: React.FormEvent) {
    event.preventDefault();
    const parsed = emailSchema.safeParse(email);
    if (!parsed.success) {
      setError(parsed.error.issues[0]?.message ?? "Enter a valid email address.");
      return;
    }
    void run(parsed.data);
  }

  return (
    <Card className="mx-auto max-w-md">
      <CardHeader>
        <CardTitle className="text-xl">Sign in</CardTitle>
        <CardDescription>Use the passkey saved on your device or password manager.</CardDescription>
      </CardHeader>
      <CardContent className="space-y-6">
        <Button onClick={() => run()} className="w-full" disabled={busy}>
          <Fingerprint aria-hidden />
          {busy ? "Waiting for your device…" : "Sign in with a passkey"}
        </Button>

        <div className="flex items-center gap-3 text-xs text-muted-foreground">
          <span className="h-px flex-1 bg-current opacity-20" />
          or use your email
          <span className="h-px flex-1 bg-current opacity-20" />
        </div>

        <form onSubmit={onEmailSubmit} className="space-y-4" noValidate>
          <div className="space-y-2">
            <Label htmlFor="email">Email</Label>
            <Input
              id="email"
              type="email"
              autoComplete="username webauthn"
              value={email}
              onChange={(e) => setEmail(e.target.value)}
            />
          </div>
          <Button type="submit" variant="outline" className="w-full" disabled={busy}>
            Continue
          </Button>
        </form>

        <SocialButtons onError={setError} />

        <FormError message={error} />

        <div className="space-y-3 border-t pt-4">
          <p className="text-sm text-muted-foreground">Can&apos;t use a passkey right now?</p>
          <div className="flex flex-wrap gap-2">
            <Button
              variant={alt === "totp" ? "secondary" : "ghost"}
              size="sm"
              onClick={() => setAlt(alt === "totp" ? null : "totp")}
            >
              Use authenticator app
            </Button>
            <Button
              variant={alt === "recovery" ? "secondary" : "ghost"}
              size="sm"
              onClick={() => setAlt(alt === "recovery" ? null : "recovery")}
            >
              Use a recovery code
            </Button>
          </div>
          {alt && <CodeSignIn key={alt} mode={alt} />}
        </div>

        <p className="text-center text-sm text-muted-foreground">
          New here?{" "}
          <Link href="/signup" className="underline">
            Create an account
          </Link>
        </p>
      </CardContent>
    </Card>
  );
}
