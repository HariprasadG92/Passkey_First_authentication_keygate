"use client";

import { useRouter } from "next/navigation";
import { useState } from "react";
import { FormError } from "@/components/form-message";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { api } from "@/lib/api";
import { emailSchema, recoveryCodeSchema, totpCodeSchema } from "@/lib/validation";

type Mode = "totp" | "recovery";

const COPY: Record<Mode, { label: string; endpoint: string; button: string; hint: string }> = {
  totp: {
    label: "Authenticator code",
    endpoint: "/auth/totp/login",
    button: "Sign in with code",
    hint: "The 6-digit code from your authenticator app.",
  },
  recovery: {
    label: "Recovery code",
    endpoint: "/auth/recovery/login",
    button: "Sign in with recovery code",
    hint: "Each recovery code works once. Add a new passkey after signing in.",
  },
};

export function CodeSignIn({ mode, onSuccess }: { mode: Mode; onSuccess?: () => void }) {
  const router = useRouter();
  const [email, setEmail] = useState("");
  const [code, setCode] = useState("");
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  const copy = COPY[mode];

  async function onSubmit(event: React.FormEvent) {
    event.preventDefault();
    const parsedEmail = emailSchema.safeParse(email);
    const parsedCode = (mode === "totp" ? totpCodeSchema : recoveryCodeSchema).safeParse(code);
    if (!parsedEmail.success || !parsedCode.success) {
      setError(
        parsedEmail.error?.issues[0]?.message ??
          parsedCode.error?.issues[0]?.message ??
          "Check your input.",
      );
      return;
    }
    setBusy(true);
    setError(null);
    try {
      await api(copy.endpoint, {
        method: "POST",
        body: { email: parsedEmail.data, code: parsedCode.data },
      });
      if (onSuccess) onSuccess();
      else router.push("/account");
    } catch (err) {
      setError((err as Error).message);
    } finally {
      setBusy(false);
    }
  }

  return (
    <form onSubmit={onSubmit} className="space-y-3" noValidate data-testid={`${mode}-form`}>
      <div className="space-y-2">
        <Label htmlFor={`${mode}-email`}>Email</Label>
        <Input
          id={`${mode}-email`}
          type="email"
          autoComplete="username"
          value={email}
          onChange={(e) => setEmail(e.target.value)}
        />
      </div>
      <div className="space-y-2">
        <Label htmlFor={`${mode}-code`}>{copy.label}</Label>
        <Input
          id={`${mode}-code`}
          inputMode={mode === "totp" ? "numeric" : "text"}
          autoComplete="one-time-code"
          value={code}
          onChange={(e) => setCode(e.target.value)}
        />
        <p className="text-xs text-muted-foreground">{copy.hint}</p>
      </div>
      <FormError message={error} />
      <Button type="submit" variant="outline" className="w-full" disabled={busy}>
        {copy.button}
      </Button>
    </form>
  );
}
