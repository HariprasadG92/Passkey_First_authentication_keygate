"use client";

import { useRouter } from "next/navigation";
import { useCallback, useEffect, useState } from "react";
import { EmailCard } from "@/components/account/email-card";
import { PasskeysCard } from "@/components/account/passkeys-card";
import { RecoveryCard } from "@/components/account/recovery-card";
import { SessionsCard } from "@/components/account/sessions-card";
import { TotpCard } from "@/components/account/totp-card";
import { FormError } from "@/components/form-message";
import { StepUpProvider } from "@/components/step-up";
import { Button } from "@/components/ui/button";
import { api, ApiError, type Account } from "@/lib/api";

export default function AccountPage() {
  const router = useRouter();
  const [account, setAccount] = useState<Account | null>(null);
  const [error, setError] = useState<string | null>(null);

  const load = useCallback(() => {
    api<Account>("/account").then(setAccount, (err: unknown) => {
      if (err instanceof ApiError && err.status === 401) router.replace("/signin");
      else setError((err as Error).message);
    });
  }, [router]);
  useEffect(load, [load]);

  async function signOut() {
    await api("/auth/logout", { method: "POST" });
    router.replace("/signin");
    router.refresh();
  }

  if (error) return <FormError message={error} />;
  if (!account) return <p className="text-muted-foreground">Loading…</p>;

  return (
    <StepUpProvider totpEnabled={account.totp_enabled}>
      <div className="mx-auto max-w-2xl space-y-6">
        <div className="flex items-center justify-between">
          <div>
            <h1 className="text-2xl font-bold" data-testid="account-heading">
              Welcome, {account.user.display_name}
            </h1>
            <p className="text-sm text-muted-foreground">{account.user.email}</p>
          </div>
          <Button variant="outline" onClick={signOut}>
            Sign out
          </Button>
        </div>
        <PasskeysCard passkeys={account.passkeys} onChange={load} />
        <TotpCard enabled={account.totp_enabled} onChange={load} />
        <RecoveryCard remaining={account.recovery_codes_remaining} onChange={load} />
        <SessionsCard />
        <EmailCard email={account.user.email} />
      </div>
    </StepUpProvider>
  );
}
