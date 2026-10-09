"use client";

import { useRouter } from "next/navigation";
import { useEffect, useState } from "react";
import { KeyRound } from "lucide-react";
import { FormError } from "@/components/form-message";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { api, ApiError, type Account } from "@/lib/api";

const dateFormat = new Intl.DateTimeFormat(undefined, { dateStyle: "medium", timeStyle: "short" });

export default function AccountPage() {
  const router = useRouter();
  const [account, setAccount] = useState<Account | null>(null);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    api<Account>("/account").then(setAccount, (err: unknown) => {
      if (err instanceof ApiError && err.status === 401) router.replace("/signin");
      else setError((err as Error).message);
    });
  }, [router]);

  async function signOut() {
    await api("/auth/logout", { method: "POST" });
    router.replace("/signin");
    router.refresh();
  }

  if (error) return <FormError message={error} />;
  if (!account) return <p className="text-muted-foreground">Loading…</p>;

  return (
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

      <Card>
        <CardHeader>
          <CardTitle>Passkeys</CardTitle>
          <CardDescription>Devices and password managers that can sign you in.</CardDescription>
        </CardHeader>
        <CardContent>
          <ul className="divide-y" data-testid="passkey-list">
            {account.passkeys.map((p) => (
              <li key={p.id} className="flex items-center gap-3 py-3">
                <KeyRound className="size-5 text-muted-foreground" aria-hidden />
                <div className="flex-1">
                  <p className="font-medium">{p.friendly_name}</p>
                  <p className="text-xs text-muted-foreground">
                    Added {dateFormat.format(new Date(p.created_at))}
                    {p.last_used_at &&
                      ` · Last used ${dateFormat.format(new Date(p.last_used_at))}`}
                    {p.backup_state && " · Synced"}
                  </p>
                </div>
              </li>
            ))}
          </ul>
        </CardContent>
      </Card>
    </div>
  );
}
