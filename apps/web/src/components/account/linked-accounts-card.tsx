"use client";

import { useEffect, useState } from "react";
import { FormError } from "@/components/form-message";
import { useStepUp } from "@/components/step-up";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { api, type LinkedSocial } from "@/lib/api";
import { listProviders, startSocial, type SocialProvider } from "@/lib/social";

export function LinkedAccountsCard({
  linked,
  onChange,
}: {
  linked: LinkedSocial[];
  onChange: () => void;
}) {
  const runWithStepUp = useStepUp();
  const [providers, setProviders] = useState<SocialProvider[]>([]);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    listProviders().then(setProviders, () => setProviders([]));
  }, []);

  if (providers.length === 0 && linked.length === 0) return null;
  const linkable = providers.filter((p) => !linked.some((l) => l.provider === p.id));

  return (
    <Card>
      <CardHeader>
        <CardTitle>Linked accounts</CardTitle>
        <CardDescription>
          Sign in with an account you already have at another service.
        </CardDescription>
      </CardHeader>
      <CardContent className="space-y-4">
        {linked.length > 0 && (
          <ul className="divide-y" data-testid="linked-list">
            {linked.map((l) => (
              <li key={l.id} className="flex items-center gap-3 py-3">
                <div className="flex-1">
                  <p className="font-medium capitalize">{l.provider}</p>
                  <p className="text-xs text-muted-foreground">
                    {l.display_name} · {l.email}
                  </p>
                </div>
                <Button
                  variant="outline"
                  size="sm"
                  onClick={async () => {
                    setError(null);
                    try {
                      await runWithStepUp(() =>
                        api(`/account/social/${l.id}`, { method: "DELETE" }),
                      );
                      onChange();
                    } catch (err) {
                      setError((err as Error).message);
                    }
                  }}
                >
                  Unlink
                </Button>
              </li>
            ))}
          </ul>
        )}
        <div className="flex flex-wrap gap-2">
          {linkable.map((p) => (
            <Button
              key={p.id}
              variant="outline"
              onClick={async () => {
                setError(null);
                try {
                  await runWithStepUp(() => startSocial(p.id, "link"));
                } catch (err) {
                  setError((err as Error).message);
                }
              }}
            >
              Link {p.name}
            </Button>
          ))}
        </div>
        <FormError message={error} />
      </CardContent>
    </Card>
  );
}
