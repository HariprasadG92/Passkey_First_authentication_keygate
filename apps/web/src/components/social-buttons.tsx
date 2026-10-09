"use client";

import { useEffect, useState } from "react";
import { Button } from "@/components/ui/button";
import { listProviders, startSocial, type SocialProvider } from "@/lib/social";

export function SocialButtons({ onError }: { onError: (message: string) => void }) {
  const [providers, setProviders] = useState<SocialProvider[]>([]);
  const [busy, setBusy] = useState(false);

  useEffect(() => {
    listProviders().then(setProviders, () => setProviders([]));
  }, []);

  if (providers.length === 0) return null;
  return (
    <div className="space-y-2" data-testid="social-buttons">
      {providers.map((p) => (
        <Button
          key={p.id}
          variant="outline"
          className="w-full"
          disabled={busy}
          onClick={async () => {
            setBusy(true);
            try {
              await startSocial(p.id, "signin");
            } catch (err) {
              onError((err as Error).message);
              setBusy(false);
            }
          }}
        >
          Continue with {p.name}
        </Button>
      ))}
    </div>
  );
}
