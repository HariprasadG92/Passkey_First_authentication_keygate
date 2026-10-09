"use client";

import { useState } from "react";
import { FormError } from "@/components/form-message";
import { useStepUp } from "@/components/step-up";
import { Alert, AlertDescription } from "@/components/ui/alert";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { api } from "@/lib/api";

export function RecoveryCard({ remaining, onChange }: { remaining: number; onChange: () => void }) {
  const runWithStepUp = useStepUp();
  const [codes, setCodes] = useState<string[] | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);

  async function generate() {
    if (
      remaining > 0 &&
      !window.confirm("Generate new codes? Your current codes will stop working.")
    )
      return;
    setBusy(true);
    setError(null);
    try {
      const res = await runWithStepUp(() =>
        api<{ codes: string[] }>("/account/recovery-codes", { method: "POST" }),
      );
      setCodes(res.codes);
      onChange();
    } catch (err) {
      setError((err as Error).message);
    } finally {
      setBusy(false);
    }
  }

  const download = () => {
    const text = `Keygate recovery codes (each works once)\n\n${codes?.join("\n")}\n`;
    const a = document.createElement("a");
    a.href = `data:text/plain;charset=utf-8,${encodeURIComponent(text)}`;
    a.download = "keygate-recovery-codes.txt";
    a.click();
  };

  return (
    <Card>
      <CardHeader>
        <CardTitle>Recovery codes</CardTitle>
        <CardDescription>
          Single-use codes to get back in if you lose all your devices.{" "}
          <span data-testid="recovery-remaining">{remaining}</span> unused.
        </CardDescription>
      </CardHeader>
      <CardContent className="space-y-4">
        {codes && (
          <Alert>
            <AlertDescription className="space-y-3">
              <p className="font-medium">Save these now. They won&apos;t be shown again.</p>
              <ul className="grid grid-cols-2 gap-1 font-mono text-sm" data-testid="recovery-codes">
                {codes.map((c) => (
                  <li key={c}>{c}</li>
                ))}
              </ul>
              <div className="flex gap-2">
                <Button size="sm" variant="outline" onClick={download}>
                  Download
                </Button>
                <Button
                  size="sm"
                  variant="outline"
                  onClick={() => navigator.clipboard.writeText(codes.join("\n"))}
                >
                  Copy
                </Button>
                <Button size="sm" onClick={() => setCodes(null)}>
                  I&apos;ve saved them
                </Button>
              </div>
            </AlertDescription>
          </Alert>
        )}
        <Button variant={remaining > 0 ? "outline" : "default"} disabled={busy} onClick={generate}>
          {remaining > 0 ? "Generate new codes" : "Generate recovery codes"}
        </Button>
        <FormError message={error} />
      </CardContent>
    </Card>
  );
}
