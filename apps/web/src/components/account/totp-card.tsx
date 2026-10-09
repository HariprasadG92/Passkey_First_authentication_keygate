"use client";

import { useState } from "react";
import { FormError } from "@/components/form-message";
import { useStepUp } from "@/components/step-up";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { api, type TotpEnrolment } from "@/lib/api";
import { totpCodeSchema } from "@/lib/validation";

export function TotpCard({ enabled, onChange }: { enabled: boolean; onChange: () => void }) {
  const runWithStepUp = useStepUp();
  const [enrolment, setEnrolment] = useState<TotpEnrolment | null>(null);
  const [code, setCode] = useState("");
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);

  async function act(fn: () => Promise<unknown>) {
    setBusy(true);
    setError(null);
    try {
      await fn();
    } catch (err) {
      setError((err as Error).message);
    } finally {
      setBusy(false);
    }
  }

  return (
    <Card>
      <CardHeader>
        <CardTitle className="flex items-center gap-2">
          Authenticator app {enabled && <Badge>On</Badge>}
        </CardTitle>
        <CardDescription>
          A fallback for when you don&apos;t have a passkey device with you. Codes can be phished,
          so prefer passkeys whenever you can.
        </CardDescription>
      </CardHeader>
      <CardContent className="space-y-4">
        {enabled ? (
          <Button
            variant="outline"
            disabled={busy}
            onClick={() =>
              act(async () => {
                await runWithStepUp(() => api("/account/totp", { method: "DELETE" }));
                onChange();
              })
            }
          >
            Remove authenticator app
          </Button>
        ) : enrolment ? (
          <div className="space-y-4" data-testid="totp-enrolment">
            {/* eslint-disable-next-line @next/next/no-img-element -- data: URI from our API */}
            <img
              src={enrolment.qr_svg_data_uri}
              alt="QR code to scan with your authenticator app"
              className="size-48 rounded border bg-white"
            />
            <p className="text-sm">
              Can&apos;t scan? Enter this key:{" "}
              <code className="rounded bg-muted px-1 break-all" data-testid="totp-secret">
                {enrolment.secret}
              </code>
            </p>
            <form
              className="space-y-2"
              onSubmit={(e) => {
                e.preventDefault();
                const parsed = totpCodeSchema.safeParse(code);
                if (!parsed.success) return setError(parsed.error.issues[0]?.message ?? "");
                void act(async () => {
                  await runWithStepUp(() =>
                    api("/account/totp/confirm", { method: "POST", body: { code: parsed.data } }),
                  );
                  setEnrolment(null);
                  setCode("");
                  onChange();
                });
              }}
            >
              <Label htmlFor="totp-code">Enter the 6-digit code to finish</Label>
              <div className="flex gap-2">
                <Input
                  id="totp-code"
                  inputMode="numeric"
                  autoComplete="one-time-code"
                  maxLength={6}
                  value={code}
                  onChange={(e) => setCode(e.target.value)}
                />
                <Button type="submit" disabled={busy}>
                  Turn on
                </Button>
              </div>
            </form>
          </div>
        ) : (
          <Button
            disabled={busy}
            onClick={() =>
              act(async () =>
                setEnrolment(
                  await runWithStepUp(() =>
                    api<TotpEnrolment>("/account/totp/setup", { method: "POST" }),
                  ),
                ),
              )
            }
          >
            Set up authenticator app
          </Button>
        )}
        <FormError message={error} />
      </CardContent>
    </Card>
  );
}
