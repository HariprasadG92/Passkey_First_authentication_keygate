"use client";

import { createContext, useCallback, useContext, useRef, useState } from "react";
import { ShieldCheck } from "lucide-react";
import { FormError } from "@/components/form-message";
import { Button } from "@/components/ui/button";
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogHeader,
  DialogTitle,
} from "@/components/ui/dialog";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { api, isStepUpRequired } from "@/lib/api";
import { describePasskeyError, stepUpWithPasskey } from "@/lib/passkeys";
import { startSocial } from "@/lib/social";
import { totpCodeSchema } from "@/lib/validation";

type RunWithStepUp = <T>(action: () => Promise<T>) => Promise<T>;

const StepUpContext = createContext<RunWithStepUp | null>(null);

/**
 * Sensitive actions may fail with `step_up_required`. `runWithStepUp(action)` catches that,
 * asks the user to re-authenticate (passkey or authenticator code), then retries the
 * action once.
 */
export function StepUpProvider({
  totpEnabled,
  socialProviders = [],
  children,
}: {
  totpEnabled: boolean;
  /** Linked providers that can confirm identity (leaves the page; the user retries after). */
  socialProviders?: { id: string; name: string }[];
  children: React.ReactNode;
}) {
  const [open, setOpen] = useState(false);
  const [code, setCode] = useState("");
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  const pending = useRef<{ resolve: () => void; reject: (e: unknown) => void } | null>(null);

  const waitForStepUp = () =>
    new Promise<void>((resolve, reject) => {
      pending.current = { resolve, reject };
      setError(null);
      setCode("");
      setOpen(true);
    });

  const runWithStepUp = useCallback<RunWithStepUp>(async (action) => {
    try {
      return await action();
    } catch (err) {
      if (!isStepUpRequired(err)) throw err;
      await waitForStepUp();
      return action();
    }
  }, []);

  async function finish(step: () => Promise<void>, describe: (e: unknown) => string) {
    setBusy(true);
    setError(null);
    try {
      await step();
      setOpen(false);
      pending.current?.resolve();
      pending.current = null;
    } catch (err) {
      setError(describe(err));
    } finally {
      setBusy(false);
    }
  }

  function cancel(next: boolean) {
    if (next) return;
    setOpen(false);
    pending.current?.reject(new Error("Confirmation cancelled."));
    pending.current = null;
  }

  return (
    <StepUpContext.Provider value={runWithStepUp}>
      {children}
      <Dialog open={open} onOpenChange={cancel}>
        <DialogContent>
          <DialogHeader>
            <DialogTitle className="flex items-center gap-2">
              <ShieldCheck className="size-5" aria-hidden /> Confirm it&apos;s you
            </DialogTitle>
            <DialogDescription>
              This is a sensitive change. Re-authenticate to continue.
            </DialogDescription>
          </DialogHeader>
          <Button
            onClick={() => finish(stepUpWithPasskey, describePasskeyError)}
            disabled={busy}
            className="w-full"
          >
            Use a passkey
          </Button>
          {socialProviders.map((p) => (
            <Button
              key={p.id}
              variant="outline"
              className="w-full"
              disabled={busy}
              onClick={() =>
                finish(
                  () => startSocial(p.id, "stepup"),
                  (e) => (e as Error).message,
                )
              }
            >
              Continue with {p.name}
            </Button>
          ))}
          {totpEnabled && (
            <form
              className="space-y-2"
              onSubmit={(e) => {
                e.preventDefault();
                const parsed = totpCodeSchema.safeParse(code);
                if (!parsed.success) {
                  setError(parsed.error.issues[0]?.message ?? "Invalid code.");
                  return;
                }
                void finish(
                  () => api("/auth/step-up/totp", { method: "POST", body: { code: parsed.data } }),
                  (e) => (e as Error).message,
                );
              }}
            >
              <Label htmlFor="stepup-code">Or enter an authenticator code</Label>
              <div className="flex gap-2">
                <Input
                  id="stepup-code"
                  inputMode="numeric"
                  autoComplete="one-time-code"
                  maxLength={6}
                  value={code}
                  onChange={(e) => setCode(e.target.value)}
                />
                <Button type="submit" variant="outline" disabled={busy}>
                  Verify
                </Button>
              </div>
            </form>
          )}
          <FormError message={error} />
        </DialogContent>
      </Dialog>
    </StepUpContext.Provider>
  );
}

export function useStepUp(): RunWithStepUp {
  const ctx = useContext(StepUpContext);
  if (!ctx) throw new Error("useStepUp must be used inside <StepUpProvider>");
  return ctx;
}
