"use client";

import { useState } from "react";
import { FormError } from "@/components/form-message";
import { useStepUp } from "@/components/step-up";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Input } from "@/components/ui/input";
import { api } from "@/lib/api";
import { emailSchema } from "@/lib/validation";

export function EmailCard({ email }: { email: string }) {
  const runWithStepUp = useStepUp();
  const [value, setValue] = useState("");
  const [message, setMessage] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);

  return (
    <Card>
      <CardHeader>
        <CardTitle>Email address</CardTitle>
        <CardDescription>
          Currently <strong>{email}</strong>. We&apos;ll ask you to confirm the new address.
        </CardDescription>
      </CardHeader>
      <CardContent className="space-y-4">
        <form
          className="flex gap-2"
          noValidate
          onSubmit={async (e) => {
            e.preventDefault();
            setError(null);
            const parsed = emailSchema.safeParse(value);
            if (!parsed.success) return setError(parsed.error.issues[0]?.message ?? "");
            try {
              const res = await runWithStepUp(() =>
                api<{ message: string }>("/account/email", {
                  method: "POST",
                  body: { new_email: parsed.data },
                }),
              );
              setMessage(res.message);
              setValue("");
            } catch (err) {
              setError((err as Error).message);
            }
          }}
        >
          <Input
            type="email"
            aria-label="New email address"
            placeholder="new@example.com"
            value={value}
            onChange={(e) => setValue(e.target.value)}
          />
          <Button type="submit" variant="outline">
            Change
          </Button>
        </form>
        {message && <p className="text-sm">{message}</p>}
        <FormError message={error} />
      </CardContent>
    </Card>
  );
}
