"use client";

import { useEffect, useState } from "react";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";

const MESSAGES: Record<string, string> = {
  invalid_client: "The app that sent you here isn't registered with Keygate (or was disabled).",
  invalid_redirect_uri:
    "The app asked to send you back to an address it hasn't registered. For your safety, Keygate won't follow it.",
};

/** Shown instead of redirecting when the client or redirect URI can't be trusted. */
export default function OAuthErrorPage() {
  const [code, setCode] = useState<string | null>(null);
  useEffect(() => setCode(new URLSearchParams(window.location.search).get("error")), []);

  return (
    <Card className="mx-auto max-w-md">
      <CardHeader>
        <CardTitle className="text-xl">Can&apos;t continue to the app</CardTitle>
        <CardDescription data-testid="oauth-error">
          {(code && MESSAGES[code]) ?? "This sign-in request is invalid."}
        </CardDescription>
      </CardHeader>
      <CardContent className="text-sm text-muted-foreground">
        If you&apos;re the app&apos;s developer, check its client ID and registered redirect URIs.
      </CardContent>
    </Card>
  );
}
