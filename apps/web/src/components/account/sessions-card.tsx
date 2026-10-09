"use client";

import { useCallback, useEffect, useState } from "react";
import { FormError } from "@/components/form-message";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { api, type ActiveSession } from "@/lib/api";

const fmt = new Intl.DateTimeFormat(undefined, { dateStyle: "medium", timeStyle: "short" });

function describeDevice(ua: string | null): string {
  if (!ua) return "Unknown device";
  const browser = /Edg\//.test(ua)
    ? "Edge"
    : /Chrome\//.test(ua)
      ? "Chrome"
      : /Firefox\//.test(ua)
        ? "Firefox"
        : /Safari\//.test(ua)
          ? "Safari"
          : "Browser";
  const os = /Windows/.test(ua)
    ? "Windows"
    : /Mac OS X/.test(ua)
      ? "macOS"
      : /Android/.test(ua)
        ? "Android"
        : /iPhone|iPad/.test(ua)
          ? "iOS"
          : /Linux/.test(ua)
            ? "Linux"
            : "";
  return os ? `${browser} on ${os}` : browser;
}

export function SessionsCard() {
  const [sessions, setSessions] = useState<ActiveSession[]>([]);
  const [error, setError] = useState<string | null>(null);

  const load = useCallback(() => {
    api<ActiveSession[]>("/account/sessions").then(setSessions, (e: Error) => setError(e.message));
  }, []);
  useEffect(load, [load]);

  async function act(fn: () => Promise<unknown>) {
    setError(null);
    try {
      await fn();
      load();
    } catch (err) {
      setError((err as Error).message);
    }
  }

  return (
    <Card>
      <CardHeader>
        <CardTitle>Where you&apos;re signed in</CardTitle>
        <CardDescription>Sign out of any session you don&apos;t recognise.</CardDescription>
      </CardHeader>
      <CardContent className="space-y-4">
        <ul className="divide-y" data-testid="session-list">
          {sessions.map((s) => (
            <li key={s.id} className="flex items-center gap-3 py-3">
              <div className="flex-1">
                <p className="flex items-center gap-2 font-medium">
                  {describeDevice(s.user_agent)}
                  {s.current && <Badge>This device</Badge>}
                </p>
                <p className="text-xs text-muted-foreground">
                  {s.ip_address ?? "unknown IP"} · signed in with {s.auth_method.replace("_", " ")}{" "}
                  · active {fmt.format(new Date(s.last_seen_at))}
                </p>
              </div>
              {!s.current && (
                <Button
                  variant="outline"
                  size="sm"
                  onClick={() => act(() => api(`/account/sessions/${s.id}`, { method: "DELETE" }))}
                >
                  Sign out
                </Button>
              )}
            </li>
          ))}
        </ul>
        {sessions.length > 1 && (
          <Button
            variant="outline"
            onClick={() => act(() => api("/account/sessions/revoke-others", { method: "POST" }))}
          >
            Sign out everywhere else
          </Button>
        )}
        <FormError message={error} />
      </CardContent>
    </Card>
  );
}
