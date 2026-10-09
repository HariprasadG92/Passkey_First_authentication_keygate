"use client";

import { useCallback, useEffect, useState } from "react";
import { FormError } from "@/components/form-message";
import { RequirePermission } from "@/components/require-permission";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { api, type AuditEvent } from "@/lib/api";

const fmt = new Intl.DateTimeFormat(undefined, { dateStyle: "short", timeStyle: "medium" });
const SEVERITY_VARIANT = { info: "secondary", warning: "outline", high: "destructive" } as const;

function AuditLog() {
  const [eventType, setEventType] = useState("");
  const [severity, setSeverity] = useState("");
  const [result, setResult] = useState("");
  const [userId, setUserId] = useState("");
  const [events, setEvents] = useState<AuditEvent[]>([]);
  const [cursor, setCursor] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);

  const fetchPage = useCallback(
    async (after: string | null) => {
      const params = new URLSearchParams({ limit: "50" });
      if (eventType.trim()) params.set("event_type", eventType.trim());
      if (severity) params.set("severity", severity);
      if (result) params.set("result", result);
      if (userId.trim()) params.set("user_id", userId.trim());
      if (after) params.set("cursor", after);
      try {
        const page = await api<{ items: AuditEvent[]; next_cursor: string | null }>(
          `/admin/audit?${params}`,
        );
        setEvents((prev) => (after ? [...prev, ...page.items] : page.items));
        setCursor(page.next_cursor);
        setError(null);
      } catch (err) {
        setError((err as Error).message);
      }
    },
    [eventType, severity, result, userId],
  );
  useEffect(() => {
    void fetchPage(null);
  }, [fetchPage]);

  const select = (label: string, value: string, set: (v: string) => void, opts: string[]) => (
    <select
      aria-label={label}
      className="rounded-md border bg-background px-2 text-sm"
      value={value}
      onChange={(e) => set(e.target.value)}
    >
      <option value="">{label}: all</option>
      {opts.map((o) => (
        <option key={o} value={o}>
          {o}
        </option>
      ))}
    </select>
  );

  return (
    <div className="space-y-4">
      <h1 className="text-2xl font-bold">Audit log</h1>
      <p className="text-sm text-muted-foreground">Append-only and read-only. Newest first.</p>
      <div className="flex flex-wrap gap-2">
        <Input
          className="w-48"
          aria-label="Event type"
          placeholder="Event type, e.g. signin"
          value={eventType}
          onChange={(e) => setEventType(e.target.value)}
        />
        <Input
          className="w-72"
          aria-label="User ID"
          placeholder="Actor or target user ID"
          value={userId}
          onChange={(e) => setUserId(e.target.value)}
        />
        {select("Severity", severity, setSeverity, ["info", "warning", "high"])}
        {select("Result", result, setResult, ["success", "failure"])}
      </div>
      <FormError message={error} />
      <div className="overflow-x-auto">
        <table className="w-full text-xs" data-testid="audit-table">
          <thead className="text-left text-muted-foreground">
            <tr>
              <th className="py-2">Time</th>
              <th>Event</th>
              <th>Result</th>
              <th>Severity</th>
              <th>Actor → Target</th>
              <th>IP</th>
              <th>Details</th>
            </tr>
          </thead>
          <tbody className="divide-y">
            {events.map((e) => (
              <tr key={e.id} className="align-top">
                <td className="py-2 whitespace-nowrap">{fmt.format(new Date(e.occurred_at))}</td>
                <td className="font-mono">{e.event_type}</td>
                <td>{e.result}</td>
                <td>
                  <Badge variant={SEVERITY_VARIANT[e.severity]}>{e.severity}</Badge>
                </td>
                <td className="font-mono">
                  {e.actor_user_id?.slice(0, 8) ?? "—"} → {e.target_user_id?.slice(0, 8) ?? "—"}
                </td>
                <td>{e.ip_address}</td>
                <td className="max-w-xs font-mono break-all">{JSON.stringify(e.details)}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
      {cursor && (
        <Button variant="outline" onClick={() => fetchPage(cursor)}>
          Load more
        </Button>
      )}
    </div>
  );
}

export default function AuditPage() {
  return <RequirePermission permission="audit:read">{() => <AuditLog />}</RequirePermission>;
}
