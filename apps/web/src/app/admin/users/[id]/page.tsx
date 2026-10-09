"use client";

import { useParams } from "next/navigation";
import { useCallback, useEffect, useState } from "react";
import { FormError } from "@/components/form-message";
import { RequirePermission } from "@/components/require-permission";
import { StepUpProvider, useStepUp } from "@/components/step-up";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Input } from "@/components/ui/input";
import { api, type AdminUserDetail, type SessionInfo } from "@/lib/api";

const ASSIGNABLE = ["admin", "auditor"] as const;
const fmt = new Intl.DateTimeFormat(undefined, { dateStyle: "medium", timeStyle: "short" });

function UserDetail({ id, session }: { id: string; session: SessionInfo }) {
  const runWithStepUp = useStepUp();
  const [user, setUser] = useState<AdminUserDetail | null>(null);
  const [reason, setReason] = useState("");
  const [error, setError] = useState<string | null>(null);
  const can = (p: string) => session.permissions.includes(p);
  const isSelf = session.user?.id === id;

  const load = useCallback(() => {
    api<AdminUserDetail>(`/admin/users/${id}`).then(setUser, (e: Error) => setError(e.message));
  }, [id]);
  useEffect(load, [load]);

  async function act(fn: () => Promise<unknown>) {
    setError(null);
    try {
      await runWithStepUp(fn);
      load();
    } catch (err) {
      setError((err as Error).message);
    }
  }

  if (!user) return <FormError message={error} />;
  const extraRoles = user.roles.filter((r) => r !== "user");

  return (
    <div className="mx-auto max-w-2xl space-y-6">
      <div>
        <h1 className="flex items-center gap-2 text-2xl font-bold" data-testid="admin-user-email">
          {user.email}
          <Badge variant={user.status === "active" ? "secondary" : "destructive"}>
            {user.status}
          </Badge>
        </h1>
        <p className="text-sm text-muted-foreground">
          {user.display_name} · joined {fmt.format(new Date(user.created_at))}
        </p>
      </div>
      <FormError message={error} />

      <Card>
        <CardHeader>
          <CardTitle>Sign-in methods</CardTitle>
        </CardHeader>
        <CardContent className="space-y-1 text-sm">
          <p>Passkeys: {user.passkeys}</p>
          <p>Authenticator app: {user.totp_enabled ? "on" : "off"}</p>
          <p>Linked: {user.social_providers.join(", ") || "none"}</p>
        </CardContent>
      </Card>

      {can("roles:assign") && (
        <Card>
          <CardHeader>
            <CardTitle>Roles</CardTitle>
          </CardHeader>
          <CardContent className="flex flex-wrap gap-4" data-testid="role-editor">
            {ASSIGNABLE.map((role) => (
              <label key={role} className="flex items-center gap-2 text-sm">
                <input
                  type="checkbox"
                  checked={extraRoles.includes(role)}
                  disabled={isSelf}
                  onChange={(e) => {
                    const next = e.target.checked
                      ? [...extraRoles, role]
                      : extraRoles.filter((r) => r !== role);
                    void act(() =>
                      api(`/admin/users/${id}/roles`, { method: "PUT", body: { roles: next } }),
                    );
                  }}
                />
                {role}
              </label>
            ))}
            {isSelf && (
              <p className="text-xs text-muted-foreground">You can&apos;t change your own roles.</p>
            )}
          </CardContent>
        </Card>
      )}

      {can("users:write") && !isSelf && (
        <Card>
          <CardHeader>
            <CardTitle>Account status</CardTitle>
          </CardHeader>
          <CardContent className="space-y-3">
            {user.status === "active" ? (
              <form
                className="flex gap-2"
                onSubmit={(e) => {
                  e.preventDefault();
                  if (reason.trim().length < 3) return setError("Give a reason (audited).");
                  void act(() =>
                    api(`/admin/users/${id}/suspend`, {
                      method: "POST",
                      body: { reason: reason.trim() },
                    }),
                  );
                }}
              >
                <Input
                  aria-label="Suspension reason"
                  placeholder="Reason (recorded in the audit log)"
                  value={reason}
                  maxLength={500}
                  onChange={(e) => setReason(e.target.value)}
                />
                <Button type="submit" variant="destructive">
                  Suspend
                </Button>
              </form>
            ) : (
              <Button
                onClick={() => act(() => api(`/admin/users/${id}/unsuspend`, { method: "POST" }))}
              >
                Unsuspend
              </Button>
            )}
          </CardContent>
        </Card>
      )}

      <Card>
        <CardHeader>
          <CardTitle>Active sessions ({user.sessions.length})</CardTitle>
        </CardHeader>
        <CardContent className="space-y-3">
          <ul className="divide-y text-sm" data-testid="admin-session-list">
            {user.sessions.map((s) => (
              <li key={s.id} className="py-2">
                {s.ip_address ?? "unknown IP"} · {s.auth_method} · active{" "}
                {fmt.format(new Date(s.last_seen_at))}
              </li>
            ))}
          </ul>
          {can("users:sessions:revoke") && user.sessions.length > 0 && (
            <Button
              variant="outline"
              onClick={() =>
                act(() => api(`/admin/users/${id}/sessions/revoke`, { method: "POST" }))
              }
            >
              Sign out of all sessions
            </Button>
          )}
        </CardContent>
      </Card>
    </div>
  );
}

export default function AdminUserPage() {
  const { id } = useParams<{ id: string }>();
  return (
    <RequirePermission permission="users:read">
      {(session) => (
        <StepUpProvider totpEnabled={false}>
          <UserDetail id={id} session={session} />
        </StepUpProvider>
      )}
    </RequirePermission>
  );
}
