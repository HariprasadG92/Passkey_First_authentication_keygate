"use client";

import { useRouter } from "next/navigation";
import { useEffect, useState } from "react";
import { FormError } from "@/components/form-message";
import { api, type SessionInfo } from "@/lib/api";

/** Client-side gate for admin pages. It only decides what to *show*; the API enforces
 * every permission on every request regardless of what the UI does. */
export function RequirePermission({
  permission,
  children,
}: {
  permission: string;
  children: (session: SessionInfo) => React.ReactNode;
}) {
  const router = useRouter();
  const [session, setSession] = useState<SessionInfo | null>(null);

  useEffect(() => {
    api<SessionInfo>("/auth/session").then((s) => {
      if (!s.authenticated) router.replace("/signin");
      else setSession(s);
    });
  }, [router]);

  if (!session) return <p className="text-muted-foreground">Loading…</p>;
  if (!session.permissions.includes(permission))
    return <FormError message="You don't have permission to view this page." />;
  return <>{children(session)}</>;
}
