"use client";

import Link from "next/link";
import { usePathname } from "next/navigation";
import { useEffect, useState } from "react";
import { api, type SessionInfo } from "@/lib/api";

export function AuthNav() {
  const pathname = usePathname();
  const [session, setSession] = useState<SessionInfo | null>(null);

  // The layout (and this component) persists across client-side navigation, so re-check
  // the session whenever the route changes (e.g. right after signing in or out).
  useEffect(() => {
    api<SessionInfo>("/auth/session").then(setSession, () => setSession(null));
  }, [pathname]);

  if (session?.authenticated) {
    const can = (p: string) => session.permissions.includes(p);
    return (
      <div className="flex gap-4">
        {can("users:read") && (
          <Link href="/admin" className="hover:text-foreground">
            Users
          </Link>
        )}
        {can("clients:read") && (
          <Link href="/admin/clients" className="hover:text-foreground">
            Apps
          </Link>
        )}
        {can("audit:read") && (
          <Link href="/admin/audit" className="hover:text-foreground">
            Audit log
          </Link>
        )}
        <Link href="/account" className="hover:text-foreground">
          {session.user?.email}
        </Link>
      </div>
    );
  }
  return (
    <div className="flex gap-4">
      <Link href="/signin" className="hover:text-foreground">
        Sign in
      </Link>
      <Link href="/signup" className="hover:text-foreground">
        Create account
      </Link>
    </div>
  );
}
