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
    return (
      <Link href="/account" className="hover:text-foreground">
        {session.user?.email}
      </Link>
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
