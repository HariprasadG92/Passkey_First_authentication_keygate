"use client";

import Link from "next/link";
import { useEffect, useState } from "react";
import { api, type SessionInfo } from "@/lib/api";

export function AuthNav() {
  const [session, setSession] = useState<SessionInfo | null>(null);

  useEffect(() => {
    api<SessionInfo>("/auth/session").then(setSession, () => setSession(null));
  }, []);

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
