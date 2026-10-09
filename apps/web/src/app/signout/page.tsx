"use client";

import { useRouter } from "next/navigation";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { api } from "@/lib/api";

/** Reached from RP-initiated logout when the request can't be verified: the user decides. */
export default function SignOutPage() {
  const router = useRouter();
  return (
    <Card className="mx-auto max-w-md">
      <CardHeader>
        <CardTitle className="text-xl">Sign out of Keygate?</CardTitle>
        <CardDescription>An app asked to sign you out.</CardDescription>
      </CardHeader>
      <CardContent className="flex gap-2">
        <Button
          onClick={async () => {
            await api("/auth/logout", { method: "POST" });
            router.replace("/signin?signed_out=1");
          }}
        >
          Sign out
        </Button>
        <Button variant="outline" onClick={() => router.push("/account")}>
          Stay signed in
        </Button>
      </CardContent>
    </Card>
  );
}
