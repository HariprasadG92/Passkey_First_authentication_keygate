import { Fingerprint, ShieldCheck, Workflow } from "lucide-react";
import { Button } from "@/components/ui/button";
import { ApiStatus } from "@/components/api-status";

const features = [
  {
    icon: Fingerprint,
    title: "Passkeys first",
    body: "Phishing-resistant WebAuthn sign-in. No passwords to steal or reuse.",
  },
  {
    icon: ShieldCheck,
    title: "Recovery built in",
    body: "TOTP fallback, single-use recovery codes and multiple passkeys per account.",
  },
  {
    icon: Workflow,
    title: "OpenID Connect provider",
    body: "Apps sign users in through Keygate with Authorization Code + PKCE.",
  },
];

export default function HomePage() {
  return (
    <div className="space-y-12">
      <section className="space-y-4">
        <h1 className="text-4xl font-bold tracking-tight">Sign in without passwords.</h1>
        <p className="max-w-2xl text-lg text-muted-foreground">
          Keygate is a self-hostable identity service built around passkeys.
        </p>
        <div className="flex items-center gap-4">
          <Button disabled>Sign in with a passkey</Button>
          <ApiStatus />
        </div>
      </section>
      <section className="grid gap-6 sm:grid-cols-3">
        {features.map(({ icon: Icon, title, body }) => (
          <div key={title} className="rounded-lg border p-5">
            <Icon className="mb-3 size-6" aria-hidden />
            <h2 className="font-semibold">{title}</h2>
            <p className="mt-1 text-sm text-muted-foreground">{body}</p>
          </div>
        ))}
      </section>
    </div>
  );
}
