import type { Metadata } from "next";
import { GeistMono } from "geist/font/mono";
import { GeistSans } from "geist/font/sans";
import { headers } from "next/headers";
import Link from "next/link";
import { KeyRound } from "lucide-react";
import { AuthNav } from "@/components/auth-nav";
import "./globals.css";

// Self-hosted fonts: no build-time or runtime requests to third-party font CDNs.

export const metadata: Metadata = {
  title: { default: "Keygate", template: "%s · Keygate" },
  description: "Passkey-first, self-hostable identity platform.",
};

export default async function RootLayout({ children }: Readonly<{ children: React.ReactNode }>) {
  // Reading request headers opts every page into dynamic rendering, which the per-request
  // CSP nonce requires: a statically prerendered page could not carry a fresh nonce.
  await headers();

  return (
    <html lang="en" className={`${GeistSans.variable} ${GeistMono.variable}`}>
      <body className="flex min-h-screen flex-col antialiased">
        <header className="border-b">
          <div className="mx-auto flex h-14 max-w-5xl items-center justify-between px-4">
            <Link href="/" className="flex items-center gap-2 font-semibold">
              <KeyRound className="size-5" aria-hidden />
              Keygate
            </Link>
            <nav aria-label="Main" className="text-sm text-muted-foreground">
              <AuthNav />
            </nav>
          </div>
        </header>
        <main className="mx-auto w-full max-w-5xl flex-1 px-4 py-12">{children}</main>
        <footer className="border-t py-6 text-center text-xs text-muted-foreground">
          Keygate · passkey-first authentication
        </footer>
      </body>
    </html>
  );
}
