import type { Metadata } from "next";
import { headers } from "next/headers";
import "./globals.css";

export const metadata: Metadata = {
  title: "Notes · a Keygate demo",
  description: "Demo relying party that signs in through Keygate with OpenID Connect.",
};

export default async function RootLayout({ children }: Readonly<{ children: React.ReactNode }>) {
  await headers(); // dynamic rendering: every response gets a fresh CSP nonce
  return (
    <html lang="en">
      <body className="bg-white text-gray-900 antialiased">{children}</body>
    </html>
  );
}
