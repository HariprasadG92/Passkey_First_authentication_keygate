import { NextResponse, type NextRequest } from "next/server";

/**
 * Per-request nonce-based Content-Security-Policy.
 *
 * Only scripts carrying this request's nonce may run ('strict-dynamic' lets them load
 * their own chunks), which neutralises injected <script> tags and inline handlers.
 * Next.js reads the nonce from the request's CSP header and applies it to its scripts.
 *
 * Same policy as the Keygate UI (see apps/web/src/middleware.ts).
 */
export function buildCsp(nonce: string, isDev: boolean, formTargets: string[] = []): string {
  const scriptSrc = [`'self'`, `'nonce-${nonce}'`, `'strict-dynamic'`];
  if (isDev) scriptSrc.push(`'unsafe-eval'`); // React dev tooling / fast refresh

  return [
    `default-src 'self'`,
    `script-src ${scriptSrc.join(" ")}`,
    `style-src 'self' 'unsafe-inline'`,
    `img-src 'self' blob: data:`,
    `font-src 'self'`,
    `connect-src 'self'`,
    `object-src 'none'`,
    `base-uri 'none'`,
    // Sign-out posts here and is redirected to Keygate's end-session endpoint; browsers
    // apply form-action to that redirect too.
    `form-action 'self' ${formTargets.join(" ")}`.trim(),
    `frame-ancestors 'none'`,
    ...(isDev ? [] : [`upgrade-insecure-requests`]),
  ].join("; ");
}

export function middleware(request: NextRequest) {
  const nonce = btoa(crypto.randomUUID());
  const csp = buildCsp(nonce, process.env.NODE_ENV === "development", [
    process.env.KEYGATE_ISSUER ?? "http://localhost",
  ]);

  const requestHeaders = new Headers(request.headers);
  requestHeaders.set("x-nonce", nonce);
  requestHeaders.set("Content-Security-Policy", csp);

  const response = NextResponse.next({ request: { headers: requestHeaders } });
  response.headers.set("Content-Security-Policy", csp);
  return response;
}

export const config = {
  matcher: [
    // Skip static assets and prefetches: they don't execute inline scripts.
    {
      source: "/((?!_next/static|_next/image|favicon.ico).*)",
      missing: [
        { type: "header", key: "next-router-prefetch" },
        { type: "header", key: "purpose", value: "prefetch" },
      ],
    },
  ],
};
