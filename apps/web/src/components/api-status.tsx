"use client";

import { useEffect, useState } from "react";

type Status = "checking" | "ok" | "degraded" | "unreachable";

const LABELS: Record<Status, string> = {
  checking: "Checking API…",
  ok: "API ready",
  degraded: "API degraded",
  unreachable: "API unreachable",
};

const DOT: Record<Status, string> = {
  checking: "bg-muted-foreground",
  ok: "bg-emerald-500",
  degraded: "bg-amber-500",
  unreachable: "bg-red-500",
};

/** Same-origin call through the gateway (/api → FastAPI): no CORS needed. */
export function ApiStatus() {
  const [status, setStatus] = useState<Status>("checking");

  useEffect(() => {
    const controller = new AbortController();
    fetch("/api/health/ready", { signal: controller.signal, cache: "no-store" })
      .then((res) => setStatus(res.ok ? "ok" : "degraded"))
      .catch((err: unknown) => {
        if (!(err instanceof DOMException && err.name === "AbortError")) setStatus("unreachable");
      });
    return () => controller.abort();
  }, []);

  return (
    <span
      className="flex items-center gap-2 text-sm text-muted-foreground"
      data-testid="api-status"
    >
      <span className={`size-2 rounded-full ${DOT[status]}`} aria-hidden />
      {LABELS[status]}
    </span>
  );
}
