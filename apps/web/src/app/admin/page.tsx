"use client";

import Link from "next/link";
import { useCallback, useEffect, useState } from "react";
import { FormError } from "@/components/form-message";
import { RequirePermission } from "@/components/require-permission";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { api, type AdminUserSummary } from "@/lib/api";

const PAGE = 25;

function UserDirectory() {
  const [q, setQ] = useState("");
  const [status, setStatus] = useState("");
  const [offset, setOffset] = useState(0);
  const [data, setData] = useState<{ items: AdminUserSummary[]; total: number } | null>(null);
  const [error, setError] = useState<string | null>(null);

  const load = useCallback(() => {
    const params = new URLSearchParams({ limit: String(PAGE), offset: String(offset) });
    if (q.trim()) params.set("q", q.trim());
    if (status) params.set("status", status);
    api<{ items: AdminUserSummary[]; total: number }>(`/admin/users?${params}`).then(
      setData,
      (e: Error) => setError(e.message),
    );
  }, [q, status, offset]);
  useEffect(load, [load]);

  return (
    <div className="space-y-4">
      <h1 className="text-2xl font-bold">Users</h1>
      <form
        className="flex gap-2"
        onSubmit={(e) => {
          e.preventDefault();
          setOffset(0);
          load();
        }}
      >
        <Input
          aria-label="Search users"
          placeholder="Search by email or name"
          value={q}
          onChange={(e) => setQ(e.target.value)}
        />
        <select
          aria-label="Status filter"
          className="rounded-md border bg-background px-2 text-sm"
          value={status}
          onChange={(e) => {
            setStatus(e.target.value);
            setOffset(0);
          }}
        >
          <option value="">All</option>
          <option value="active">Active</option>
          <option value="suspended">Suspended</option>
        </select>
        <Button type="submit">Search</Button>
      </form>
      <FormError message={error} />
      {data && (
        <>
          <table className="w-full text-sm" data-testid="user-table">
            <thead className="text-left text-muted-foreground">
              <tr>
                <th className="py-2">Email</th>
                <th>Name</th>
                <th>Roles</th>
                <th>Status</th>
              </tr>
            </thead>
            <tbody className="divide-y">
              {data.items.map((u) => (
                <tr key={u.id}>
                  <td className="py-2">
                    <Link className="underline" href={`/admin/users/${u.id}`}>
                      {u.email}
                    </Link>
                  </td>
                  <td>{u.display_name}</td>
                  <td>{u.roles.filter((r) => r !== "user").join(", ") || "user"}</td>
                  <td>
                    <Badge variant={u.status === "active" ? "secondary" : "destructive"}>
                      {u.status}
                    </Badge>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
          <div className="flex items-center justify-between text-sm text-muted-foreground">
            <span>
              {data.total === 0 ? 0 : offset + 1}–{Math.min(offset + PAGE, data.total)} of{" "}
              {data.total}
            </span>
            <div className="flex gap-2">
              <Button
                variant="outline"
                size="sm"
                disabled={offset === 0}
                onClick={() => setOffset(Math.max(0, offset - PAGE))}
              >
                Previous
              </Button>
              <Button
                variant="outline"
                size="sm"
                disabled={offset + PAGE >= data.total}
                onClick={() => setOffset(offset + PAGE)}
              >
                Next
              </Button>
            </div>
          </div>
        </>
      )}
    </div>
  );
}

export default function AdminUsersPage() {
  return <RequirePermission permission="users:read">{() => <UserDirectory />}</RequirePermission>;
}
