"use client";

import { useState } from "react";
import Link from "next/link";
import { useRouter } from "next/navigation";

type QrBundle = {
  secret: string;
  uri: string;
  qrDataUrl: string;
};

export function AdminLoginClient({ needsCreate }: { needsCreate: boolean }) {
  const router = useRouter();
  const [mode, setMode] = useState<"create" | "login">(
    needsCreate ? "create" : "login",
  );
  const [error, setError] = useState("");
  const [loading, setLoading] = useState(false);
  const [created, setCreated] = useState<{ viewer: QrBundle } | null>(null);

  async function onCreate(e: React.FormEvent<HTMLFormElement>) {
    e.preventDefault();
    setLoading(true);
    setError("");
    const form = new FormData(e.currentTarget);
    const payload = Object.fromEntries(form.entries());
    const res = await fetch("/api/admin/login", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ ...payload, mode: "create" }),
    });
    const data = await res.json().catch(() => ({}));
    setLoading(false);
    if (!res.ok) {
      setError(data.error || "Could not create admin login.");
      return;
    }
    setCreated({ viewer: data.viewer });
    setMode("login");
  }

  async function onLogin(e: React.FormEvent<HTMLFormElement>) {
    e.preventDefault();
    setLoading(true);
    setError("");
    const form = new FormData(e.currentTarget);
    const res = await fetch("/api/admin/login", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        mode: "login",
        password: form.get("password"),
      }),
    });
    const data = await res.json().catch(() => ({}));
    setLoading(false);
    if (!res.ok) {
      setError(data.error || "Could not sign in.");
      if (data.needsCreate) setMode("create");
      return;
    }
    router.push("/admin");
    router.refresh();
  }

  if (created) {
    return (
      <div className="space-y-6">
        <p className="rounded-xl bg-emerald-50 px-4 py-3 text-sm font-semibold text-emerald-800">
          Admin login created. Share the family gate QR with families, then sign
          in with your password.
        </p>
        <div className="rounded-2xl border border-sky-100 bg-white p-4 text-center">
          <h2 className="font-[family-name:var(--font-display)] text-lg font-semibold">
            Family gate QR
          </h2>
          {/* eslint-disable-next-line @next/next/no-img-element */}
          <img
            src={created.viewer.qrDataUrl}
            alt="Family authenticator QR"
            className="mx-auto mt-2"
          />
          <p className="mt-2 break-all text-xs text-[var(--ink-soft)]">
            {created.viewer.secret}
          </p>
        </div>
        <LoginFields error={error} loading={loading} onSubmit={onLogin} />
      </div>
    );
  }

  if (mode === "create") {
    return (
      <form onSubmit={onCreate} className="space-y-4">
        <p className="text-sm text-[var(--ink-soft)]">
          Create the teacher admin login for your class website.
        </p>
        <div className="grid gap-4 sm:grid-cols-2">
          <div className="sm:col-span-2">
            <label className="mb-2 block text-sm font-bold">Class name</label>
            <input
              name="className"
              className="input-field"
              defaultValue="Sunshine Second Grade"
              required
            />
          </div>
          <div>
            <label className="mb-2 block text-sm font-bold">Teacher</label>
            <input
              name="teacherName"
              className="input-field"
              defaultValue="Ms. Harper"
              required
            />
          </div>
          <div>
            <label className="mb-2 block text-sm font-bold">School</label>
            <input
              name="schoolName"
              className="input-field"
              defaultValue="Maple Creek Elementary"
            />
          </div>
          <div>
            <label className="mb-2 block text-sm font-bold">Grade</label>
            <input name="grade" className="input-field" defaultValue="2nd Grade" />
          </div>
          <div>
            <label className="mb-2 block text-sm font-bold">Room</label>
            <input name="room" className="input-field" defaultValue="2B" />
          </div>
          <div className="sm:col-span-2">
            <label className="mb-2 block text-sm font-bold">Welcome message</label>
            <textarea
              name="welcomeMessage"
              className="input-field min-h-24"
              defaultValue="Welcome, families! This private class website shares our learning adventures, reminders, and newsletters."
            />
          </div>
          <div className="sm:col-span-2">
            <label className="mb-2 block text-sm font-bold">Admin password</label>
            <input
              name="password"
              type="password"
              className="input-field"
              minLength={8}
              placeholder="At least 8 characters"
              required
            />
          </div>
        </div>
        {error ? (
          <p className="rounded-xl bg-red-50 px-4 py-3 text-sm font-semibold text-red-700">
            {error}
          </p>
        ) : null}
        <button type="submit" className="btn-primary w-full" disabled={loading}>
          {loading ? "Creating…" : "Create admin login"}
        </button>
        {!needsCreate ? (
          <button
            type="button"
            className="w-full text-sm font-bold text-[var(--sky-deep)]"
            onClick={() => setMode("login")}
          >
            Already have an account? Sign in
          </button>
        ) : null}
      </form>
    );
  }

  return (
    <div className="space-y-4">
      <LoginFields error={error} loading={loading} onSubmit={onLogin} />
      {needsCreate ? (
        <button
          type="button"
          className="w-full text-sm font-bold text-[var(--sky-deep)]"
          onClick={() => setMode("create")}
        >
          Create admin login
        </button>
      ) : null}
      <p className="text-sm text-[var(--ink-soft)]">
        <Link href="/gate" className="font-bold text-[var(--sky-deep)]">
          Back to family gate
        </Link>
      </p>
    </div>
  );
}

function LoginFields({
  error,
  loading,
  onSubmit,
}: {
  error: string;
  loading: boolean;
  onSubmit: (e: React.FormEvent<HTMLFormElement>) => void;
}) {
  return (
    <form onSubmit={onSubmit} className="space-y-4">
      <div>
        <label htmlFor="password" className="mb-2 block text-sm font-bold">
          Password
        </label>
        <input
          id="password"
          name="password"
          type="password"
          className="input-field"
          required
        />
      </div>
      {error ? (
        <p className="rounded-xl bg-red-50 px-4 py-3 text-sm font-semibold text-red-700">
          {error}
        </p>
      ) : null}
      <button type="submit" className="btn-primary w-full" disabled={loading}>
        {loading ? "Checking…" : "Sign in"}
      </button>
    </form>
  );
}
