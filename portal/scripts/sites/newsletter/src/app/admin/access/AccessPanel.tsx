"use client";

import { useEffect, useState } from "react";

type QrBundle = {
  secret: string;
  uri: string;
  qrDataUrl: string;
};

export function AccessPanel() {
  const [viewer, setViewer] = useState<QrBundle | null>(null);
  const [admin, setAdmin] = useState<QrBundle | null>(null);
  const [error, setError] = useState("");
  const [busy, setBusy] = useState(false);

  async function load() {
    const res = await fetch("/api/admin/access-qr");
    const data = await res.json();
    if (!res.ok) {
      setError(data.error || "Could not load QR codes.");
      return;
    }
    setViewer(data.viewer);
    setAdmin(data.admin);
  }

  useEffect(() => {
    void load();
  }, []);

  async function regenerate(target: "viewer" | "admin") {
    const ok = window.confirm(
      target === "viewer"
        ? "Regenerate the family access code? Existing authenticator setups will stop working."
        : "Regenerate the admin authenticator? You will need to scan the new QR immediately.",
    );
    if (!ok) return;
    setBusy(true);
    const res = await fetch("/api/admin/access-qr", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ target }),
    });
    setBusy(false);
    if (!res.ok) {
      setError("Could not regenerate.");
      return;
    }
    await load();
  }

  if (error) {
    return (
      <p className="rounded-xl bg-red-50 px-4 py-3 text-sm font-semibold text-red-700">
        {error}
      </p>
    );
  }

  if (!viewer || !admin) {
    return <p className="text-[var(--ink-soft)]">Loading QR codes…</p>;
  }

  return (
    <div className="grid gap-8 lg:grid-cols-2">
      <article className="paper-card rounded-3xl p-6">
        <h2 className="font-[family-name:var(--font-display)] text-2xl font-semibold">
          Family website access
        </h2>
        <p className="mt-2 text-sm text-[var(--ink-soft)]">
          Print this QR or share it privately. Families scan once with Google
          Authenticator, Authy, or similar, then use the rotating code at the
          gate page.
        </p>
        {/* eslint-disable-next-line @next/next/no-img-element */}
        <img
          src={viewer.qrDataUrl}
          alt="Family access QR code"
          className="mx-auto mt-6 rounded-2xl border border-sky-100 bg-white p-3"
        />
        <p className="mt-4 break-all text-center text-xs text-[var(--ink-soft)]">
          Secret: {viewer.secret}
        </p>
        <button
          type="button"
          className="btn-secondary mt-5 w-full"
          disabled={busy}
          onClick={() => regenerate("viewer")}
        >
          Regenerate family QR
        </button>
      </article>

      <article className="paper-card rounded-3xl p-6">
        <h2 className="font-[family-name:var(--font-display)] text-2xl font-semibold">
          Admin authenticator
        </h2>
        <p className="mt-2 text-sm text-[var(--ink-soft)]">
          Keep this private. Scan it into your own authenticator app for admin
          sign-in.
        </p>
        {/* eslint-disable-next-line @next/next/no-img-element */}
        <img
          src={admin.qrDataUrl}
          alt="Admin access QR code"
          className="mx-auto mt-6 rounded-2xl border border-sky-100 bg-white p-3"
        />
        <p className="mt-4 break-all text-center text-xs text-[var(--ink-soft)]">
          Secret: {admin.secret}
        </p>
        <button
          type="button"
          className="btn-secondary mt-5 w-full"
          disabled={busy}
          onClick={() => regenerate("admin")}
        >
          Regenerate admin QR
        </button>
      </article>
    </div>
  );
}
