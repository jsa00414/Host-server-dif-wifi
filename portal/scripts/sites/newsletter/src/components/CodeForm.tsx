"use client";

import { useState } from "react";
import { useRouter } from "next/navigation";

export function CodeForm({
  endpoint,
  redirectTo,
  extraFields,
  submitLabel,
}: {
  endpoint: string;
  redirectTo: string;
  extraFields?: React.ReactNode;
  submitLabel: string;
}) {
  const router = useRouter();
  const [code, setCode] = useState("");
  const [error, setError] = useState("");
  const [loading, setLoading] = useState(false);

  async function onSubmit(e: React.FormEvent<HTMLFormElement>) {
    e.preventDefault();
    setLoading(true);
    setError("");
    const form = new FormData(e.currentTarget);
    const payload = Object.fromEntries(form.entries());
    payload.code = code;

    const res = await fetch(endpoint, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(payload),
    });
    const data = await res.json().catch(() => ({}));
    setLoading(false);
    if (!res.ok) {
      setError(data.error || "Could not sign in. Try again.");
      return;
    }
    router.push(redirectTo);
    router.refresh();
  }

  return (
    <form onSubmit={onSubmit} className="space-y-4">
      {extraFields}
      <div>
        <label
          htmlFor="code"
          className="mb-2 block text-sm font-bold text-[var(--ink)]"
        >
          Authenticator code
        </label>
        <input
          id="code"
          name="code"
          inputMode="numeric"
          autoComplete="one-time-code"
          maxLength={6}
          placeholder="000000"
          value={code}
          onChange={(e) => setCode(e.target.value.replace(/\D/g, "").slice(0, 6))}
          className="input-field text-center font-[family-name:var(--font-display)] text-3xl tracking-[0.35em]"
          required
        />
      </div>
      {error ? (
        <p className="rounded-xl bg-red-50 px-4 py-3 text-sm font-semibold text-red-700">
          {error}
        </p>
      ) : null}
      <button type="submit" className="btn-primary w-full" disabled={loading}>
        {loading ? "Checking…" : submitLabel}
      </button>
    </form>
  );
}
