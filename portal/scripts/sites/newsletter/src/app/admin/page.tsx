export const dynamic = "force-dynamic";

import Link from "next/link";
import { redirect } from "next/navigation";
import { getConfig, listNewsletters } from "@/lib/storage";

export default async function AdminDashboard() {
  const config = await getConfig();
  if (!config?.setupComplete) redirect("/admin/login");
  const newsletters = await listNewsletters();

  return (
    <div className="min-h-screen">
      <header className="mx-auto flex max-w-6xl items-center justify-between px-5 py-6">
        <div>
          <p className="text-sm font-extrabold uppercase tracking-[0.18em] text-[var(--coral)]">
            Admin
          </p>
          <h1 className="font-[family-name:var(--font-display)] text-3xl font-semibold">
            {config.className}
          </h1>
        </div>
        <form action="/api/admin/logout" method="post">
          <button type="submit" className="btn-secondary">
            Sign out
          </button>
        </form>
      </header>

      <main className="mx-auto grid max-w-6xl gap-6 px-5 pb-16 md:grid-cols-3">
        <Link
          href="/admin/newsletters/new"
          className="paper-card rounded-3xl p-6 transition hover:-translate-y-1"
        >
          <h2 className="font-[family-name:var(--font-display)] text-2xl font-semibold">
            New PDF newsletter
          </h2>
          <p className="mt-2 text-sm text-[var(--ink-soft)]">
            Write sections and generate a downloadable family PDF.
          </p>
        </Link>
        <Link
          href="/admin/newsletters"
          className="paper-card rounded-3xl p-6 transition hover:-translate-y-1"
        >
          <h2 className="font-[family-name:var(--font-display)] text-2xl font-semibold">
            Manage newsletters
          </h2>
          <p className="mt-2 text-sm text-[var(--ink-soft)]">
            {newsletters.length} issue{newsletters.length === 1 ? "" : "s"} saved.
          </p>
        </Link>
        <Link
          href="/admin/access"
          className="paper-card rounded-3xl p-6 transition hover:-translate-y-1"
        >
          <h2 className="font-[family-name:var(--font-display)] text-2xl font-semibold">
            Family 2FA QR
          </h2>
          <p className="mt-2 text-sm text-[var(--ink-soft)]">
            Share the QR code so families can unlock the gated site.
          </p>
        </Link>
        <Link
          href="/home"
          className="paper-card rounded-3xl p-6 transition hover:-translate-y-1 md:col-span-3"
        >
          <h2 className="font-[family-name:var(--font-display)] text-2xl font-semibold">
            Preview class website
          </h2>
          <p className="mt-2 text-sm text-[var(--ink-soft)]">
            Open the family-facing pages while signed in as admin.
          </p>
        </Link>
      </main>
    </div>
  );
}
