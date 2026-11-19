export const dynamic = "force-dynamic";

import { getConfig } from "@/lib/storage";
import { AdminLoginClient } from "./AdminLoginClient";

export default async function AdminLoginPage() {
  const config = await getConfig();
  const needsCreate = !config?.setupComplete;

  return (
    <main className="mx-auto flex min-h-screen w-full max-w-xl items-center px-5 py-12">
      <div className="paper-card w-full animate-fade-up rounded-3xl p-8 sm:p-10">
        <p className="text-sm font-extrabold uppercase tracking-[0.2em] text-[var(--coral)]">
          Teacher admin
        </p>
        <h1 className="mt-2 font-[family-name:var(--font-display)] text-3xl font-semibold">
          {needsCreate ? "Create admin login" : "Admin sign in"}
        </h1>
        <p className="mt-2 text-sm text-[var(--ink-soft)]">
          {needsCreate
            ? "Set up your class website and teacher account in one step."
            : "Use your admin password to continue."}
        </p>
        <div className="mt-6">
          <AdminLoginClient needsCreate={needsCreate} />
        </div>
      </div>
    </main>
  );
}
