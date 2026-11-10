export const dynamic = "force-dynamic";

import Link from "next/link";
import { redirect } from "next/navigation";
import { readSession } from "@/lib/auth";
import { getConfig } from "@/lib/storage";
import { CodeForm } from "@/components/CodeForm";

export default async function GatePage() {
  const config = await getConfig();
  if (!config?.setupComplete) {
    redirect("/admin/login");
  }

  const [viewer, admin] = await Promise.all([
    readSession("viewer"),
    readSession("admin"),
  ]);
  if (viewer || admin) {
    redirect("/home");
  }

  return (
    <main className="relative mx-auto flex min-h-screen w-full max-w-6xl items-center px-5 py-10">
      <div className="grid w-full items-center gap-10 lg:grid-cols-[1.15fr_0.85fr]">
        <section className="hero-plane animate-fade-up relative overflow-hidden rounded-[2rem] px-8 py-12 text-white sm:px-12 sm:py-16">
          <div className="animate-float absolute -right-8 top-8 h-36 w-36 rounded-full bg-[var(--sun)]/40 blur-2xl" />
          <div className="absolute bottom-0 left-0 h-28 w-28 rounded-full bg-white/10 blur-xl" />
          <p className="text-sm font-extrabold uppercase tracking-[0.22em] text-white/80">
            {config.schoolName}
          </p>
          <h1 className="mt-4 max-w-xl font-[family-name:var(--font-display)] text-5xl font-semibold leading-tight sm:text-6xl">
            {config.className}
          </h1>
          <span className="animate-underline mt-5 block h-1.5 w-28 rounded-full bg-[var(--sun)]" />
          <p className="animate-fade-up-delay mt-6 max-w-md text-lg text-white/90">
            A private family space for Room {config.room}. Unlock with the
            authenticator code from the class QR.
          </p>
        </section>

        <section className="paper-card animate-fade-up-delay rounded-3xl p-8">
          <h2 className="font-[family-name:var(--font-display)] text-3xl font-semibold">
            Enter to visit
          </h2>
          <p className="mt-2 text-sm text-[var(--ink-soft)]">
            Open your authenticator app and type the 6-digit code for{" "}
            <strong>{config.className} Families</strong>.
          </p>
          <div className="mt-6">
            <CodeForm
              endpoint="/api/auth/verify"
              redirectTo="/home"
              submitLabel="Unlock class website"
            />
          </div>
          <p className="mt-6 text-sm text-[var(--ink-soft)]">
            Teacher?{" "}
            <Link href="/admin/login" className="font-bold text-[var(--sky-deep)]">
              Admin sign-in
            </Link>
          </p>
        </section>
      </div>
    </main>
  );
}
