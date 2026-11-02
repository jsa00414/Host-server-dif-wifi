export const dynamic = "force-dynamic";

import Link from "next/link";
import { redirect } from "next/navigation";
import { SiteHeader } from "@/components/SiteHeader";
import { readSession } from "@/lib/auth";
import { getConfig, listNewsletters } from "@/lib/storage";

export default async function HomePage() {
  const config = await getConfig();
  if (!config?.setupComplete) redirect("/admin/login");

  const admin = await readSession("admin");
  const newsletters = (await listNewsletters())
    .filter((n) => n.published)
    .slice(0, 3);

  return (
    <div className="min-h-screen">
      <SiteHeader className={config.className} showAdmin={Boolean(admin)} />
      <main>
        <section className="hero-plane relative mx-auto min-h-[72vh] w-full overflow-hidden">
          <div className="absolute inset-0">
            <div className="animate-float absolute right-[12%] top-[18%] h-40 w-40 rounded-full bg-[var(--sun)]/35 blur-2xl" />
            <div className="absolute left-[8%] bottom-[12%] h-48 w-48 rounded-full bg-white/10 blur-2xl" />
          </div>
          <div className="relative mx-auto flex min-h-[72vh] max-w-6xl flex-col justify-end px-5 pb-16 pt-10 text-white">
            <p className="animate-fade-up text-sm font-extrabold uppercase tracking-[0.22em] text-white/75">
              Room {config.room} · {config.grade}
            </p>
            <h1 className="animate-fade-up mt-4 max-w-3xl font-[family-name:var(--font-display)] text-5xl font-semibold leading-[1.05] sm:text-7xl">
              {config.className}
            </h1>
            <p className="animate-fade-up-delay mt-5 max-w-xl text-lg text-white/90">
              {config.welcomeMessage}
            </p>
            <div className="animate-fade-up-delay mt-8 flex flex-wrap gap-3">
              <Link href="/newsletters" className="btn-accent">
                Read newsletters
              </Link>
              <Link
                href="/about"
                className="rounded-xl bg-white/15 px-5 py-3 font-semibold text-white backdrop-blur transition hover:bg-white/25"
              >
                Meet our class
              </Link>
            </div>
          </div>
        </section>

        <section className="mx-auto max-w-6xl px-5 py-16">
          <h2 className="font-[family-name:var(--font-display)] text-3xl font-semibold text-[var(--ink)]">
            Latest for families
          </h2>
          <p className="mt-2 max-w-2xl text-[var(--ink-soft)]">
            Newsletters from {config.teacherName} — download as PDF anytime.
          </p>
          <div className="mt-8 space-y-4">
            {newsletters.length === 0 ? (
              <p className="text-[var(--ink-soft)]">
                No published newsletters yet. Check back soon!
              </p>
            ) : (
              newsletters.map((n) => (
                <Link
                  key={n.id}
                  href={`/newsletters/${n.id}`}
                  className="block border-b border-[rgba(75,163,195,0.25)] py-5 transition hover:pl-2"
                >
                  <p className="text-sm font-bold text-[var(--sky-deep)]">
                    {new Date(n.issueDate + "T12:00:00").toLocaleDateString(
                      "en-US",
                      { month: "long", day: "numeric", year: "numeric" },
                    )}
                  </p>
                  <h3 className="mt-1 font-[family-name:var(--font-display)] text-2xl font-semibold">
                    {n.title}
                  </h3>
                  {n.subtitle ? (
                    <p className="mt-1 text-[var(--ink-soft)]">{n.subtitle}</p>
                  ) : null}
                </Link>
              ))
            )}
          </div>
        </section>
      </main>
    </div>
  );
}
