export const dynamic = "force-dynamic";

import Link from "next/link";
import { redirect } from "next/navigation";
import { SiteHeader } from "@/components/SiteHeader";
import { readSession } from "@/lib/auth";
import { getConfig, listNewsletters } from "@/lib/storage";

export default async function NewslettersPage() {
  const config = await getConfig();
  if (!config?.setupComplete) redirect("/admin/login");
  const admin = await readSession("admin");
  const newsletters = (await listNewsletters()).filter((n) => n.published);

  return (
    <div className="min-h-screen">
      <SiteHeader className={config.className} showAdmin={Boolean(admin)} />
      <main className="mx-auto max-w-6xl px-5 py-10">
        <h1 className="font-[family-name:var(--font-display)] text-5xl font-semibold">
          Class newsletters
        </h1>
        <p className="mt-3 max-w-2xl text-[var(--ink-soft)]">
          Family updates you can read online or download as a PDF.
        </p>

        <div className="mt-10 space-y-3">
          {newsletters.length === 0 ? (
            <p className="text-[var(--ink-soft)]">No newsletters yet.</p>
          ) : (
            newsletters.map((n) => (
              <div
                key={n.id}
                className="flex flex-col gap-3 border-b border-[rgba(75,163,195,0.25)] py-6 sm:flex-row sm:items-end sm:justify-between"
              >
                <div>
                  <p className="text-sm font-bold text-[var(--sky-deep)]">
                    {new Date(n.issueDate + "T12:00:00").toLocaleDateString(
                      "en-US",
                      { month: "long", day: "numeric", year: "numeric" },
                    )}
                  </p>
                  <h2 className="mt-1 font-[family-name:var(--font-display)] text-2xl font-semibold">
                    {n.title}
                  </h2>
                  {n.subtitle ? (
                    <p className="mt-1 text-[var(--ink-soft)]">{n.subtitle}</p>
                  ) : null}
                </div>
                <div className="flex gap-2">
                  <Link href={`/newsletters/${n.id}`} className="btn-secondary">
                    Read
                  </Link>
                  <a
                    href={`/api/newsletters/${n.id}/pdf`}
                    className="btn-primary"
                  >
                    PDF
                  </a>
                </div>
              </div>
            ))
          )}
        </div>
      </main>
    </div>
  );
}
