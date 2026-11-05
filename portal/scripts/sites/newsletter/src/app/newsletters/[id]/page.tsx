export const dynamic = "force-dynamic";

import Link from "next/link";
import { notFound, redirect } from "next/navigation";
import { SiteHeader } from "@/components/SiteHeader";
import { readSession } from "@/lib/auth";
import { getConfig, getNewsletter } from "@/lib/storage";

type Props = { params: Promise<{ id: string }> };

export default async function NewsletterDetailPage({ params }: Props) {
  const { id } = await params;
  const config = await getConfig();
  if (!config?.setupComplete) redirect("/admin/login");

  const newsletter = await getNewsletter(id);
  if (!newsletter || !newsletter.published) notFound();

  const admin = await readSession("admin");

  return (
    <div className="min-h-screen">
      <SiteHeader className={config.className} showAdmin={Boolean(admin)} />
      <main className="mx-auto max-w-3xl px-5 py-10">
        <Link
          href="/newsletters"
          className="text-sm font-bold text-[var(--sky-deep)]"
        >
          ← All newsletters
        </Link>
        <p className="mt-6 text-sm font-bold text-[var(--sky-deep)]">
          {new Date(newsletter.issueDate + "T12:00:00").toLocaleDateString(
            "en-US",
            { weekday: "long", month: "long", day: "numeric", year: "numeric" },
          )}
        </p>
        <h1 className="mt-2 font-[family-name:var(--font-display)] text-5xl font-semibold">
          {newsletter.title}
        </h1>
        {newsletter.subtitle ? (
          <p className="mt-3 text-lg text-[var(--ink-soft)]">
            {newsletter.subtitle}
          </p>
        ) : null}
        <a
          href={`/api/newsletters/${newsletter.id}/pdf`}
          className="btn-primary mt-6 inline-flex"
        >
          Download PDF
        </a>

        <div className="mt-12 space-y-10">
          {newsletter.sections.map((section) => (
            <section key={section.id}>
              <h2 className="font-[family-name:var(--font-display)] text-2xl font-semibold text-[var(--ink)]">
                {section.heading}
              </h2>
              <p className="mt-3 whitespace-pre-wrap leading-relaxed text-[var(--ink-soft)]">
                {section.body}
              </p>
            </section>
          ))}
        </div>
      </main>
    </div>
  );
}
