export const dynamic = "force-dynamic";

import Link from "next/link";
import { notFound, redirect } from "next/navigation";
import { NewsletterEditor } from "@/components/NewsletterEditor";
import { getConfig, getNewsletter } from "@/lib/storage";

type Props = { params: Promise<{ id: string }> };

export default async function EditNewsletterPage({ params }: Props) {
  const { id } = await params;
  const [newsletter, config] = await Promise.all([
    getNewsletter(id),
    getConfig(),
  ]);
  if (!config) redirect("/admin/login");
  if (!newsletter) notFound();

  return (
    <div className="min-h-screen">
      <header className="mx-auto max-w-7xl px-5 py-6">
        <Link
          href="/admin/newsletters"
          className="text-sm font-bold text-[var(--sky-deep)]"
        >
          ← Newsletters
        </Link>
        <h1 className="mt-2 font-[family-name:var(--font-display)] text-3xl font-semibold">
          Edit PDF newsletter
        </h1>
        <p className="mt-2 max-w-3xl text-sm text-[var(--ink-soft)]">
          Switch designs, reorder sections, and watch the PDF preview update
          live.
        </p>
        <div className="mt-4 flex flex-wrap gap-3">
          <a
            href={`/api/admin/newsletters/${newsletter.id}/pdf`}
            className="btn-primary inline-flex"
          >
            Download saved PDF
          </a>
          {newsletter.slideshowToken ? (
            <a
              href={`/s/${newsletter.slideshowToken}`}
              target="_blank"
              rel="noreferrer"
              className="btn-secondary inline-flex"
            >
              Open hidden slideshow
            </a>
          ) : null}
        </div>
      </header>
      <main className="mx-auto max-w-7xl px-5 pb-16">
        <NewsletterEditor
          initial={newsletter}
          classInfo={{
            className: config.className,
            teacherName: config.teacherName,
            schoolName: config.schoolName,
            grade: config.grade,
            room: config.room,
          }}
        />
      </main>
    </div>
  );
}
