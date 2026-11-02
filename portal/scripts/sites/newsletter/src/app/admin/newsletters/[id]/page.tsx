export const dynamic = "force-dynamic";

import Link from "next/link";
import { notFound } from "next/navigation";
import { NewsletterEditor } from "@/components/NewsletterEditor";
import { getNewsletter } from "@/lib/storage";

type Props = { params: Promise<{ id: string }> };

export default async function EditNewsletterPage({ params }: Props) {
  const { id } = await params;
  const newsletter = await getNewsletter(id);
  if (!newsletter) notFound();

  return (
    <div className="min-h-screen">
      <header className="mx-auto max-w-3xl px-5 py-6">
        <Link
          href="/admin/newsletters"
          className="text-sm font-bold text-[var(--sky-deep)]"
        >
          ← Newsletters
        </Link>
        <h1 className="mt-2 font-[family-name:var(--font-display)] text-3xl font-semibold">
          Edit newsletter
        </h1>
        <div className="mt-4 flex flex-wrap gap-3">
          <a
            href={`/api/admin/newsletters/${newsletter.id}/pdf`}
            className="btn-primary inline-flex"
          >
            Download current PDF
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
      <main className="mx-auto max-w-3xl px-5 pb-16">
        <NewsletterEditor initial={newsletter} />
      </main>
    </div>
  );
}
