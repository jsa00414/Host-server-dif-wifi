export const dynamic = "force-dynamic";

import Link from "next/link";
import { NewsletterEditor } from "@/components/NewsletterEditor";

export default function NewNewsletterPage() {
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
          Create newsletter
        </h1>
        <p className="mt-2 text-sm text-[var(--ink-soft)]">
          Saving generates a PDF families can download from the class site.
        </p>
      </header>
      <main className="mx-auto max-w-3xl px-5 pb-16">
        <NewsletterEditor />
      </main>
    </div>
  );
}
