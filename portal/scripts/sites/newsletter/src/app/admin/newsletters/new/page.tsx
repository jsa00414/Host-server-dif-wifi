export const dynamic = "force-dynamic";

import Link from "next/link";
import { redirect } from "next/navigation";
import { NewsletterEditor } from "@/components/NewsletterEditor";
import { getConfig } from "@/lib/storage";

export default async function NewNewsletterPage() {
  const config = await getConfig();
  if (!config) redirect("/admin/login");

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
          PDF newsletter editor
        </h1>
        <p className="mt-2 max-w-3xl text-sm text-[var(--ink-soft)]">
          Choose a colorful premade design, organize your sections, and preview
          the PDF before saving. The bottom-right QR still opens the hidden
          slideshow.
        </p>
      </header>
      <main className="mx-auto max-w-7xl px-5 pb-16">
        <NewsletterEditor
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
