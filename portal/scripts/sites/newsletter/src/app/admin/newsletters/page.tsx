export const dynamic = "force-dynamic";

import Link from "next/link";
import { getDesign } from "@/lib/designs";
import { listNewsletters } from "@/lib/storage";
import { DeleteNewsletterButton } from "./DeleteNewsletterButton";

export default async function AdminNewslettersPage() {
  const newsletters = await listNewsletters();

  return (
    <div className="min-h-screen">
      <header className="mx-auto flex max-w-6xl flex-wrap items-center justify-between gap-4 px-5 py-6">
        <div>
          <Link href="/admin" className="text-sm font-bold text-[var(--sky-deep)]">
            ← Admin home
          </Link>
          <h1 className="mt-2 font-[family-name:var(--font-display)] text-3xl font-semibold">
            Newsletters
          </h1>
        </div>
        <Link href="/admin/newsletters/new" className="btn-primary">
          Create newsletter
        </Link>
      </header>
      <main className="mx-auto max-w-6xl px-5 pb-16">
        {newsletters.length === 0 ? (
          <p className="text-[var(--ink-soft)]">No newsletters yet.</p>
        ) : (
          <div className="space-y-3">
            {newsletters.map((n) => (
              <div
                key={n.id}
                className="paper-card flex flex-col gap-4 rounded-2xl p-5 sm:flex-row sm:items-center sm:justify-between"
              >
                <div>
                  <p className="text-sm font-bold text-[var(--sky-deep)]">
                    {n.issueDate} · {n.published ? "Published" : "Draft"} ·{" "}
                    {getDesign(n.designId).name}
                  </p>
                  <h2 className="font-[family-name:var(--font-display)] text-xl font-semibold">
                    {n.title}
                  </h2>
                  <div className="mt-2 flex gap-1">
                    {getDesign(n.designId).swatches.map((color) => (
                      <span
                        key={color}
                        className="h-2.5 w-2.5 rounded-full"
                        style={{ background: color }}
                      />
                    ))}
                  </div>
                </div>
                <div className="flex flex-wrap gap-2">
                  <Link
                    href={`/admin/newsletters/${n.id}`}
                    className="btn-secondary"
                  >
                    Edit
                  </Link>
                  <a
                    href={`/api/admin/newsletters/${n.id}/pdf`}
                    className="btn-primary"
                  >
                    PDF
                  </a>
                  <DeleteNewsletterButton id={n.id} />
                </div>
              </div>
            ))}
          </div>
        )}
      </main>
    </div>
  );
}
