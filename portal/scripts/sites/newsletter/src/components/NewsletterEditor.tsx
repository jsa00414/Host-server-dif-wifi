"use client";

import { useEffect, useMemo, useState } from "react";
import { useRouter } from "next/navigation";
import {
  DEFAULT_DESIGN_ID,
  NEWSLETTER_DESIGNS,
  getDesign,
} from "@/lib/designs";
import { buildNewsletterPdf } from "@/lib/pdf";
import type { Newsletter, NewsletterSection, SiteConfig } from "@/lib/types";

function blankSection(): NewsletterSection {
  return {
    id: crypto.randomUUID(),
    heading: "",
    body: "",
  };
}

type ClassInfo = Pick<
  SiteConfig,
  "className" | "teacherName" | "schoolName" | "grade" | "room"
>;

export function NewsletterEditor({
  initial,
  classInfo,
}: {
  initial?: Newsletter | null;
  classInfo: ClassInfo;
}) {
  const router = useRouter();
  const [title, setTitle] = useState(initial?.title || "");
  const [subtitle, setSubtitle] = useState(initial?.subtitle || "");
  const [issueDate, setIssueDate] = useState(
    initial?.issueDate || new Date().toISOString().slice(0, 10),
  );
  const [published, setPublished] = useState(initial?.published ?? true);
  const [designId, setDesignId] = useState(
    initial?.designId || DEFAULT_DESIGN_ID,
  );
  const [sections, setSections] = useState<NewsletterSection[]>(
    initial?.sections?.length ? initial.sections : [blankSection()],
  );
  const [error, setError] = useState("");
  const [saving, setSaving] = useState(false);
  const [previewUrl, setPreviewUrl] = useState<string | null>(null);
  const [previewBusy, setPreviewBusy] = useState(false);
  const [previewError, setPreviewError] = useState("");

  const selectedDesign = useMemo(() => getDesign(designId), [designId]);

  const draft = useMemo(
    () => ({
      id: initial?.id || "preview",
      title: title || "Untitled newsletter",
      subtitle,
      issueDate,
      sections,
      designId,
      slideshowToken: initial?.slideshowToken || "preview-token",
      createdAt: initial?.createdAt || new Date().toISOString(),
      updatedAt: new Date().toISOString(),
      published,
    }),
    [
      initial?.id,
      initial?.slideshowToken,
      initial?.createdAt,
      title,
      subtitle,
      issueDate,
      sections,
      designId,
      published,
    ],
  );

  useEffect(() => {
    let cancelled = false;
    let objectUrl: string | null = null;
    const timer = window.setTimeout(async () => {
      setPreviewBusy(true);
      setPreviewError("");
      try {
        const bytes = await buildNewsletterPdf(draft, {
          ...classInfo,
          welcomeMessage: "",
          setupComplete: true,
          adminPasswordHash: "",
          adminTotpSecret: "",
          viewerTotpSecret: "",
          createdAt: "",
        });
        if (cancelled) return;
        const blob = new Blob([Uint8Array.from(bytes)], {
          type: "application/pdf",
        });
        objectUrl = URL.createObjectURL(blob);
        setPreviewUrl((prev) => {
          if (prev) URL.revokeObjectURL(prev);
          return objectUrl;
        });
      } catch (err) {
        if (!cancelled) {
          setPreviewError(
            err instanceof Error ? err.message : "Could not build preview.",
          );
        }
      } finally {
        if (!cancelled) setPreviewBusy(false);
      }
    }, 350);

    return () => {
      cancelled = true;
      window.clearTimeout(timer);
      if (objectUrl) URL.revokeObjectURL(objectUrl);
    };
  }, [draft, classInfo]);

  function updateSection(id: string, patch: Partial<NewsletterSection>) {
    setSections((prev) =>
      prev.map((s) => (s.id === id ? { ...s, ...patch } : s)),
    );
  }

  function moveSection(id: string, dir: -1 | 1) {
    setSections((prev) => {
      const index = prev.findIndex((s) => s.id === id);
      const next = index + dir;
      if (index < 0 || next < 0 || next >= prev.length) return prev;
      const copy = [...prev];
      const [item] = copy.splice(index, 1);
      copy.splice(next, 0, item);
      return copy;
    });
  }

  async function save(e: React.FormEvent) {
    e.preventDefault();
    setSaving(true);
    setError("");
    const payload = {
      id: initial?.id,
      title,
      subtitle,
      issueDate,
      published,
      designId,
      sections,
    };
    const res = await fetch(
      initial?.id
        ? `/api/admin/newsletters/${initial.id}`
        : "/api/admin/newsletters",
      {
        method: initial?.id ? "PUT" : "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(payload),
      },
    );
    const data = await res.json().catch(() => ({}));
    setSaving(false);
    if (!res.ok) {
      setError(data.error || "Could not save newsletter.");
      return;
    }
    router.push(`/admin/newsletters/${data.id}`);
    router.refresh();
  }

  return (
    <form onSubmit={save} className="space-y-8">
      <section className="space-y-3">
        <div className="flex flex-wrap items-end justify-between gap-3">
          <div>
            <h2 className="font-[family-name:var(--font-display)] text-2xl font-semibold">
              Premade PDF designs
            </h2>
            <p className="mt-1 text-sm text-[var(--ink-soft)]">
              Pick one of 10 colorful layouts. The live preview updates as you
              edit.
            </p>
          </div>
          <p className="rounded-full bg-white/80 px-4 py-2 text-sm font-bold text-[var(--sky-deep)] shadow-sm">
            Selected: {selectedDesign.name}
          </p>
        </div>
        <div className="grid gap-3 sm:grid-cols-2 lg:grid-cols-5">
          {NEWSLETTER_DESIGNS.map((design) => {
            const active = design.id === designId;
            return (
              <button
                key={design.id}
                type="button"
                onClick={() => setDesignId(design.id)}
                className={`group overflow-hidden rounded-2xl border text-left transition ${
                  active
                    ? "border-[var(--sky-deep)] shadow-[0_12px_28px_rgba(47,126,160,0.28)] ring-2 ring-[var(--sky-deep)]"
                    : "border-white/70 bg-white/70 hover:-translate-y-0.5 hover:shadow-lg"
                }`}
              >
                <div
                  className="h-16 w-full"
                  style={{
                    background: `linear-gradient(135deg, ${design.swatches[0]}, ${design.swatches[1]} 45%, ${design.swatches[2]})`,
                  }}
                />
                <div className="space-y-2 p-3">
                  <div className="flex gap-1">
                    {design.swatches.map((color) => (
                      <span
                        key={color}
                        className="h-3 w-3 rounded-full border border-black/5"
                        style={{ background: color }}
                      />
                    ))}
                  </div>
                  <p className="text-sm font-extrabold text-[var(--ink)]">
                    {design.name}
                  </p>
                  <p className="text-xs leading-snug text-[var(--ink-soft)]">
                    {design.tagline}
                  </p>
                </div>
              </button>
            );
          })}
        </div>
      </section>

      <div className="grid gap-6 xl:grid-cols-[minmax(0,1fr)_minmax(320px,0.95fr)]">
        <section className="space-y-6">
          <div className="paper-card space-y-4 rounded-3xl p-6">
            <h2 className="font-[family-name:var(--font-display)] text-xl font-semibold">
              Newsletter details
            </h2>
            <div className="grid gap-4 md:grid-cols-2">
              <div className="md:col-span-2">
                <label className="mb-2 block text-sm font-bold">Title</label>
                <input
                  className="input-field"
                  value={title}
                  onChange={(e) => setTitle(e.target.value)}
                  placeholder="March Family Newsletter"
                  required
                />
              </div>
              <div>
                <label className="mb-2 block text-sm font-bold">Subtitle</label>
                <input
                  className="input-field"
                  value={subtitle}
                  onChange={(e) => setSubtitle(e.target.value)}
                  placeholder="Reading week & spring science"
                />
              </div>
              <div>
                <label className="mb-2 block text-sm font-bold">Issue date</label>
                <input
                  type="date"
                  className="input-field"
                  value={issueDate}
                  onChange={(e) => setIssueDate(e.target.value)}
                  required
                />
              </div>
            </div>
            <label className="flex items-center gap-3 text-sm font-bold">
              <input
                type="checkbox"
                checked={published}
                onChange={(e) => setPublished(e.target.checked)}
                className="h-4 w-4 accent-[var(--sky-deep)]"
              />
              Published for families
            </label>
          </div>

          <div className="space-y-4">
            <div className="flex items-center justify-between gap-3">
              <h2 className="font-[family-name:var(--font-display)] text-xl font-semibold">
                Sections
              </h2>
              <button
                type="button"
                className="btn-secondary"
                onClick={() => setSections((s) => [...s, blankSection()])}
              >
                Add section
              </button>
            </div>
            {sections.map((section, index) => (
              <div
                key={section.id}
                className="paper-card space-y-3 rounded-2xl p-5"
                style={{
                  borderLeft: `6px solid ${selectedDesign.swatches[index % 4]}`,
                }}
              >
                <div className="flex flex-wrap items-center justify-between gap-3">
                  <p className="text-sm font-bold text-[var(--ink-soft)]">
                    Section {index + 1}
                  </p>
                  <div className="flex flex-wrap gap-2">
                    <button
                      type="button"
                      className="rounded-lg px-2 py-1 text-xs font-bold text-[var(--sky-deep)] hover:bg-sky-50"
                      onClick={() => moveSection(section.id, -1)}
                      disabled={index === 0}
                    >
                      Up
                    </button>
                    <button
                      type="button"
                      className="rounded-lg px-2 py-1 text-xs font-bold text-[var(--sky-deep)] hover:bg-sky-50"
                      onClick={() => moveSection(section.id, 1)}
                      disabled={index === sections.length - 1}
                    >
                      Down
                    </button>
                    {sections.length > 1 ? (
                      <button
                        type="button"
                        className="text-sm font-bold text-[var(--coral)]"
                        onClick={() =>
                          setSections((prev) =>
                            prev.filter((s) => s.id !== section.id),
                          )
                        }
                      >
                        Remove
                      </button>
                    ) : null}
                  </div>
                </div>
                <input
                  className="input-field"
                  placeholder="Heading"
                  value={section.heading}
                  onChange={(e) =>
                    updateSection(section.id, { heading: e.target.value })
                  }
                  required
                />
                <textarea
                  className="input-field min-h-28"
                  placeholder="What should families know?"
                  value={section.body}
                  onChange={(e) =>
                    updateSection(section.id, { body: e.target.value })
                  }
                  required
                />
              </div>
            ))}
          </div>

          {error ? (
            <p className="rounded-xl bg-red-50 px-4 py-3 text-sm font-semibold text-red-700">
              {error}
            </p>
          ) : null}

          <div className="flex flex-wrap gap-3">
            <button type="submit" className="btn-primary" disabled={saving}>
              {saving
                ? "Saving PDF…"
                : initial
                  ? "Update newsletter PDF"
                  : "Create newsletter PDF"}
            </button>
            {previewUrl ? (
              <a
                href={previewUrl}
                download={`${(title || "newsletter").replace(/\s+/g, "-").toLowerCase()}-preview.pdf`}
                className="btn-secondary inline-flex"
              >
                Download preview
              </a>
            ) : null}
          </div>
        </section>

        <aside className="xl:sticky xl:top-6 xl:self-start">
          <div className="paper-card overflow-hidden rounded-3xl">
            <div className="flex items-center justify-between gap-3 border-b border-sky-100 px-5 py-4">
              <div>
                <h2 className="font-[family-name:var(--font-display)] text-xl font-semibold">
                  Live PDF preview
                </h2>
                <p className="text-xs text-[var(--ink-soft)]">
                  {selectedDesign.name} · QR stays bottom-right
                </p>
              </div>
              <span
                className={`rounded-full px-3 py-1 text-xs font-bold ${
                  previewBusy
                    ? "bg-amber-50 text-amber-700"
                    : "bg-emerald-50 text-emerald-700"
                }`}
              >
                {previewBusy ? "Updating…" : "Ready"}
              </span>
            </div>
            <div className="bg-[#d9e7ef] p-3 sm:p-4">
              {previewError ? (
                <p className="rounded-xl bg-red-50 px-4 py-3 text-sm font-semibold text-red-700">
                  {previewError}
                </p>
              ) : previewUrl ? (
                <iframe
                  title="Newsletter PDF preview"
                  src={previewUrl}
                  className="h-[72vh] w-full rounded-xl bg-white shadow-inner"
                />
              ) : (
                <div className="flex h-[72vh] items-center justify-center rounded-xl bg-white/70 text-sm font-bold text-[var(--ink-soft)]">
                  Building preview…
                </div>
              )}
            </div>
          </div>
        </aside>
      </div>
    </form>
  );
}
