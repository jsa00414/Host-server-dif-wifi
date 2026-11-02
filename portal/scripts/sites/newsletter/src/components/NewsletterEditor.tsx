"use client";

import { useEffect, useMemo, useState } from "react";
import { useRouter } from "next/navigation";
import {
  DEFAULT_DESIGN_ID,
  NEWSLETTER_DESIGNS,
  SECTION_TONES,
  SECTION_VARIANTS,
  getDesign,
  sectionsFromStarter,
} from "@/lib/designs";
import { buildNewsletterPdf } from "@/lib/pdf";
import type {
  Newsletter,
  NewsletterSection,
  SectionTone,
  SectionVariant,
  SectionWidth,
  SiteConfig,
} from "@/lib/types";

function blankSection(
  partial?: Partial<NewsletterSection>,
): NewsletterSection {
  return {
    id: crypto.randomUUID(),
    heading: "",
    body: "",
    variant: "card",
    tone: "blue",
    width: "half",
    ...partial,
  };
}

type ClassInfo = Pick<
  SiteConfig,
  "className" | "teacherName" | "schoolName" | "grade" | "room"
>;

const TONE_HEX: Record<SectionTone, string> = {
  green: "#D2EFC6",
  blue: "#C9E6F5",
  pink: "#FAD6E0",
  orange: "#FFE0BC",
  yellow: "#FFF4B4",
  lavender: "#E6DCFA",
  coral: "#FFD6CD",
  mint: "#CDF2E6",
};

export function NewsletterEditor({
  initial,
  classInfo,
}: {
  initial?: Newsletter | null;
  classInfo: ClassInfo;
}) {
  const router = useRouter();
  const [title, setTitle] = useState(
    initial?.title || classInfo.className || "Classroom",
  );
  const [subtitle, setSubtitle] = useState(initial?.subtitle || "");
  const [bannerLabel, setBannerLabel] = useState(
    initial?.bannerLabel ||
      `${new Date().toLocaleString("en-US", { month: "long" }).toUpperCase()} CLASS NEWS`,
  );
  const [footerNote, setFooterNote] = useState(
    initial?.footerNote ||
      `Questions? Email ${classInfo.teacherName.replace(/\s+/g, ".").toLowerCase()}@school.org · Room ${classInfo.room}`,
  );
  const [issueDate, setIssueDate] = useState(
    initial?.issueDate || new Date().toISOString().slice(0, 10),
  );
  const [published, setPublished] = useState(initial?.published ?? true);
  const [designId, setDesignId] = useState(
    initial?.designId || DEFAULT_DESIGN_ID,
  );
  const [sections, setSections] = useState<NewsletterSection[]>(
    initial?.sections?.length
      ? initial.sections.map((s, i) => ({
          variant: s.variant || (i === 0 ? "banner" : "card"),
          tone: s.tone || SECTION_TONES[i % SECTION_TONES.length],
          width: s.width || (i === 0 || i === 3 ? "full" : "half"),
          ...s,
        }))
      : sectionsFromStarter(DEFAULT_DESIGN_ID),
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
      title: title || "Classroom",
      subtitle,
      bannerLabel,
      footerNote,
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
      bannerLabel,
      footerNote,
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
    }, 280);

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

  function applyDesign(nextId: string, loadStarter: boolean) {
    setDesignId(nextId);
    if (loadStarter) {
      setSections(sectionsFromStarter(nextId));
      const design = getDesign(nextId);
      if (!initial?.bannerLabel) {
        setBannerLabel(
          `${new Date().toLocaleString("en-US", { month: "long" }).toUpperCase()} CLASS NEWS`,
        );
      }
      if (!title) setTitle(classInfo.className || design.name);
    }
  }

  async function save(e: React.FormEvent) {
    e.preventDefault();
    setSaving(true);
    setError("");
    const payload = {
      id: initial?.id,
      title,
      subtitle,
      bannerLabel,
      footerNote,
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
              Classroom PDF designs
            </h2>
            <p className="mt-1 text-sm text-[var(--ink-soft)]">
              Pick a colorful modular template — pastel blocks, banners, and
              decorations like the sample newsletter.
            </p>
          </div>
          <p className="rounded-full bg-white/80 px-4 py-2 text-sm font-bold text-[var(--sky-deep)] shadow-sm">
            {selectedDesign.name}
          </p>
        </div>
        <div className="grid gap-3 sm:grid-cols-2 lg:grid-cols-5">
          {NEWSLETTER_DESIGNS.map((design) => {
            const active = design.id === designId;
            return (
              <button
                key={design.id}
                type="button"
                onClick={() => applyDesign(design.id, !initial)}
                className={`overflow-hidden rounded-2xl border text-left transition ${
                  active
                    ? "border-[var(--sky-deep)] ring-2 ring-[var(--sky-deep)] shadow-lg"
                    : "border-white/80 bg-white/80 hover:-translate-y-0.5 hover:shadow-md"
                }`}
              >
                <div className="relative h-20 p-2" style={{ background: "#fff" }}>
                  <div
                    className="absolute inset-x-2 top-2 h-3 rounded-full"
                    style={{ background: design.swatches[0] }}
                  />
                  <div className="mt-5 grid grid-cols-2 gap-1">
                    <div
                      className="h-8 rounded-md"
                      style={{ background: design.swatches[1] }}
                    />
                    <div
                      className="h-8 rounded-md"
                      style={{ background: design.swatches[2] }}
                    />
                    <div
                      className="col-span-2 h-5 rounded-md"
                      style={{ background: design.swatches[3] }}
                    />
                  </div>
                </div>
                <div className="space-y-1 p-3">
                  <p className="text-sm font-extrabold">{design.name}</p>
                  <p className="text-[11px] leading-snug text-[var(--ink-soft)]">
                    {design.tagline}
                  </p>
                </div>
              </button>
            );
          })}
        </div>
        <div className="flex flex-wrap gap-2">
          <button
            type="button"
            className="btn-secondary"
            onClick={() => applyDesign(designId, true)}
          >
            Load starter blocks for this design
          </button>
        </div>
      </section>

      <div className="grid gap-6 xl:grid-cols-[minmax(0,1.05fr)_minmax(340px,0.95fr)]">
        <section className="space-y-5">
          <div className="paper-card space-y-4 rounded-3xl p-6">
            <h2 className="font-[family-name:var(--font-display)] text-xl font-semibold">
              Header & footer
            </h2>
            <div className="grid gap-4 md:grid-cols-2">
              <div>
                <label className="mb-2 block text-sm font-bold">
                  Script title (top)
                </label>
                <input
                  className="input-field"
                  value={title}
                  onChange={(e) => setTitle(e.target.value)}
                  placeholder="Classroom"
                  required
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
              <div className="md:col-span-2">
                <label className="mb-2 block text-sm font-bold">
                  Green banner label
                </label>
                <input
                  className="input-field"
                  value={bannerLabel}
                  onChange={(e) => setBannerLabel(e.target.value)}
                  placeholder="AUGUST CLASS NEWS"
                />
              </div>
              <div className="md:col-span-2">
                <label className="mb-2 block text-sm font-bold">
                  Short subtitle (optional)
                </label>
                <input
                  className="input-field"
                  value={subtitle}
                  onChange={(e) => setSubtitle(e.target.value)}
                  placeholder="Welcome back families"
                />
              </div>
              <div className="md:col-span-2">
                <label className="mb-2 block text-sm font-bold">
                  Footer contact line
                </label>
                <input
                  className="input-field"
                  value={footerNote}
                  onChange={(e) => setFooterNote(e.target.value)}
                  placeholder="Questions? teacher@school.org"
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
            <div className="flex flex-wrap items-center justify-between gap-3">
              <h2 className="font-[family-name:var(--font-display)] text-xl font-semibold">
                Content blocks
              </h2>
              <div className="flex flex-wrap gap-2">
                <button
                  type="button"
                  className="btn-secondary"
                  onClick={() =>
                    setSections((s) => [
                      ...s,
                      blankSection({
                        variant: "card",
                        tone: "blue",
                        width: "half",
                        heading: "New block",
                      }),
                    ])
                  }
                >
                  Add card
                </button>
                <button
                  type="button"
                  className="btn-secondary"
                  onClick={() =>
                    setSections((s) => [
                      ...s,
                      blankSection({
                        variant: "banner",
                        tone: "green",
                        width: "full",
                        heading: "Class news",
                      }),
                    ])
                  }
                >
                  Add banner
                </button>
              </div>
            </div>

            {sections.map((section, index) => (
              <div
                key={section.id}
                className="space-y-3 rounded-3xl border border-black/5 p-5 shadow-sm"
                style={{
                  background: TONE_HEX[section.tone || "blue"],
                }}
              >
                <div className="flex flex-wrap items-center justify-between gap-2">
                  <p className="text-sm font-extrabold uppercase tracking-wide text-black/60">
                    Block {index + 1}
                  </p>
                  <div className="flex flex-wrap gap-2">
                    <button
                      type="button"
                      className="rounded-lg bg-white/70 px-2 py-1 text-xs font-bold"
                      onClick={() => moveSection(section.id, -1)}
                      disabled={index === 0}
                    >
                      Up
                    </button>
                    <button
                      type="button"
                      className="rounded-lg bg-white/70 px-2 py-1 text-xs font-bold"
                      onClick={() => moveSection(section.id, 1)}
                      disabled={index === sections.length - 1}
                    >
                      Down
                    </button>
                    {sections.length > 1 ? (
                      <button
                        type="button"
                        className="rounded-lg bg-white/70 px-2 py-1 text-xs font-bold text-[var(--coral)]"
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

                <div className="grid gap-3 md:grid-cols-3">
                  <label className="text-xs font-bold">
                    Style
                    <select
                      className="input-field mt-1"
                      value={section.variant || "card"}
                      onChange={(e) =>
                        updateSection(section.id, {
                          variant: e.target.value as SectionVariant,
                          width:
                            e.target.value === "banner"
                              ? "full"
                              : section.width || "half",
                        })
                      }
                    >
                      {SECTION_VARIANTS.map((v) => (
                        <option key={v.id} value={v.id}>
                          {v.label}
                        </option>
                      ))}
                    </select>
                  </label>
                  <label className="text-xs font-bold">
                    Color
                    <select
                      className="input-field mt-1"
                      value={section.tone || "blue"}
                      onChange={(e) =>
                        updateSection(section.id, {
                          tone: e.target.value as SectionTone,
                        })
                      }
                    >
                      {SECTION_TONES.map((t) => (
                        <option key={t} value={t}>
                          {t}
                        </option>
                      ))}
                    </select>
                  </label>
                  <label className="text-xs font-bold">
                    Width
                    <select
                      className="input-field mt-1"
                      value={section.width || "half"}
                      onChange={(e) =>
                        updateSection(section.id, {
                          width: e.target.value as SectionWidth,
                        })
                      }
                    >
                      <option value="full">Full width</option>
                      <option value="half">Half (side-by-side)</option>
                    </select>
                  </label>
                </div>

                <input
                  className="input-field bg-white/90"
                  placeholder="Heading"
                  value={section.heading}
                  onChange={(e) =>
                    updateSection(section.id, { heading: e.target.value })
                  }
                  required
                />
                <textarea
                  className="input-field min-h-28 bg-white/90"
                  placeholder="Write the block text. Use new lines for event lists."
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

        <aside className="xl:sticky xl:top-4 xl:self-start">
          <div className="paper-card overflow-hidden rounded-3xl">
            <div className="flex items-center justify-between gap-3 border-b border-sky-100 px-5 py-4">
              <div>
                <h2 className="font-[family-name:var(--font-display)] text-xl font-semibold">
                  Live PDF preview
                </h2>
                <p className="text-xs text-[var(--ink-soft)]">
                  {selectedDesign.name} · QR bottom-right for slideshow
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
            <div className="bg-[#e7eef3] p-3 sm:p-4">
              {previewError ? (
                <p className="rounded-xl bg-red-50 px-4 py-3 text-sm font-semibold text-red-700">
                  {previewError}
                </p>
              ) : previewUrl ? (
                <iframe
                  title="Newsletter PDF preview"
                  src={previewUrl}
                  className="h-[78vh] w-full rounded-xl bg-white shadow-inner"
                />
              ) : (
                <div className="flex h-[78vh] items-center justify-center rounded-xl bg-white/70 text-sm font-bold text-[var(--ink-soft)]">
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
