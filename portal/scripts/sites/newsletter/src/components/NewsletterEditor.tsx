"use client";

import Link from "next/link";
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
import {
  TONE_FILL,
  TONE_HEADING,
  letterColorCss,
  rgbCss,
} from "@/lib/editorTheme";
import { buildNewsletterPdf } from "@/lib/pdf";
import type {
  Newsletter,
  NewsletterSection,
  SectionTone,
  SectionVariant,
  SectionWidth,
  SiteConfig,
} from "@/lib/types";

type ClassInfo = Pick<
  SiteConfig,
  "className" | "teacherName" | "schoolName" | "grade" | "room"
>;

type LeftTab = "templates" | "elements" | "text";
type Selection =
  | { kind: "page" }
  | { kind: "header" }
  | { kind: "footer" }
  | { kind: "block"; id: string };

function blankSection(
  partial?: Partial<NewsletterSection>,
): NewsletterSection {
  return {
    id: crypto.randomUUID(),
    heading: "New block",
    body: "Click to edit this text.",
    variant: "card",
    tone: "blue",
    width: "half",
    ...partial,
  };
}

function pairRows(sections: NewsletterSection[]) {
  const rows: Array<NewsletterSection[]> = [];
  let i = 0;
  while (i < sections.length) {
    const cur = sections[i];
    const width = cur.width || (cur.variant === "banner" ? "full" : "half");
    const next = sections[i + 1];
    if (
      width === "half" &&
      next &&
      (next.width || "half") === "half" &&
      next.variant !== "banner"
    ) {
      rows.push([cur, next]);
      i += 2;
    } else {
      rows.push([cur]);
      i += 1;
    }
  }
  return rows;
}

export function NewsletterEditor({
  initial,
  classInfo,
}: {
  initial?: Newsletter | null;
  classInfo: ClassInfo;
}) {
  const router = useRouter();
  const [leftTab, setLeftTab] = useState<LeftTab>("templates");
  const [selection, setSelection] = useState<Selection>({ kind: "page" });
  const [zoom, setZoom] = useState(0.82);
  const [showPdf, setShowPdf] = useState(false);

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

  const selectedDesign = useMemo(() => getDesign(designId), [designId]);
  const letterColors = useMemo(
    () => letterColorCss(selectedDesign),
    [selectedDesign],
  );
  const rows = useMemo(() => pairRows(sections), [sections]);

  const selectedBlock =
    selection.kind === "block"
      ? sections.find((s) => s.id === selection.id) || null
      : null;

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
      } catch {
        /* canvas is primary; PDF preview is secondary */
      } finally {
        if (!cancelled) setPreviewBusy(false);
      }
    }, 400);
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

  function removeSection(id: string) {
    setSections((prev) => {
      if (prev.length <= 1) return prev;
      return prev.filter((s) => s.id !== id);
    });
    setSelection({ kind: "page" });
  }

  function applyDesign(nextId: string, loadStarter: boolean) {
    setDesignId(nextId);
    if (loadStarter) setSections(sectionsFromStarter(nextId));
    setLeftTab("templates");
  }

  function addElement(variant: SectionVariant) {
    const section = blankSection({
      variant,
      tone: variant === "banner" ? "green" : variant === "learning" ? "orange" : "blue",
      width: variant === "banner" ? "full" : "half",
      heading:
        variant === "banner"
          ? "Class news"
          : variant === "list"
            ? "Upcoming events"
            : variant === "learning"
              ? "What we're learning"
              : "New card",
      body:
        variant === "list"
          ? "Mon – Event one\nWed – Event two"
          : variant === "learning"
            ? "READING: …\nMATH: …\nSCIENCE: …\nART: …"
            : "Add your family update here.",
    });
    setSections((prev) => [...prev, section]);
    setSelection({ kind: "block", id: section.id });
    setLeftTab("elements");
  }

  async function save() {
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
    <div className="canva-shell flex flex-col">
      {/* Top bar */}
      <header className="canva-topbar flex items-center justify-between gap-3 px-3">
        <div className="flex min-w-0 items-center gap-3">
          <Link
            href="/admin/newsletters"
            className="rounded-lg px-2 py-1 text-sm font-semibold text-[#9fb0c3] hover:bg-white/5 hover:text-white"
          >
            ←
          </Link>
          <div className="min-w-0">
            <p className="truncate text-sm font-bold text-white">
              {title || "Untitled newsletter"}
            </p>
            <p className="truncate text-[11px] text-[#8090a3]">
              {selectedDesign.name} · Canva-style editor
            </p>
          </div>
        </div>
        <div className="flex flex-wrap items-center gap-2">
          <button
            type="button"
            className="rounded-lg bg-white/5 px-3 py-1.5 text-xs font-bold text-[#c5d0dc] hover:bg-white/10"
            onClick={() => setZoom((z) => Math.max(0.5, Number((z - 0.08).toFixed(2))))}
          >
            −
          </button>
          <span className="w-12 text-center text-xs font-bold text-[#9fb0c3]">
            {Math.round(zoom * 100)}%
          </span>
          <button
            type="button"
            className="rounded-lg bg-white/5 px-3 py-1.5 text-xs font-bold text-[#c5d0dc] hover:bg-white/10"
            onClick={() => setZoom((z) => Math.min(1.25, Number((z + 0.08).toFixed(2))))}
          >
            +
          </button>
          <button
            type="button"
            className={`rounded-lg px-3 py-1.5 text-xs font-bold ${
              showPdf ? "bg-violet-600 text-white" : "bg-white/5 text-[#c5d0dc]"
            }`}
            onClick={() => setShowPdf((v) => !v)}
          >
            {showPdf ? "Canvas" : "PDF view"}
          </button>
          {previewUrl ? (
            <a
              href={previewUrl}
              download={`${(title || "newsletter").replace(/\s+/g, "-").toLowerCase()}.pdf`}
              className="rounded-lg bg-white/5 px-3 py-1.5 text-xs font-bold text-[#c5d0dc] hover:bg-white/10"
            >
              Download
            </a>
          ) : null}
          {initial?.slideshowToken ? (
            <a
              href={`/s/${initial.slideshowToken}`}
              target="_blank"
              rel="noreferrer"
              className="rounded-lg bg-white/5 px-3 py-1.5 text-xs font-bold text-[#c5d0dc] hover:bg-white/10"
            >
              Slideshow
            </a>
          ) : null}
          <button
            type="button"
            onClick={() => void save()}
            disabled={saving}
            className="rounded-lg bg-violet-600 px-4 py-1.5 text-xs font-bold text-white hover:bg-violet-500 disabled:opacity-60"
          >
            {saving ? "Saving…" : previewBusy ? "Save PDF" : "Save PDF"}
          </button>
        </div>
      </header>

      <div className="flex min-h-0 flex-1">
        {/* Icon rail */}
        <nav className="canva-rail flex flex-col items-center gap-2 py-3">
          {(
            [
              ["templates", "Design"],
              ["elements", "Elements"],
              ["text", "Text"],
            ] as const
          ).map(([id, label]) => (
            <button
              key={id}
              type="button"
              onClick={() => setLeftTab(id)}
              className={`flex w-16 flex-col items-center gap-1 rounded-xl px-1 py-2 text-[10px] font-bold ${
                leftTab === id
                  ? "bg-violet-600/30 text-white"
                  : "text-[#8fa0b3] hover:bg-white/5 hover:text-white"
              }`}
            >
              <span className="text-lg leading-none">
                {id === "templates" ? "▦" : id === "elements" ? "＋" : "T"}
              </span>
              {label}
            </button>
          ))}
        </nav>

        {/* Left panel */}
        <aside className="canva-panel flex min-h-0 flex-col overflow-hidden">
          <div className="border-b border-white/10 px-4 py-3">
            <p className="text-sm font-bold text-white">
              {leftTab === "templates"
                ? "Templates"
                : leftTab === "elements"
                  ? "Elements"
                  : "Text & page"}
            </p>
            <p className="mt-0.5 text-[11px] text-[#8090a3]">
              {leftTab === "templates"
                ? "Click a design to restyle the page"
                : leftTab === "elements"
                  ? "Add colorful blocks to the canvas"
                  : "Edit title, banner, and footer"}
            </p>
          </div>
          <div className="min-h-0 flex-1 overflow-y-auto p-3">
            {leftTab === "templates" ? (
              <div className="grid grid-cols-2 gap-2">
                {NEWSLETTER_DESIGNS.map((design) => {
                  const active = design.id === designId;
                  return (
                    <button
                      key={design.id}
                      type="button"
                      onClick={() => applyDesign(design.id, !initial)}
                      className={`overflow-hidden rounded-xl border text-left ${
                        active
                          ? "border-violet-400 ring-2 ring-violet-500/50"
                          : "border-white/10 hover:border-white/25"
                      }`}
                    >
                      <div className="bg-white p-1.5">
                        <div
                          className="mb-1 h-2 rounded-full"
                          style={{ background: design.swatches[0] }}
                        />
                        <div className="grid grid-cols-2 gap-1">
                          <div
                            className="h-7 rounded"
                            style={{ background: design.swatches[1] }}
                          />
                          <div
                            className="h-7 rounded"
                            style={{ background: design.swatches[2] }}
                          />
                        </div>
                      </div>
                      <div className="px-2 py-1.5">
                        <p className="text-[11px] font-bold text-white">
                          {design.name}
                        </p>
                      </div>
                    </button>
                  );
                })}
              </div>
            ) : null}

            {leftTab === "elements" ? (
              <div className="space-y-2">
                {(
                  [
                    ["banner", "Banner strip", "Full-width news bar"],
                    ["list", "Events list", "Half-width list card"],
                    ["learning", "Learning card", "Subjects & skills"],
                    ["card", "Color card", "Notes & reminders"],
                  ] as const
                ).map(([variant, label, hint]) => (
                  <button
                    key={variant}
                    type="button"
                    onClick={() => addElement(variant)}
                    className="flex w-full items-center gap-3 rounded-xl border border-white/10 bg-white/5 px-3 py-3 text-left hover:bg-white/10"
                  >
                    <span
                      className="h-10 w-10 rounded-lg"
                      style={{
                        background:
                          variant === "banner"
                            ? TONE_FILL.green
                            : variant === "list"
                              ? TONE_FILL.blue
                              : variant === "learning"
                                ? TONE_FILL.orange
                                : TONE_FILL.pink,
                      }}
                    />
                    <span>
                      <span className="block text-sm font-bold text-white">
                        {label}
                      </span>
                      <span className="block text-[11px] text-[#8090a3]">
                        {hint}
                      </span>
                    </span>
                  </button>
                ))}
                <button
                  type="button"
                  className="mt-2 w-full rounded-xl border border-dashed border-white/20 px-3 py-2 text-xs font-bold text-[#9fb0c3] hover:bg-white/5"
                  onClick={() => applyDesign(designId, true)}
                >
                  Reset to template starter blocks
                </button>
              </div>
            ) : null}

            {leftTab === "text" ? (
              <div className="space-y-3">
                <label className="block text-[11px] font-bold text-[#9fb0c3]">
                  Script title
                  <input
                    className="mt-1 w-full rounded-lg border border-white/10 bg-[#0f1520] px-3 py-2 text-sm text-white"
                    value={title}
                    onChange={(e) => setTitle(e.target.value)}
                    onFocus={() => setSelection({ kind: "header" })}
                  />
                </label>
                <label className="block text-[11px] font-bold text-[#9fb0c3]">
                  Banner label
                  <input
                    className="mt-1 w-full rounded-lg border border-white/10 bg-[#0f1520] px-3 py-2 text-sm text-white"
                    value={bannerLabel}
                    onChange={(e) => setBannerLabel(e.target.value)}
                    onFocus={() => setSelection({ kind: "header" })}
                  />
                </label>
                <label className="block text-[11px] font-bold text-[#9fb0c3]">
                  Subtitle
                  <input
                    className="mt-1 w-full rounded-lg border border-white/10 bg-[#0f1520] px-3 py-2 text-sm text-white"
                    value={subtitle}
                    onChange={(e) => setSubtitle(e.target.value)}
                  />
                </label>
                <label className="block text-[11px] font-bold text-[#9fb0c3]">
                  Footer
                  <input
                    className="mt-1 w-full rounded-lg border border-white/10 bg-[#0f1520] px-3 py-2 text-sm text-white"
                    value={footerNote}
                    onChange={(e) => setFooterNote(e.target.value)}
                    onFocus={() => setSelection({ kind: "footer" })}
                  />
                </label>
                <label className="block text-[11px] font-bold text-[#9fb0c3]">
                  Issue date
                  <input
                    type="date"
                    className="mt-1 w-full rounded-lg border border-white/10 bg-[#0f1520] px-3 py-2 text-sm text-white"
                    value={issueDate}
                    onChange={(e) => setIssueDate(e.target.value)}
                  />
                </label>
                <label className="flex items-center gap-2 text-xs font-bold text-[#c5d0dc]">
                  <input
                    type="checkbox"
                    checked={published}
                    onChange={(e) => setPublished(e.target.checked)}
                  />
                  Published for families
                </label>
              </div>
            ) : null}
          </div>
        </aside>

        {/* Center stage */}
        <main
          className="canva-stage min-w-0 flex-1 overflow-auto"
          onClick={() => setSelection({ kind: "page" })}
        >
          <div className="flex min-h-full justify-center px-6 py-8">
            {showPdf && previewUrl ? (
              <iframe
                title="PDF preview"
                src={previewUrl}
                className="h-[85vh] w-[min(900px,100%)] rounded-xl bg-white shadow-2xl"
                onClick={(e) => e.stopPropagation()}
              />
            ) : (
              <div
                style={{ transform: `scale(${zoom})`, transformOrigin: "top center" }}
                onClick={(e) => e.stopPropagation()}
              >
                <div
                  className="canva-page relative overflow-hidden rounded-sm"
                  style={{ background: rgbCss(selectedDesign.pageBg) }}
                  onClick={() => setSelection({ kind: "page" })}
                >
                  {/* decorations */}
                  <div className="pointer-events-none absolute right-4 top-3 flex gap-1">
                    {letterColors.slice(0, 7).map((c, i) => (
                      <span
                        key={i}
                        className="h-3.5 w-3.5 rounded-full"
                        style={{ background: c }}
                      />
                    ))}
                  </div>
                  <div className="pointer-events-none absolute left-6 top-5 text-lg text-yellow-400">
                    ★
                  </div>
                  <div className="pointer-events-none absolute left-14 top-10 text-sm text-sky-400">
                    ★
                  </div>

                  {/* Header */}
                  <div
                    className="canva-selectable px-8 pb-3 pt-8"
                    data-selected={selection.kind === "header"}
                    onClick={(e) => {
                      e.stopPropagation();
                      setSelection({ kind: "header" });
                      setLeftTab("text");
                    }}
                  >
                    <input
                      className="canva-editable font-[Georgia,Times,serif] text-[34px] italic leading-none text-neutral-900"
                      value={title}
                      onChange={(e) => setTitle(e.target.value)}
                      placeholder="Classroom"
                    />
                    <div className="mt-2 flex flex-wrap gap-[2px] font-black tracking-wide">
                      {"NEWSLETTER".split("").map((ch, i) => (
                        <span
                          key={`${ch}-${i}`}
                          className="text-[34px] leading-none"
                          style={{ color: letterColors[i % letterColors.length] }}
                        >
                          {ch}
                        </span>
                      ))}
                    </div>
                    <p className="mt-2 text-[11px] text-neutral-500">
                      {classInfo.className} · {classInfo.grade} · Room{" "}
                      {classInfo.room} · {issueDate}
                    </p>
                    <div
                      className="mt-4 flex items-center justify-center rounded-md px-3 py-2 text-center text-xs font-extrabold tracking-wide text-white"
                      style={{ background: rgbCss(selectedDesign.bannerBar) }}
                    >
                      <input
                        className="canva-editable text-center text-xs font-extrabold uppercase tracking-wide text-white placeholder:text-white/70"
                        value={bannerLabel}
                        onChange={(e) => setBannerLabel(e.target.value)}
                        placeholder="CLASS NEWS"
                      />
                    </div>
                  </div>

                  {/* Blocks */}
                  <div className="space-y-3 px-8 pb-24 pt-2">
                    {rows.map((row) => (
                      <div
                        key={row.map((r) => r.id).join("-")}
                        className={`grid gap-3 ${row.length === 2 ? "grid-cols-2" : "grid-cols-1"}`}
                      >
                        {row.map((section) => {
                          const tone = section.tone || "blue";
                          const variant = section.variant || "card";
                          const selected =
                            selection.kind === "block" &&
                            selection.id === section.id;
                          if (variant === "banner") {
                            return (
                              <div
                                key={section.id}
                                className="canva-selectable space-y-2"
                                data-selected={selected}
                                onClick={(e) => {
                                  e.stopPropagation();
                                  setSelection({
                                    kind: "block",
                                    id: section.id,
                                  });
                                }}
                              >
                                <div
                                  className="rounded-md px-2 py-2 text-white"
                                  style={{
                                    background: rgbCss(selectedDesign.bannerBar),
                                  }}
                                >
                                  <input
                                    className="canva-editable text-center text-[11px] font-extrabold uppercase tracking-wide text-white"
                                    value={section.heading}
                                    onChange={(e) =>
                                      updateSection(section.id, {
                                        heading: e.target.value,
                                      })
                                    }
                                  />
                                </div>
                                <div
                                  className="rounded-xl p-3"
                                  style={{ background: TONE_FILL[tone] }}
                                >
                                  <textarea
                                    className="canva-editable min-h-16 text-[12px] leading-relaxed text-neutral-700"
                                    value={section.body}
                                    onChange={(e) =>
                                      updateSection(section.id, {
                                        body: e.target.value,
                                      })
                                    }
                                  />
                                </div>
                              </div>
                            );
                          }
                          return (
                            <div
                              key={section.id}
                              className="canva-selectable relative rounded-2xl p-3"
                              data-selected={selected}
                              style={{ background: TONE_FILL[tone] }}
                              onClick={(e) => {
                                e.stopPropagation();
                                setSelection({ kind: "block", id: section.id });
                              }}
                            >
                              <input
                                className="canva-editable text-[13px] font-extrabold uppercase tracking-wide"
                                style={{ color: TONE_HEADING[tone] }}
                                value={section.heading}
                                onChange={(e) =>
                                  updateSection(section.id, {
                                    heading: e.target.value,
                                  })
                                }
                              />
                              <textarea
                                className="canva-editable mt-1 min-h-24 whitespace-pre-wrap text-[12px] leading-relaxed text-neutral-700"
                                value={section.body}
                                onChange={(e) =>
                                  updateSection(section.id, {
                                    body: e.target.value,
                                  })
                                }
                              />
                              {variant === "learning" ? (
                                <div className="pointer-events-none absolute bottom-2 right-3 text-2xl">
                                  🌈
                                </div>
                              ) : null}
                            </div>
                          );
                        })}
                      </div>
                    ))}
                  </div>

                  {/* Footer */}
                  <div
                    className="canva-selectable absolute bottom-3 left-8 right-24"
                    data-selected={selection.kind === "footer"}
                    onClick={(e) => {
                      e.stopPropagation();
                      setSelection({ kind: "footer" });
                      setLeftTab("text");
                    }}
                  >
                    <div
                      className="rounded-lg px-3 py-2"
                      style={{ background: rgbCss(selectedDesign.footerBar) }}
                    >
                      <input
                        className="canva-editable text-[11px]"
                        style={{ color: rgbCss(selectedDesign.footerText) }}
                        value={footerNote}
                        onChange={(e) => setFooterNote(e.target.value)}
                      />
                    </div>
                  </div>
                  <div className="absolute bottom-3 right-6 flex h-16 w-16 items-center justify-center rounded-md border-2 border-dashed border-neutral-300 bg-white text-[9px] font-bold text-neutral-400">
                    QR
                  </div>
                </div>
              </div>
            )}
          </div>
        </main>

        {/* Right properties */}
        <aside className="canva-props flex min-h-0 flex-col overflow-hidden">
          <div className="border-b border-white/10 px-4 py-3">
            <p className="text-sm font-bold text-white">
              {selection.kind === "block"
                ? "Block properties"
                : selection.kind === "header"
                  ? "Header properties"
                  : selection.kind === "footer"
                    ? "Footer properties"
                    : "Page properties"}
            </p>
            <p className="mt-0.5 text-[11px] text-[#8090a3]">
              Click anything on the canvas to edit it
            </p>
          </div>
          <div className="min-h-0 flex-1 space-y-4 overflow-y-auto p-4">
            {selection.kind === "page" ? (
              <>
                <p className="text-xs leading-relaxed text-[#9fb0c3]">
                  Use the left sidebar for templates and elements. Zoom and
                  switch to PDF view from the top bar.
                </p>
                <div className="rounded-xl bg-white/5 p-3 text-xs text-[#c5d0dc]">
                  Design: <strong>{selectedDesign.name}</strong>
                  <br />
                  Blocks: {sections.length}
                </div>
              </>
            ) : null}

            {selection.kind === "header" || selection.kind === "footer" ? (
              <p className="text-xs text-[#9fb0c3]">
                Edit directly on the canvas, or use the Text panel on the left.
              </p>
            ) : null}

            {selectedBlock ? (
              <>
                <div>
                  <p className="mb-2 text-[11px] font-bold uppercase tracking-wide text-[#8090a3]">
                    Style
                  </p>
                  <div className="grid grid-cols-2 gap-2">
                    {SECTION_VARIANTS.map((v) => (
                      <button
                        key={v.id}
                        type="button"
                        className={`canva-chip ${
                          selectedBlock.variant === v.id
                            ? "canva-chip-active"
                            : "canva-chip-idle"
                        }`}
                        onClick={() =>
                          updateSection(selectedBlock.id, {
                            variant: v.id,
                            width: v.id === "banner" ? "full" : selectedBlock.width,
                          })
                        }
                      >
                        {v.label}
                      </button>
                    ))}
                  </div>
                </div>

                <div>
                  <p className="mb-2 text-[11px] font-bold uppercase tracking-wide text-[#8090a3]">
                    Color
                  </p>
                  <div className="grid grid-cols-4 gap-2">
                    {SECTION_TONES.map((tone) => (
                      <button
                        key={tone}
                        type="button"
                        title={tone}
                        onClick={() =>
                          updateSection(selectedBlock.id, { tone })
                        }
                        className={`h-9 rounded-lg border-2 ${
                          selectedBlock.tone === tone
                            ? "border-violet-400"
                            : "border-transparent"
                        }`}
                        style={{ background: TONE_FILL[tone] }}
                      />
                    ))}
                  </div>
                </div>

                <div>
                  <p className="mb-2 text-[11px] font-bold uppercase tracking-wide text-[#8090a3]">
                    Width
                  </p>
                  <div className="grid grid-cols-2 gap-2">
                    {(
                      [
                        ["full", "Full"],
                        ["half", "Half"],
                      ] as const
                    ).map(([id, label]) => (
                      <button
                        key={id}
                        type="button"
                        className={`canva-chip ${
                          (selectedBlock.width || "half") === id
                            ? "canva-chip-active"
                            : "canva-chip-idle"
                        }`}
                        onClick={() =>
                          updateSection(selectedBlock.id, {
                            width: id as SectionWidth,
                          })
                        }
                      >
                        {label}
                      </button>
                    ))}
                  </div>
                </div>

                <div className="flex flex-wrap gap-2">
                  <button
                    type="button"
                    className="canva-chip canva-chip-idle"
                    onClick={() => moveSection(selectedBlock.id, -1)}
                  >
                    Move up
                  </button>
                  <button
                    type="button"
                    className="canva-chip canva-chip-idle"
                    onClick={() => moveSection(selectedBlock.id, 1)}
                  >
                    Move down
                  </button>
                  <button
                    type="button"
                    className="canva-chip bg-red-500/20 text-red-200"
                    onClick={() => removeSection(selectedBlock.id)}
                  >
                    Delete
                  </button>
                </div>
              </>
            ) : null}

            {error ? (
              <p className="rounded-lg bg-red-500/20 px-3 py-2 text-xs font-semibold text-red-200">
                {error}
              </p>
            ) : null}
          </div>
        </aside>
      </div>
    </div>
  );
}
