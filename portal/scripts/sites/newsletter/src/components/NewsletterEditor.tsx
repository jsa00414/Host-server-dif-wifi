"use client";

import Link from "next/link";
import {
  useEffect,
  useMemo,
  useRef,
  useState,
  type CSSProperties,
} from "react";
import { useRouter } from "next/navigation";
import {
  DEFAULT_DESIGN_ID,
  SECTION_TONES,
  SECTION_VARIANTS,
  getDesign,
  sectionsFromStarter,
} from "@/lib/designs";
import {
  PAGE_BACKGROUNDS,
  SHAPE_PALETTE,
  backgroundCss,
} from "@/lib/backgrounds";
import {
  TONE_FILL,
  designToneCss,
  rgbCss,
} from "@/lib/editorTheme";
import {
  createShapeLayer,
  reorderLayer,
  sortLayers,
} from "@/lib/layers";
import { buildNewsletterPdf } from "@/lib/pdf";
import {
  ensureSectionFrames,
  nextSectionZIndex,
} from "@/lib/sections";
import type {
  Newsletter,
  NewsletterLayer,
  NewsletterSection,
  PageBackground,
  SectionVariant,
  SectionWidth,
  ShapeKind,
  SiteConfig,
} from "@/lib/types";

type ClassInfo = Pick<
  SiteConfig,
  "className" | "teacherName" | "schoolName" | "grade" | "room"
>;

type LeftTab =
  | "elements"
  | "photos"
  | "shapes"
  | "background"
  | "text";

const SHAPE_OPTIONS: Array<{ id: ShapeKind; label: string; preview: string }> = [
  { id: "rounded", label: "Rounded", preview: "▢" },
  { id: "rect", label: "Square", preview: "■" },
  { id: "circle", label: "Circle", preview: "●" },
  { id: "ellipse", label: "Oval", preview: "⬭" },
  { id: "triangle", label: "Triangle", preview: "▲" },
  { id: "star", label: "Star", preview: "★" },
  { id: "heart", label: "Heart", preview: "♥" },
  { id: "line", label: "Line", preview: "━" },
];
type Selection =
  | { kind: "page" }
  | { kind: "header" }
  | { kind: "footer" }
  | { kind: "block"; id: string }
  | { kind: "layer"; id: string };

type DragTarget = "layer" | "section";

type DragState =
  | {
      mode: "move";
      target: DragTarget;
      id: string;
      startX: number;
      startY: number;
      origX: number;
      origY: number;
    }
  | {
      mode: "resize";
      target: DragTarget;
      id: string;
      startX: number;
      startY: number;
      origW: number;
      origH: number;
    };

const PAGE_W = 612;
const PAGE_H = 792;

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
    x: 28,
    y: 36,
    boxW: 42,
    boxH: 18,
    zIndex: 1,
    ...partial,
  };
}

function clamp(n: number, min: number, max: number) {
  return Math.min(max, Math.max(min, n));
}

/** Textarea that grows with content — never shows an inner scrollbar. */
function AutoGrowTextarea({
  value,
  onChange,
  className,
  style,
  onContentHeight,
}: {
  value: string;
  onChange: (value: string) => void;
  className?: string;
  style?: CSSProperties;
  onContentHeight?: (px: number) => void;
}) {
  const ref = useRef<HTMLTextAreaElement | null>(null);

  useEffect(() => {
    const el = ref.current;
    if (!el) return;
    el.style.height = "0px";
    const next = Math.max(24, el.scrollHeight);
    el.style.height = `${next}px`;
    onContentHeight?.(next);
    // Only remeasure when text changes — callback identity must not loop.
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [value]);

  return (
    <textarea
      ref={ref}
      className={`canva-editable canva-autogrow ${className || ""}`}
      style={style}
      value={value}
      rows={1}
      onChange={(e) => onChange(e.target.value)}
      onPointerDown={(e) => e.stopPropagation()}
    />
  );
}

export function NewsletterEditor({
  initial,
  classInfo,
}: {
  initial?: Newsletter | null;
  classInfo: ClassInfo;
}) {
  const router = useRouter();
  const fileInputRef = useRef<HTMLInputElement | null>(null);
  const [leftTab, setLeftTab] = useState<LeftTab>("elements");
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
  const [designId, setDesignId] = useState(DEFAULT_DESIGN_ID);
  const [sections, setSections] = useState<NewsletterSection[]>(() =>
    ensureSectionFrames(
      initial?.sections?.length
        ? initial.sections.map((s, i) => ({
            variant: s.variant || (i === 0 ? "banner" : "card"),
            tone: s.tone || SECTION_TONES[i % SECTION_TONES.length],
            width: s.width || (i === 0 || i === 3 ? "full" : "half"),
            ...s,
          }))
        : sectionsFromStarter(DEFAULT_DESIGN_ID),
    ),
  );
  const [layers, setLayers] = useState<NewsletterLayer[]>(
    initial?.layers || [],
  );
  const [pageBackground, setPageBackground] = useState<PageBackground | undefined>(
    initial?.pageBackground,
  );
  const [shapeFill, setShapeFill] = useState(SHAPE_PALETTE[5]);
  const [uploading, setUploading] = useState(false);
  const [drag, setDrag] = useState<DragState | null>(null);
  const [error, setError] = useState("");
  const [saving, setSaving] = useState(false);
  const [deleting, setDeleting] = useState(false);
  const [previewUrl, setPreviewUrl] = useState<string | null>(null);
  const [previewBusy, setPreviewBusy] = useState(false);

  const selectedDesign = useMemo(() => getDesign(designId), [designId]);
  const sortedSections = useMemo(
    () =>
      [...sections].sort((a, b) => (a.zIndex || 0) - (b.zIndex || 0)),
    [sections],
  );
  const sortedLayers = useMemo(() => sortLayers(layers), [layers]);

  const selectedBlock =
    selection.kind === "block"
      ? sections.find((s) => s.id === selection.id) || null
      : null;
  const selectedLayer =
    selection.kind === "layer"
      ? layers.find((l) => l.id === selection.id) || null
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
      layers,
      pageBackground,
      designId: DEFAULT_DESIGN_ID,
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
      layers,
      pageBackground,
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

  function updateLayer(id: string, patch: Record<string, unknown>) {
    setLayers((prev) =>
      prev.map((l) =>
        l.id === id ? ({ ...l, ...patch } as NewsletterLayer) : l,
      ),
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

  function removeLayer(id: string) {
    setLayers((prev) => prev.filter((l) => l.id !== id));
    setSelection({ kind: "page" });
  }

  useEffect(() => {
    function onKeyDown(e: KeyboardEvent) {
      if (e.key !== "Delete" && e.key !== "Backspace") return;
      const target = e.target as HTMLElement | null;
      if (
        target &&
        (target.tagName === "INPUT" ||
          target.tagName === "TEXTAREA" ||
          target.isContentEditable)
      ) {
        return;
      }
      if (selection.kind === "block") {
        e.preventDefault();
        removeSection(selection.id);
      } else if (selection.kind === "layer") {
        e.preventDefault();
        removeLayer(selection.id);
      }
    }
    window.addEventListener("keydown", onKeyDown);
    return () => window.removeEventListener("keydown", onKeyDown);
  }, [selection]);

  useEffect(() => {
    if (!drag) return;
    const active = drag;
    function onMove(e: PointerEvent) {
      const dx = ((e.clientX - active.startX) / zoom / PAGE_W) * 100;
      const dy = ((e.clientY - active.startY) / zoom / PAGE_H) * 100;
      if (active.target === "section") {
        if (active.mode === "move") {
          setSections((prev) =>
            prev.map((s) =>
              s.id === active.id
                ? {
                    ...s,
                    x: clamp(active.origX + dx, 0, 92),
                    y: clamp(active.origY + dy, 0, 92),
                  }
                : s,
            ),
          );
        } else {
          setSections((prev) =>
            prev.map((s) =>
              s.id === active.id
                ? {
                    ...s,
                    boxW: clamp(active.origW + dx, 12, 100 - (s.x || 0)),
                    boxH: clamp(active.origH + dy, 8, 100 - (s.y || 0)),
                  }
                : s,
            ),
          );
        }
        return;
      }
      if (active.mode === "move") {
        setLayers((prev) =>
          prev.map((l) =>
            l.id === active.id
              ? {
                  ...l,
                  x: clamp(active.origX + dx, 0, 92),
                  y: clamp(active.origY + dy, 0, 92),
                }
              : l,
          ),
        );
      } else {
        setLayers((prev) =>
          prev.map((l) =>
            l.id === active.id
              ? {
                  ...l,
                  width: clamp(active.origW + dx, 8, 100 - l.x),
                  height: clamp(active.origH + dy, 8, 100 - l.y),
                }
              : l,
          ),
        );
      }
    }
    function onUp() {
      setDrag(null);
    }
    window.addEventListener("pointermove", onMove);
    window.addEventListener("pointerup", onUp);
    return () => {
      window.removeEventListener("pointermove", onMove);
      window.removeEventListener("pointerup", onUp);
    };
  }, [drag, zoom]);

  function addShape(shape: ShapeKind) {
    const layer = createShapeLayer(shape, layers, shapeFill);
    layer.zIndex = nextSectionZIndex(sections, layers);
    setLayers((prev) => [...prev, layer]);
    setSelection({ kind: "layer", id: layer.id });
    setLeftTab("shapes");
  }

  function addElement(variant: SectionVariant) {
    const count = sections.length;
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
      x: variant === "banner" ? 6.5 : 12 + (count % 3) * 8,
      y: variant === "banner" ? 22 : 30 + (count % 4) * 6,
      boxW: variant === "banner" ? 87 : 42,
      boxH: variant === "banner" ? 16 : variant === "learning" ? 22 : 18,
      zIndex: nextSectionZIndex(sections, layers),
    });
    setSections((prev) => [...prev, section]);
    setSelection({ kind: "block", id: section.id });
    setLeftTab("elements");
  }

  async function uploadPhoto(file: File) {
    setUploading(true);
    setError("");
    try {
      const form = new FormData();
      form.append("file", file);
      const res = await fetch("/api/admin/uploads", {
        method: "POST",
        body: form,
      });
      const data = await res.json().catch(() => ({}));
      if (!res.ok) {
        setError(data.error || "Could not upload photo.");
        return;
      }
      const layer: NewsletterLayer = {
        id: crypto.randomUUID(),
        type: "image",
        name: (file.name || "Photo").replace(/\.[^.]+$/, "").slice(0, 40) || "Photo",
        src: data.url as string,
        x: 12 + (layers.length % 4) * 6,
        y: 28 + (layers.length % 3) * 8,
        width: 28,
        height: 22,
        rotation: 0,
        opacity: 1,
        zIndex: nextSectionZIndex(sections, layers),
      };
      setLayers((prev) => [...prev, layer]);
      setSelection({ kind: "layer", id: layer.id });
      setLeftTab("photos");
    } catch {
      setError("Could not upload photo.");
    } finally {
      setUploading(false);
      if (fileInputRef.current) fileInputRef.current.value = "";
    }
  }

  async function attachPhotoToBlock(file: File, blockId: string) {
    setUploading(true);
    setError("");
    try {
      const form = new FormData();
      form.append("file", file);
      const res = await fetch("/api/admin/uploads", {
        method: "POST",
        body: form,
      });
      const data = await res.json().catch(() => ({}));
      if (!res.ok) {
        setError(data.error || "Could not upload photo.");
        return;
      }
      updateSection(blockId, { imageSrc: data.url as string });
    } catch {
      setError("Could not upload photo.");
    } finally {
      setUploading(false);
    }
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
      designId: DEFAULT_DESIGN_ID,
      sections,
      layers,
      pageBackground,
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

  async function deleteNewsletter() {
    if (!initial?.id) return;
    if (
      !window.confirm(
        "Delete this newsletter and its PDF? This cannot be undone.",
      )
    ) {
      return;
    }
    setDeleting(true);
    setError("");
    const res = await fetch(`/api/admin/newsletters/${initial.id}`, {
      method: "DELETE",
    });
    setDeleting(false);
    if (!res.ok) {
      setError("Could not delete newsletter.");
      return;
    }
    router.push("/admin/newsletters");
    router.refresh();
  }

  return (
    <div className="canva-shell flex flex-col">
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
              Newsletter editor
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
          {selection.kind === "block" ? (
            <button
              type="button"
              onClick={() => removeSection(selection.id)}
              className="rounded-lg bg-red-500/20 px-3 py-1.5 text-xs font-bold text-red-200 hover:bg-red-500/30"
              title="Delete selected block (Del)"
            >
              Delete block
            </button>
          ) : null}
          {selection.kind === "layer" ? (
            <button
              type="button"
              onClick={() => removeLayer(selection.id)}
              className="rounded-lg bg-red-500/20 px-3 py-1.5 text-xs font-bold text-red-200 hover:bg-red-500/30"
              title="Delete selected layer (Del)"
            >
              Delete layer
            </button>
          ) : null}
          {initial?.id ? (
            <button
              type="button"
              onClick={() => void deleteNewsletter()}
              disabled={deleting}
              className="rounded-lg bg-red-600/90 px-3 py-1.5 text-xs font-bold text-white hover:bg-red-500 disabled:opacity-60"
            >
              {deleting ? "Deleting…" : "Delete"}
            </button>
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
        <nav className="canva-rail flex flex-col items-center gap-2 py-3">
          {(
            [
              ["elements", "Elements", "＋"],
              ["photos", "Photos", "▣"],
              ["shapes", "Shapes", "◇"],
              ["background", "Backgrd", "▤"],
              ["text", "Text", "T"],
            ] as const
          ).map(([id, label, icon]) => (
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
              <span className="text-lg leading-none">{icon}</span>
              {label}
            </button>
          ))}
        </nav>

        <aside className="canva-panel flex min-h-0 flex-col overflow-hidden">
          <div className="border-b border-white/10 px-4 py-3">
            <p className="text-sm font-bold text-white">
              {leftTab === "elements"
                ? "Elements"
                : leftTab === "photos"
                  ? "Photos"
                  : leftTab === "shapes"
                    ? "Shapes"
                    : leftTab === "background"
                      ? "Backgrounds"
                      : "Text & page"}
            </p>
            <p className="mt-0.5 text-[11px] text-[#8090a3]">
              {leftTab === "elements"
                ? "Add blocks to the canvas"
                : leftTab === "photos"
                  ? "Upload photos and stack them on the page"
                  : leftTab === "shapes"
                    ? "Add rectangles, stars, hearts, and more"
                    : leftTab === "background"
                      ? "Pick a solid color or patterned page"
                      : "Edit title, banner, and footer"}
            </p>
          </div>
          <div className="min-h-0 flex-1 overflow-y-auto p-3">
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
                  onClick={() => {
                    setDesignId(DEFAULT_DESIGN_ID);
                    setSections(sectionsFromStarter(DEFAULT_DESIGN_ID));
                    setPageBackground(undefined);
                  }}
                >
                  Reset to starter blocks
                </button>
              </div>
            ) : null}

            {leftTab === "photos" ? (
              <div className="space-y-3">
                <input
                  ref={fileInputRef}
                  type="file"
                  accept="image/jpeg,image/png,image/webp,image/gif"
                  className="hidden"
                  onChange={(e) => {
                    const file = e.target.files?.[0];
                    if (file) void uploadPhoto(file);
                  }}
                />
                <button
                  type="button"
                  disabled={uploading}
                  onClick={() => fileInputRef.current?.click()}
                  className="w-full rounded-xl border border-dashed border-violet-400/50 bg-violet-600/20 px-3 py-4 text-sm font-bold text-violet-100 hover:bg-violet-600/30 disabled:opacity-60"
                >
                  {uploading ? "Uploading…" : "Upload photo"}
                </button>
                <p className="text-[11px] leading-relaxed text-[#8090a3]">
                  Photos sit on the page as free layers. Drag to move, use the
                  corner to resize, and set stacking order in properties.
                </p>
                {sortedLayers.some((l) => l.type === "image") ? (
                  <div className="space-y-2">
                    <p className="text-[11px] font-bold uppercase tracking-wide text-[#8090a3]">
                      Photos (top = front)
                    </p>
                    {[...sortedLayers]
                      .reverse()
                      .filter((l) => l.type === "image")
                      .map((layer) => {
                        const active =
                          selection.kind === "layer" &&
                          selection.id === layer.id;
                        return (
                          <button
                            key={layer.id}
                            type="button"
                            onClick={() =>
                              setSelection({ kind: "layer", id: layer.id })
                            }
                            className={`flex w-full items-center gap-2 rounded-xl border px-2 py-2 text-left ${
                              active
                                ? "border-violet-400 bg-violet-600/20"
                                : "border-white/10 bg-white/5 hover:bg-white/10"
                            }`}
                          >
                            {/* eslint-disable-next-line @next/next/no-img-element */}
                            <img
                              src={layer.src}
                              alt=""
                              className="h-10 w-10 rounded-md object-cover"
                            />
                            <span className="min-w-0 flex-1">
                              <span className="block truncate text-xs font-bold text-white">
                                {layer.name}
                              </span>
                              <span className="block text-[10px] text-[#8090a3]">
                                z {layer.zIndex}
                              </span>
                            </span>
                          </button>
                        );
                      })}
                  </div>
                ) : (
                  <p className="rounded-xl bg-white/5 px-3 py-3 text-xs text-[#9fb0c3]">
                    No photos yet — upload one to place it on the newsletter.
                  </p>
                )}
              </div>
            ) : null}

            {leftTab === "shapes" ? (
              <div className="space-y-3">
                <div>
                  <p className="mb-2 text-[11px] font-bold uppercase tracking-wide text-[#8090a3]">
                    Fill color
                  </p>
                  <div className="grid grid-cols-6 gap-1.5">
                    {SHAPE_PALETTE.map((c) => (
                      <button
                        key={c}
                        type="button"
                        title={c}
                        onClick={() => setShapeFill(c)}
                        className={`h-7 rounded-md border-2 ${
                          shapeFill === c
                            ? "border-violet-400"
                            : "border-transparent"
                        }`}
                        style={{ background: c }}
                      />
                    ))}
                  </div>
                </div>
                <div className="grid grid-cols-2 gap-2">
                  {SHAPE_OPTIONS.map((opt) => (
                    <button
                      key={opt.id}
                      type="button"
                      onClick={() => addShape(opt.id)}
                      className="flex items-center gap-2 rounded-xl border border-white/10 bg-white/5 px-3 py-3 text-left hover:bg-white/10"
                    >
                      <span
                        className="flex h-9 w-9 items-center justify-center rounded-lg text-lg"
                        style={{
                          background:
                            opt.id === "line" ? "transparent" : shapeFill,
                          color: opt.id === "line" ? shapeFill : "#fff",
                          border:
                            opt.id === "line"
                              ? `3px solid ${shapeFill}`
                              : "none",
                        }}
                      >
                        {opt.preview}
                      </span>
                      <span className="text-xs font-bold text-white">
                        {opt.label}
                      </span>
                    </button>
                  ))}
                </div>
                {sortedLayers.some((l) => l.type === "shape") ? (
                  <div className="space-y-2">
                    <p className="text-[11px] font-bold uppercase tracking-wide text-[#8090a3]">
                      Shape layers
                    </p>
                    {[...sortedLayers]
                      .reverse()
                      .filter((l) => l.type === "shape")
                      .map((layer) => {
                        const active =
                          selection.kind === "layer" &&
                          selection.id === layer.id;
                        return (
                          <button
                            key={layer.id}
                            type="button"
                            onClick={() =>
                              setSelection({ kind: "layer", id: layer.id })
                            }
                            className={`flex w-full items-center gap-2 rounded-xl border px-2 py-2 text-left ${
                              active
                                ? "border-violet-400 bg-violet-600/20"
                                : "border-white/10 bg-white/5 hover:bg-white/10"
                            }`}
                          >
                            <span
                              className="h-8 w-8 rounded-md"
                              style={{ background: layer.fill }}
                            />
                            <span className="min-w-0 flex-1">
                              <span className="block truncate text-xs font-bold text-white">
                                {layer.name}
                              </span>
                              <span className="block text-[10px] text-[#8090a3]">
                                {layer.shape} · z {layer.zIndex}
                              </span>
                            </span>
                          </button>
                        );
                      })}
                  </div>
                ) : null}
              </div>
            ) : null}

            {leftTab === "background" ? (
              <div className="space-y-3">
                <button
                  type="button"
                  className="w-full rounded-xl border border-dashed border-white/20 px-3 py-2 text-xs font-bold text-[#9fb0c3] hover:bg-white/5"
                  onClick={() => setPageBackground(undefined)}
                >
                  Use template default background
                </button>
                <div className="grid grid-cols-2 gap-2">
                  {PAGE_BACKGROUNDS.map((bg) => {
                    const active =
                      pageBackground?.pattern === bg.pattern &&
                      (pageBackground?.color === bg.color ||
                        (!pageBackground?.color && bg.pattern === "solid"));
                    const isActive =
                      active ||
                      (bg.id.startsWith("solid-") &&
                        pageBackground?.color === bg.color &&
                        (pageBackground?.pattern === "solid" ||
                          pageBackground?.pattern === bg.pattern));
                    return (
                      <button
                        key={bg.id}
                        type="button"
                        onClick={() =>
                          setPageBackground({
                            color: bg.color,
                            pattern: bg.pattern,
                          })
                        }
                        className={`overflow-hidden rounded-xl border text-left ${
                          isActive
                            ? "border-violet-400 ring-2 ring-violet-500/40"
                            : "border-white/10 hover:border-white/25"
                        }`}
                      >
                        <div
                          className="h-14"
                          style={backgroundCss(selectedDesign, {
                            color: bg.color,
                            pattern: bg.pattern,
                          })}
                        />
                        <div className="px-2 py-1.5">
                          <p className="text-[11px] font-bold text-white">
                            {bg.name}
                          </p>
                        </div>
                      </button>
                    );
                  })}
                </div>
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
                  style={backgroundCss(selectedDesign, pageBackground)}
                  onClick={() => setSelection({ kind: "page" })}
                >
                  {/* Decorative accents by design */}

                  <div
                    className="canva-selectable relative z-[1] px-8 pb-3 pt-7"
                    data-selected={selection.kind === "header"}
                    onClick={(e) => {
                      e.stopPropagation();
                      setSelection({ kind: "header" });
                      setLeftTab("text");
                    }}
                  >
                    {selectedDesign.headerStyle === "chunky-bar" ||
                    selectedDesign.headerStyle === "spots-band" ? (
                      <div
                        className={`mb-3 rounded-xl px-4 py-5 text-center ${
                          selectedDesign.headerStyle === "spots-band"
                            ? "bg-[radial-gradient(circle,_#fff_2px,_transparent_2.5px)] bg-[length:16px_16px]"
                            : ""
                        }`}
                        style={{
                          backgroundColor: rgbCss(selectedDesign.bannerBar),
                          color: rgbCss(selectedDesign.bannerText),
                        }}
                      >
                        <input
                          className="canva-editable text-center text-[26px] font-black uppercase tracking-wide"
                          style={{ color: rgbCss(selectedDesign.bannerText) }}
                          value={title}
                          onChange={(e) => setTitle(e.target.value)}
                          placeholder="Classroom"
                        />
                        <p className="mt-1 text-xs font-extrabold tracking-[0.2em] opacity-90">
                          NEWSLETTER
                        </p>
                      </div>
                    ) : selectedDesign.headerStyle === "ink-banner" ? (
                      <div className="mb-3 rounded border-2 border-neutral-900 px-4 py-4 text-center">
                        <input
                          className="canva-editable text-center text-[24px] font-black uppercase tracking-wide text-neutral-900"
                          value={title}
                          onChange={(e) => setTitle(e.target.value)}
                          placeholder="Classroom"
                        />
                        <p className="mt-1 border-t border-dashed border-neutral-400 pt-2 text-xs font-bold tracking-widest text-neutral-700">
                          CLASSROOM NEWSLETTER
                        </p>
                      </div>
                    ) : (
                      <>
                        <input
                          className="canva-editable text-center font-[Georgia,Times,serif] text-[32px] font-bold leading-none"
                          style={{ color: rgbCss(selectedDesign.scriptColor) }}
                          value={title}
                          onChange={(e) => setTitle(e.target.value)}
                          placeholder="Classroom"
                        />
                        <p
                          className="mt-2 text-center text-sm font-extrabold uppercase tracking-[0.18em]"
                          style={{ color: rgbCss(selectedDesign.bannerBar) }}
                        >
                          Newsletter
                        </p>
                      </>
                    )}
                    <p className="mt-2 text-[11px]" style={{ color: rgbCss(selectedDesign.muted) }}>
                      {classInfo.className} · {classInfo.grade} · Room{" "}
                      {classInfo.room} · {issueDate}
                    </p>
                    <div
                      className={`mt-4 flex items-center justify-center px-3 py-2 text-center text-xs font-extrabold tracking-wide ${
                        selectedDesign.headerStyle === "soft-pill"
                          ? "rounded-full"
                          : "rounded-md"
                      }`}
                      style={{
                        background: rgbCss(selectedDesign.bannerBar),
                        color: rgbCss(selectedDesign.bannerText),
                      }}
                    >
                      <input
                        className="canva-editable text-center text-xs font-extrabold uppercase tracking-wide placeholder:opacity-70"
                        style={{ color: rgbCss(selectedDesign.bannerText) }}
                        value={bannerLabel}
                        onChange={(e) => setBannerLabel(e.target.value)}
                        placeholder="CLASS NEWS"
                      />
                    </div>
                  </div>

                  {/* Free-position text boxes (Canva-style) */}
                  {sortedSections.map((section) => {
                    const toneKey = section.tone || "blue";
                    const tone = designToneCss(selectedDesign, toneKey);
                    const variant = section.variant || "card";
                    const selected =
                      selection.kind === "block" && selection.id === section.id;
                    const cardStyle = selectedDesign.cardStyle;
                    const cardBoxStyle: CSSProperties =
                      cardStyle === "outlined" || cardStyle === "dashed"
                        ? {
                            background: "#fff",
                            border: `${cardStyle === "dashed" ? "1.5px dashed" : "2.5px solid"} ${tone.border}`,
                          }
                        : cardStyle === "ink"
                          ? {
                              background: "#fff",
                              border: "2px solid #111",
                              boxShadow: "inset 0 0 0 1px #111",
                            }
                          : cardStyle === "top-strip"
                            ? {
                                background: tone.fill,
                                borderTop: `10px solid ${tone.bar}`,
                              }
                            : { background: tone.fill };

                    const growBoxToFit = (contentPx: number) => {
                      const neededPct = (contentPx / PAGE_H) * 100 + 4;
                      const current = section.boxH || 16;
                      if (neededPct > current + 0.4) {
                        updateSection(section.id, {
                          boxH: clamp(neededPct, 8, 100 - (section.y || 0)),
                        });
                      }
                    };

                    return (
                      <div
                        key={section.id}
                        className="absolute cursor-move overflow-hidden rounded-2xl"
                        style={{
                          left: `${section.x ?? 6.5}%`,
                          top: `${section.y ?? 22}%`,
                          width: `${section.boxW ?? 42}%`,
                          height: `${section.boxH ?? 16}%`,
                          zIndex: 10 + (section.zIndex || 1),
                          outline: selected
                            ? "2px solid #8b5cf6"
                            : "2px solid transparent",
                          boxShadow: selected
                            ? "0 0 0 4px rgba(139, 92, 246, 0.25)"
                            : undefined,
                          ...cardBoxStyle,
                          ...(variant === "banner"
                            ? { background: "transparent", border: "none" }
                            : null),
                        }}
                        onClick={(e) => {
                          e.stopPropagation();
                          setSelection({ kind: "block", id: section.id });
                          setLeftTab("elements");
                        }}
                        onPointerDown={(e) => {
                          if ((e.target as HTMLElement).dataset.resize) return;
                          const tag = (e.target as HTMLElement).tagName;
                          if (
                            tag === "INPUT" ||
                            tag === "TEXTAREA" ||
                            tag === "BUTTON"
                          ) {
                            return;
                          }
                          e.stopPropagation();
                          e.preventDefault();
                          setSelection({ kind: "block", id: section.id });
                          setDrag({
                            mode: "move",
                            target: "section",
                            id: section.id,
                            startX: e.clientX,
                            startY: e.clientY,
                            origX: section.x ?? 6.5,
                            origY: section.y ?? 22,
                          });
                        }}
                      >
                        {selected ? (
                          <>
                            <button
                              type="button"
                              className="absolute -right-2 -top-2 z-20 rounded-full bg-red-600 px-2 py-1 text-[10px] font-bold text-white shadow-lg hover:bg-red-500"
                              onClick={(e) => {
                                e.stopPropagation();
                                removeSection(section.id);
                              }}
                              title="Delete block"
                            >
                              Delete
                            </button>
                            <span
                              data-resize="1"
                              className="absolute -bottom-1.5 -right-1.5 z-20 h-3.5 w-3.5 cursor-se-resize rounded-sm border-2 border-white bg-violet-500"
                              onPointerDown={(e) => {
                                e.stopPropagation();
                                e.preventDefault();
                                setDrag({
                                  mode: "resize",
                                  target: "section",
                                  id: section.id,
                                  startX: e.clientX,
                                  startY: e.clientY,
                                  origW: section.boxW ?? 42,
                                  origH: section.boxH ?? 16,
                                });
                              }}
                            />
                          </>
                        ) : null}

                        {variant === "banner" ? (
                          <div className="flex h-full flex-col gap-1.5 overflow-hidden p-0">
                            <div
                              className="rounded-md px-2 py-1.5 text-white"
                              style={{ background: tone.bar }}
                            >
                              <input
                                className="canva-editable text-center text-[11px] font-extrabold uppercase tracking-wide text-white"
                                value={section.heading}
                                onChange={(e) =>
                                  updateSection(section.id, {
                                    heading: e.target.value,
                                  })
                                }
                                onPointerDown={(e) => e.stopPropagation()}
                              />
                            </div>
                            <div
                              className="min-h-0 flex-1 overflow-hidden rounded-xl p-2"
                              style={cardBoxStyle}
                            >
                              <AutoGrowTextarea
                                className="whitespace-pre-wrap text-[12px] leading-relaxed"
                                style={{ color: tone.body }}
                                value={section.body}
                                onChange={(body) =>
                                  updateSection(section.id, { body })
                                }
                                onContentHeight={(px) =>
                                  growBoxToFit(px + 36)
                                }
                              />
                            </div>
                          </div>
                        ) : (
                          <div className="flex h-full flex-col overflow-hidden p-3">
                            <input
                              className="canva-editable shrink-0 text-[13px] font-extrabold uppercase tracking-wide"
                              style={{ color: tone.heading }}
                              value={section.heading}
                              onChange={(e) =>
                                updateSection(section.id, {
                                  heading: e.target.value,
                                })
                              }
                              onPointerDown={(e) => e.stopPropagation()}
                            />
                            <div className="min-h-0 flex-1 overflow-hidden">
                              <AutoGrowTextarea
                                className="mt-1 whitespace-pre-wrap text-[12px] leading-relaxed"
                                style={{ color: tone.body }}
                                value={section.body}
                                onChange={(body) =>
                                  updateSection(section.id, { body })
                                }
                                onContentHeight={(px) =>
                                  growBoxToFit(
                                    px + 40 + (section.imageSrc ? 80 : 0),
                                  )
                                }
                              />
                            </div>
                            {section.imageSrc ? (
                              // eslint-disable-next-line @next/next/no-img-element
                              <img
                                src={section.imageSrc}
                                alt=""
                                className="mt-2 max-h-20 w-full shrink-0 rounded-lg object-cover"
                                draggable={false}
                              />
                            ) : null}
                          </div>
                        )}
                      </div>
                    );
                  })}

                  {/* Free photo + shape layers */}
                  {sortedLayers.map((layer) => {
                    const selected =
                      selection.kind === "layer" && selection.id === layer.id;
                    const shapeStyle =
                      layer.type === "shape"
                        ? layer.shape === "circle"
                          ? {
                              background: layer.fill,
                              borderRadius: "9999px",
                              border:
                                layer.strokeWidth > 0
                                  ? `${layer.strokeWidth}px solid ${layer.stroke}`
                                  : undefined,
                            }
                          : layer.shape === "ellipse"
                            ? {
                                background: layer.fill,
                                borderRadius: "50%",
                                border:
                                  layer.strokeWidth > 0
                                    ? `${layer.strokeWidth}px solid ${layer.stroke}`
                                    : undefined,
                              }
                            : layer.shape === "rounded"
                              ? {
                                  background: layer.fill,
                                  borderRadius: "18px",
                                  border:
                                    layer.strokeWidth > 0
                                      ? `${layer.strokeWidth}px solid ${layer.stroke}`
                                      : undefined,
                                }
                              : layer.shape === "rect"
                                ? {
                                    background: layer.fill,
                                    border:
                                      layer.strokeWidth > 0
                                        ? `${layer.strokeWidth}px solid ${layer.stroke}`
                                        : undefined,
                                  }
                                : layer.shape === "triangle"
                                  ? {
                                      background: layer.fill,
                                      clipPath: "polygon(50% 0%, 100% 100%, 0% 100%)",
                                    }
                                  : layer.shape === "star"
                                    ? {
                                        background: layer.fill,
                                        clipPath:
                                          "polygon(50% 0%, 61% 35%, 98% 35%, 68% 57%, 79% 91%, 50% 70%, 21% 91%, 32% 57%, 2% 35%, 39% 35%)",
                                      }
                                    : layer.shape === "heart"
                                      ? {
                                          color: layer.fill,
                                          fontSize: "min(18vw, 72px)",
                                          display: "flex",
                                          alignItems: "center",
                                          justifyContent: "center",
                                          lineHeight: 1,
                                        }
                                      : layer.shape === "line"
                                        ? {
                                            background: layer.fill,
                                            borderRadius: "9999px",
                                            height: "100%",
                                          }
                                        : { background: layer.fill }
                        : undefined;
                    return (
                      <div
                        key={layer.id}
                        className="absolute cursor-move"
                        style={{
                          left: `${layer.x}%`,
                          top: `${layer.y}%`,
                          width: `${layer.width}%`,
                          height: `${layer.height}%`,
                          zIndex: 20 + layer.zIndex,
                          opacity: layer.opacity,
                          transform: layer.rotation
                            ? `rotate(${layer.rotation}deg)`
                            : undefined,
                          outline: selected
                            ? "2px solid #8b5cf6"
                            : "2px solid transparent",
                          boxShadow: selected
                            ? "0 0 0 4px rgba(139, 92, 246, 0.25)"
                            : undefined,
                        }}
                        onClick={(e) => {
                          e.stopPropagation();
                          setSelection({ kind: "layer", id: layer.id });
                          setLeftTab(layer.type === "shape" ? "shapes" : "photos");
                        }}
                        onPointerDown={(e) => {
                          if ((e.target as HTMLElement).dataset.resize) return;
                          e.stopPropagation();
                          e.preventDefault();
                          setSelection({ kind: "layer", id: layer.id });
                          setDrag({
                            mode: "move",
                            target: "layer",
                            id: layer.id,
                            startX: e.clientX,
                            startY: e.clientY,
                            origX: layer.x,
                            origY: layer.y,
                          });
                        }}
                      >
                        {layer.type === "image" ? (
                          // eslint-disable-next-line @next/next/no-img-element
                          <img
                            src={layer.src}
                            alt={layer.name}
                            className="pointer-events-none h-full w-full select-none rounded-sm object-cover"
                            draggable={false}
                          />
                        ) : layer.shape === "heart" ? (
                          <div
                            className="pointer-events-none flex h-full w-full select-none items-center justify-center"
                            style={shapeStyle}
                          >
                            ♥
                          </div>
                        ) : (
                          <div
                            className="pointer-events-none h-full w-full"
                            style={shapeStyle}
                          />
                        )}
                        {selected ? (
                          <>
                            <button
                              type="button"
                              className="absolute -right-2 -top-2 z-10 rounded-full bg-red-600 px-2 py-1 text-[10px] font-bold text-white shadow-lg hover:bg-red-500"
                              onClick={(e) => {
                                e.stopPropagation();
                                removeLayer(layer.id);
                              }}
                            >
                              Delete
                            </button>
                            <span
                              data-resize="1"
                              className="absolute -bottom-1.5 -right-1.5 h-3.5 w-3.5 cursor-se-resize rounded-sm border-2 border-white bg-violet-500"
                              onPointerDown={(e) => {
                                e.stopPropagation();
                                e.preventDefault();
                                setDrag({
                                  mode: "resize",
                                  target: "layer",
                                  id: layer.id,
                                  startX: e.clientX,
                                  startY: e.clientY,
                                  origW: layer.width,
                                  origH: layer.height,
                                });
                              }}
                            />
                          </>
                        ) : null}
                      </div>
                    );
                  })}

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
                  <div className="absolute bottom-3 right-6 z-[100] flex h-16 w-16 items-center justify-center rounded-md border-2 border-dashed border-neutral-300 bg-white text-[9px] font-bold text-neutral-400">
                    QR
                  </div>
                </div>
              </div>
            )}
          </div>
        </main>

        <aside className="canva-props flex min-h-0 flex-col overflow-hidden">
          <div className="border-b border-white/10 px-4 py-3">
            <p className="text-sm font-bold text-white">
              {selection.kind === "block"
                ? "Block properties"
                : selection.kind === "layer"
                  ? selectedLayer?.type === "shape"
                    ? "Shape layer"
                    : "Photo layer"
                  : selection.kind === "header"
                    ? "Header properties"
                    : selection.kind === "footer"
                      ? "Footer properties"
                      : "Page properties"}
            </p>
            <p className="mt-0.5 text-[11px] text-[#8090a3]">
              {selection.kind === "layer" || selection.kind === "block"
                ? "Drag to move · corner handle to resize · no text scroll"
                : "Click anything on the canvas to edit it"}
            </p>
          </div>
          <div className="min-h-0 flex-1 space-y-4 overflow-y-auto p-4">
            {selection.kind === "page" ? (
              <>
                <p className="text-xs leading-relaxed text-[#9fb0c3]">
                  Drag text boxes, photos, and shapes freely. Text boxes grow
                  with content — no scrollbars inside cards.
                </p>
                <div className="rounded-xl bg-white/5 p-3 text-xs text-[#c5d0dc]">
                  Blocks: {sections.length}
                  <br />
                  Photos: {layers.filter((l) => l.type === "image").length}
                  <br />
                  Shapes: {layers.filter((l) => l.type === "shape").length}
                  <br />
                  Background:{" "}
                  {pageBackground?.pattern || pageBackground?.color || "white"}
                </div>
              </>
            ) : null}

            {selection.kind === "header" || selection.kind === "footer" ? (
              <p className="text-xs text-[#9fb0c3]">
                Edit directly on the canvas, or use the Text panel on the left.
              </p>
            ) : null}

            {selectedLayer ? (
              <>
                <label className="block text-[11px] font-bold text-[#9fb0c3]">
                  Name
                  <input
                    className="mt-1 w-full rounded-lg border border-white/10 bg-[#0f1520] px-3 py-2 text-sm text-white"
                    value={selectedLayer.name}
                    onChange={(e) =>
                      updateLayer(selectedLayer.id, { name: e.target.value })
                    }
                  />
                </label>

                {selectedLayer.type === "shape" ? (
                  <div>
                    <p className="mb-2 text-[11px] font-bold uppercase tracking-wide text-[#8090a3]">
                      Shape color
                    </p>
                    <div className="grid grid-cols-6 gap-1.5">
                      {SHAPE_PALETTE.map((c) => (
                        <button
                          key={c}
                          type="button"
                          onClick={() =>
                            updateLayer(selectedLayer.id, { fill: c })
                          }
                          className={`h-7 rounded-md border-2 ${
                            selectedLayer.fill === c
                              ? "border-violet-400"
                              : "border-transparent"
                          }`}
                          style={{ background: c }}
                        />
                      ))}
                    </div>
                  </div>
                ) : null}

                <div>
                  <p className="mb-2 text-[11px] font-bold uppercase tracking-wide text-[#8090a3]">
                    Layering
                  </p>
                  <div className="grid grid-cols-2 gap-2">
                    {(
                      [
                        ["front", "Bring front"],
                        ["forward", "Forward"],
                        ["backward", "Backward"],
                        ["back", "Send back"],
                      ] as const
                    ).map(([action, label]) => (
                      <button
                        key={action}
                        type="button"
                        className="canva-chip canva-chip-idle"
                        onClick={() =>
                          setLayers((prev) =>
                            reorderLayer(prev, selectedLayer.id, action),
                          )
                        }
                      >
                        {label}
                      </button>
                    ))}
                  </div>
                  <p className="mt-2 text-[11px] text-[#8090a3]">
                    Current order: {selectedLayer.zIndex} of {layers.length}
                  </p>
                </div>

                <label className="block text-[11px] font-bold text-[#9fb0c3]">
                  Opacity ({Math.round(selectedLayer.opacity * 100)}%)
                  <input
                    type="range"
                    min={10}
                    max={100}
                    value={Math.round(selectedLayer.opacity * 100)}
                    className="mt-2 w-full"
                    onChange={(e) =>
                      updateLayer(selectedLayer.id, {
                        opacity: Number(e.target.value) / 100,
                      })
                    }
                  />
                </label>

                <label className="block text-[11px] font-bold text-[#9fb0c3]">
                  Rotation ({selectedLayer.rotation}°)
                  <input
                    type="range"
                    min={-45}
                    max={45}
                    value={selectedLayer.rotation}
                    className="mt-2 w-full"
                    onChange={(e) =>
                      updateLayer(selectedLayer.id, {
                        rotation: Number(e.target.value),
                      })
                    }
                  />
                </label>

                <div className="grid grid-cols-2 gap-2">
                  <label className="block text-[11px] font-bold text-[#9fb0c3]">
                    Width %
                    <input
                      type="number"
                      min={8}
                      max={100}
                      className="mt-1 w-full rounded-lg border border-white/10 bg-[#0f1520] px-2 py-1.5 text-sm text-white"
                      value={Math.round(selectedLayer.width)}
                      onChange={(e) =>
                        updateLayer(selectedLayer.id, {
                          width: clamp(Number(e.target.value) || 8, 8, 100),
                        })
                      }
                    />
                  </label>
                  <label className="block text-[11px] font-bold text-[#9fb0c3]">
                    Height %
                    <input
                      type="number"
                      min={8}
                      max={100}
                      className="mt-1 w-full rounded-lg border border-white/10 bg-[#0f1520] px-2 py-1.5 text-sm text-white"
                      value={Math.round(selectedLayer.height)}
                      onChange={(e) =>
                        updateLayer(selectedLayer.id, {
                          height: clamp(Number(e.target.value) || 8, 8, 100),
                        })
                      }
                    />
                  </label>
                </div>

                <button
                  type="button"
                  className="canva-chip bg-red-500/20 text-red-200"
                  onClick={() => removeLayer(selectedLayer.id)}
                >
                  Delete layer
                </button>
              </>
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

                <div className="grid grid-cols-2 gap-2">
                  <label className="block text-[11px] font-bold text-[#9fb0c3]">
                    X %
                    <input
                      type="number"
                      min={0}
                      max={92}
                      className="mt-1 w-full rounded-lg border border-white/10 bg-[#0f1520] px-2 py-1.5 text-sm text-white"
                      value={Math.round(selectedBlock.x ?? 0)}
                      onChange={(e) =>
                        updateSection(selectedBlock.id, {
                          x: clamp(Number(e.target.value) || 0, 0, 92),
                        })
                      }
                    />
                  </label>
                  <label className="block text-[11px] font-bold text-[#9fb0c3]">
                    Y %
                    <input
                      type="number"
                      min={0}
                      max={92}
                      className="mt-1 w-full rounded-lg border border-white/10 bg-[#0f1520] px-2 py-1.5 text-sm text-white"
                      value={Math.round(selectedBlock.y ?? 0)}
                      onChange={(e) =>
                        updateSection(selectedBlock.id, {
                          y: clamp(Number(e.target.value) || 0, 0, 92),
                        })
                      }
                    />
                  </label>
                  <label className="block text-[11px] font-bold text-[#9fb0c3]">
                    Width %
                    <input
                      type="number"
                      min={12}
                      max={100}
                      className="mt-1 w-full rounded-lg border border-white/10 bg-[#0f1520] px-2 py-1.5 text-sm text-white"
                      value={Math.round(selectedBlock.boxW ?? 42)}
                      onChange={(e) =>
                        updateSection(selectedBlock.id, {
                          boxW: clamp(Number(e.target.value) || 12, 12, 100),
                          width:
                            (Number(e.target.value) || 12) >= 70
                              ? ("full" as SectionWidth)
                              : ("half" as SectionWidth),
                        })
                      }
                    />
                  </label>
                  <label className="block text-[11px] font-bold text-[#9fb0c3]">
                    Height %
                    <input
                      type="number"
                      min={8}
                      max={90}
                      className="mt-1 w-full rounded-lg border border-white/10 bg-[#0f1520] px-2 py-1.5 text-sm text-white"
                      value={Math.round(selectedBlock.boxH ?? 16)}
                      onChange={(e) =>
                        updateSection(selectedBlock.id, {
                          boxH: clamp(Number(e.target.value) || 8, 8, 90),
                        })
                      }
                    />
                  </label>
                </div>

                {selectedBlock.variant !== "banner" ? (
                  <div>
                    <p className="mb-2 text-[11px] font-bold uppercase tracking-wide text-[#8090a3]">
                      Block photo
                    </p>
                    {selectedBlock.imageSrc ? (
                      <div className="space-y-2">
                        {/* eslint-disable-next-line @next/next/no-img-element */}
                        <img
                          src={selectedBlock.imageSrc}
                          alt=""
                          className="h-24 w-full rounded-lg object-cover"
                        />
                        <button
                          type="button"
                          className="canva-chip canva-chip-idle"
                          onClick={() =>
                            updateSection(selectedBlock.id, {
                              imageSrc: undefined,
                            })
                          }
                        >
                          Remove photo
                        </button>
                      </div>
                    ) : (
                      <label className="flex cursor-pointer items-center justify-center rounded-xl border border-dashed border-white/20 px-3 py-3 text-xs font-bold text-[#9fb0c3] hover:bg-white/5">
                        {uploading ? "Uploading…" : "Add photo to block"}
                        <input
                          type="file"
                          accept="image/jpeg,image/png,image/webp,image/gif"
                          className="hidden"
                          disabled={uploading}
                          onChange={(e) => {
                            const file = e.target.files?.[0];
                            if (file)
                              void attachPhotoToBlock(file, selectedBlock.id);
                            e.target.value = "";
                          }}
                        />
                      </label>
                    )}
                  </div>
                ) : null}

                <div>
                  <p className="mb-2 text-[11px] font-bold uppercase tracking-wide text-[#8090a3]">
                    Layering
                  </p>
                  <div className="grid grid-cols-2 gap-2">
                    <button
                      type="button"
                      className="canva-chip canva-chip-idle"
                      onClick={() =>
                        updateSection(selectedBlock.id, {
                          zIndex: nextSectionZIndex(sections, layers),
                        })
                      }
                    >
                      Bring front
                    </button>
                    <button
                      type="button"
                      className="canva-chip canva-chip-idle"
                      onClick={() =>
                        updateSection(selectedBlock.id, { zIndex: 1 })
                      }
                    >
                      Send back
                    </button>
                    <button
                      type="button"
                      className="canva-chip canva-chip-idle"
                      onClick={() => moveSection(selectedBlock.id, -1)}
                    >
                      Earlier in list
                    </button>
                    <button
                      type="button"
                      className="canva-chip canva-chip-idle"
                      onClick={() => moveSection(selectedBlock.id, 1)}
                    >
                      Later in list
                    </button>
                  </div>
                </div>

                <button
                  type="button"
                  className="canva-chip bg-red-500/20 text-red-200"
                  onClick={() => removeSection(selectedBlock.id)}
                >
                  Delete block
                </button>
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
