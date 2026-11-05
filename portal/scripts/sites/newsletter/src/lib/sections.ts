import type {
  NewsletterSection,
  SectionTone,
  SectionVariant,
  SectionWidth,
} from "./types";

function newId() {
  if (typeof crypto !== "undefined" && "randomUUID" in crypto) {
    return crypto.randomUUID();
  }
  return `sec-${Date.now()}-${Math.random().toString(36).slice(2, 8)}`;
}

const TONES = new Set<SectionTone>([
  "green",
  "blue",
  "pink",
  "orange",
  "yellow",
  "lavender",
  "coral",
  "mint",
]);

const VARIANTS = new Set<SectionVariant>([
  "banner",
  "card",
  "list",
  "learning",
]);

function asTone(value: unknown, fallback: SectionTone): SectionTone {
  return typeof value === "string" && TONES.has(value as SectionTone)
    ? (value as SectionTone)
    : fallback;
}

function asVariant(value: unknown, fallback: SectionVariant): SectionVariant {
  return typeof value === "string" && VARIANTS.has(value as SectionVariant)
    ? (value as SectionVariant)
    : fallback;
}

function asWidth(value: unknown, fallback: SectionWidth): SectionWidth {
  return value === "full" || value === "half" ? value : fallback;
}

function clampNum(
  value: unknown,
  fallback: number,
  min: number,
  max: number,
) {
  const n = Number(value);
  if (!Number.isFinite(n)) return fallback;
  return Math.min(max, Math.max(min, n));
}

function hasFrame(s: Partial<NewsletterSection>) {
  return (
    Number.isFinite(Number(s.x)) &&
    Number.isFinite(Number(s.y)) &&
    Number.isFinite(Number(s.boxW)) &&
    Number.isFinite(Number(s.boxH))
  );
}

/** Default Canva-style frames from legacy full/half flow order. */
export function defaultFramesForSections(
  sections: Array<Partial<NewsletterSection>>,
): Array<{ x: number; y: number; boxW: number; boxH: number; zIndex: number }> {
  const frames: Array<{
    x: number;
    y: number;
    boxW: number;
    boxH: number;
    zIndex: number;
  }> = new Array(sections.length);
  let y = 22;
  let i = 0;
  let z = 1;
  while (i < sections.length) {
    const cur = sections[i];
    const width =
      cur.width ||
      (cur.variant === "banner" || i === 0 || i === 3 ? "full" : "half");
    const next = sections[i + 1];
    const nextWidth = next
      ? next.width || (next.variant === "banner" ? "full" : "half")
      : null;
    const pair =
      width === "half" &&
      next &&
      nextWidth === "half" &&
      next.variant !== "banner";

    if (pair) {
      const h =
        cur.variant === "learning" || next?.variant === "learning" ? 22 : 18;
      frames[i] = { x: 6.5, y, boxW: 42, boxH: h, zIndex: z++ };
      frames[i + 1] = { x: 51.5, y, boxW: 42, boxH: h, zIndex: z++ };
      y += h + 2.5;
      i += 2;
    } else {
      const banner = cur.variant === "banner" || width === "full";
      const h = banner ? (cur.variant === "banner" ? 16 : 14) : 16;
      frames[i] = {
        x: 6.5,
        y,
        boxW: 87,
        boxH: h,
        zIndex: z++,
      };
      y += h + 2.5;
      i += 1;
    }
    if (y > 78) y = 24;
  }
  return frames;
}

export function withDefaultFrame(
  section: NewsletterSection,
  index: number,
  all: NewsletterSection[],
): NewsletterSection {
  if (hasFrame(section)) {
    return {
      ...section,
      x: clampNum(section.x, 6.5, 0, 92),
      y: clampNum(section.y, 22, 0, 92),
      boxW: clampNum(section.boxW, section.width === "full" ? 87 : 42, 12, 100),
      boxH: clampNum(section.boxH, 16, 8, 90),
      zIndex: Number.isFinite(Number(section.zIndex))
        ? Number(section.zIndex)
        : index + 1,
    };
  }
  const frames = defaultFramesForSections(all);
  const frame = frames[index] || {
    x: 6.5,
    y: 22 + index * 18,
    boxW: 87,
    boxH: 16,
    zIndex: index + 1,
  };
  return { ...section, ...frame };
}

export function ensureSectionFrames(
  sections: NewsletterSection[],
): NewsletterSection[] {
  const needDefaults = sections.some((s) => !hasFrame(s));
  if (!needDefaults) {
    return sections.map((s, i) => withDefaultFrame(s, i, sections));
  }
  const frames = defaultFramesForSections(sections);
  return sections.map((s, i) => ({
    ...s,
    x: clampNum(s.x, frames[i].x, 0, 92),
    y: clampNum(s.y, frames[i].y, 0, 92),
    boxW: clampNum(s.boxW, frames[i].boxW, 12, 100),
    boxH: clampNum(s.boxH, frames[i].boxH, 8, 90),
    zIndex: Number.isFinite(Number(s.zIndex))
      ? Number(s.zIndex)
      : frames[i].zIndex,
  }));
}

export function normalizeSections(raw: unknown): NewsletterSection[] {
  if (!Array.isArray(raw)) return [];
  const mapped = raw.map((item, index) => {
    const s = (item || {}) as Partial<NewsletterSection>;
    const fallbackTone = (
      ["green", "blue", "orange", "pink"] as SectionTone[]
    )[index % 4];
    const variant = asVariant(
      s.variant,
      index === 0 ? "banner" : "card",
    );
    const imageSrc = String(s.imageSrc || "").trim();
    const base: NewsletterSection = {
      id: s.id || newId(),
      heading: String(s.heading || "").trim(),
      body: String(s.body || "").trim(),
      variant,
      tone: asTone(s.tone, fallbackTone),
      width: asWidth(
        s.width,
        variant === "banner" || index === 0 || index === 3 ? "full" : "half",
      ),
      ...(imageSrc ? { imageSrc } : {}),
    };
    if (hasFrame(s)) {
      return {
        ...base,
        x: clampNum(s.x, 6.5, 0, 92),
        y: clampNum(s.y, 22, 0, 92),
        boxW: clampNum(s.boxW, base.width === "full" ? 87 : 42, 12, 100),
        boxH: clampNum(s.boxH, 16, 8, 90),
        zIndex: Number.isFinite(Number(s.zIndex))
          ? Number(s.zIndex)
          : index + 1,
      };
    }
    return base;
  });
  return ensureSectionFrames(mapped);
}

export function nextSectionZIndex(
  sections: NewsletterSection[],
  layers: Array<{ zIndex: number }> = [],
) {
  const zs = [
    ...sections.map((s) => Number(s.zIndex) || 0),
    ...layers.map((l) => Number(l.zIndex) || 0),
  ];
  if (!zs.length) return 1;
  return Math.max(...zs) + 1;
}
