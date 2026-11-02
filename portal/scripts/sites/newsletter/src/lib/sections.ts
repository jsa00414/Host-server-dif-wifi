import { randomUUID } from "crypto";
import type {
  NewsletterSection,
  SectionTone,
  SectionVariant,
  SectionWidth,
} from "./types";

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

export function normalizeSections(raw: unknown): NewsletterSection[] {
  if (!Array.isArray(raw)) return [];
  return raw.map((item, index) => {
    const s = (item || {}) as Partial<NewsletterSection>;
    const fallbackTone = (
      ["green", "blue", "orange", "pink"] as SectionTone[]
    )[index % 4];
    const variant = asVariant(
      s.variant,
      index === 0 ? "banner" : "card",
    );
    const imageSrc = String(s.imageSrc || "").trim();
    return {
      id: s.id || randomUUID(),
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
  });
}
