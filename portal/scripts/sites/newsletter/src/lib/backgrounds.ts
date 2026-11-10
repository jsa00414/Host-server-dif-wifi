import type { CSSProperties } from "react";
import type { NewsletterDesign, PagePattern } from "./designs";
import type { PageBackground } from "./types";
import { rgbCss } from "./editorTheme";

export type BackgroundOption = {
  id: string;
  name: string;
  /** Preview swatch */
  swatch: string;
  /** Default solid color when picking this pattern */
  color: string;
  pattern: PagePattern | ExtendedPattern;
};

export type ExtendedPattern =
  | PagePattern
  | "stripes"
  | "grid"
  | "stars"
  | "hearts"
  | "clouds"
  | "waves"
  | "diagonal"
  | "solid";

export const PAGE_BACKGROUNDS: BackgroundOption[] = [
  { id: "solid-white", name: "White", swatch: "#FFFFFF", color: "#FFFFFF", pattern: "solid" },
  { id: "solid-cream", name: "Cream", swatch: "#FFF8F0", color: "#FFF8F0", pattern: "solid" },
  { id: "solid-sky", name: "Sky", swatch: "#E8F4FF", color: "#E8F4FF", pattern: "solid" },
  { id: "solid-mint", name: "Mint", swatch: "#E8FFF6", color: "#E8FFF6", pattern: "solid" },
  { id: "solid-blush", name: "Blush", swatch: "#FFEAF2", color: "#FFEAF2", pattern: "solid" },
  { id: "solid-lavender", name: "Lavender", swatch: "#F3EEFF", color: "#F3EEFF", pattern: "solid" },
  { id: "solid-lemon", name: "Lemon", swatch: "#FFF9DB", color: "#FFF9DB", pattern: "solid" },
  { id: "solid-peach", name: "Peach", swatch: "#FFE8D6", color: "#FFE8D6", pattern: "solid" },
  { id: "dots", name: "Soft Dots", swatch: "#F5F5F7", color: "#FFFFFF", pattern: "dots" },
  { id: "spots", name: "Dalmatian", swatch: "#111111", color: "#FFFFFF", pattern: "spots" },
  { id: "gingham", name: "Gingham", swatch: "#F7A8C6", color: "#FFFCFF", pattern: "gingham" },
  { id: "confetti", name: "Confetti", swatch: "#FF006E", color: "#FFFFFF", pattern: "confetti" },
  { id: "stripes", name: "Stripes", swatch: "#A0C4FF", color: "#F7FBFF", pattern: "stripes" },
  { id: "grid", name: "Notebook Grid", swatch: "#CDE7FF", color: "#FFFFFF", pattern: "grid" },
  { id: "stars", name: "Starfield", swatch: "#FFE066", color: "#FFFCF5", pattern: "stars" },
  { id: "hearts", name: "Tiny Hearts", swatch: "#FF8FAB", color: "#FFF5F8", pattern: "hearts" },
  { id: "clouds", name: "Cloud Soft", swatch: "#BDE0FE", color: "#F0F7FF", pattern: "clouds" },
  { id: "waves", name: "Waves", swatch: "#90E0EF", color: "#F0FBFF", pattern: "waves" },
  { id: "diagonal", name: "Diagonal", swatch: "#FFD6A5", color: "#FFF9F0", pattern: "diagonal" },
];

export const SHAPE_PALETTE = [
  "#FF6B6B",
  "#FF922B",
  "#FFD43B",
  "#69DB7C",
  "#38D9A9",
  "#4DABF7",
  "#748FFC",
  "#DA77F2",
  "#F783AC",
  "#212529",
  "#FFFFFF",
  "#ADB5BD",
];

export function normalizePageBackground(raw: unknown): PageBackground | undefined {
  if (!raw || typeof raw !== "object") return undefined;
  const b = raw as Partial<PageBackground>;
  const color =
    typeof b.color === "string" && /^#([0-9a-f]{3}|[0-9a-f]{6})$/i.test(b.color.trim())
      ? b.color.trim()
      : undefined;
  const pattern =
    typeof b.pattern === "string" && b.pattern.trim()
      ? b.pattern.trim()
      : undefined;
  if (!color && !pattern) return undefined;
  return { ...(color ? { color } : {}), ...(pattern ? { pattern } : {}) };
}

export function resolveBackground(
  design: NewsletterDesign,
  override?: PageBackground | null,
): { color: string; pattern: ExtendedPattern } {
  const designColor = rgbCss(design.pageBg);
  const color = override?.color || designColor;
  const pattern = (override?.pattern ||
    design.pagePattern ||
    "none") as ExtendedPattern;
  return { color, pattern };
}

export function backgroundCss(
  design: NewsletterDesign,
  override?: PageBackground | null,
): CSSProperties {
  const { color, pattern } = resolveBackground(design, override);
  if (pattern === "none" || pattern === "solid") {
    return { backgroundColor: color };
  }
  if (pattern === "dots") {
    return {
      backgroundColor: color,
      backgroundImage: "radial-gradient(#d2d2d8 1.2px, transparent 1.2px)",
      backgroundSize: "18px 18px",
    };
  }
  if (pattern === "spots") {
    return {
      backgroundColor: color,
      backgroundImage: "radial-gradient(#111 2px, transparent 2px)",
      backgroundSize: "26px 26px",
    };
  }
  if (pattern === "gingham") {
    return {
      backgroundColor: color,
      backgroundImage:
        "linear-gradient(90deg, rgba(247,168,198,0.22) 50%, transparent 50%), linear-gradient(rgba(184,224,210,0.22) 50%, transparent 50%)",
      backgroundSize: "22px 22px",
    };
  }
  if (pattern === "confetti") {
    return {
      backgroundColor: color,
      backgroundImage:
        "radial-gradient(circle at 10% 20%, rgba(255,0,110,0.2) 0 3px, transparent 4px), radial-gradient(circle at 80% 30%, rgba(58,134,255,0.2) 0 3px, transparent 4px), radial-gradient(circle at 40% 70%, rgba(255,190,11,0.22) 0 3px, transparent 4px), radial-gradient(circle at 70% 80%, rgba(131,56,236,0.18) 0 2.5px, transparent 3.5px)",
    };
  }
  if (pattern === "stripes") {
    return {
      backgroundColor: color,
      backgroundImage:
        "repeating-linear-gradient(0deg, rgba(100,160,230,0.14) 0 10px, transparent 10px 20px)",
    };
  }
  if (pattern === "grid") {
    return {
      backgroundColor: color,
      backgroundImage:
        "linear-gradient(rgba(120,170,220,0.28) 1px, transparent 1px), linear-gradient(90deg, rgba(120,170,220,0.28) 1px, transparent 1px)",
      backgroundSize: "24px 24px",
    };
  }
  if (pattern === "stars") {
    return {
      backgroundColor: color,
      backgroundImage:
        "radial-gradient(circle at 12% 18%, #ffd43b 0 2px, transparent 2.5px), radial-gradient(circle at 78% 28%, #748ffc 0 2px, transparent 2.5px), radial-gradient(circle at 42% 62%, #ff922b 0 1.8px, transparent 2.3px), radial-gradient(circle at 88% 72%, #da77f2 0 2px, transparent 2.5px), radial-gradient(circle at 22% 80%, #69db7c 0 1.6px, transparent 2.1px)",
    };
  }
  if (pattern === "hearts") {
    return {
      backgroundColor: color,
      backgroundImage:
        "radial-gradient(circle at 15% 20%, rgba(255,143,171,0.45) 0 4px, transparent 5px), radial-gradient(circle at 70% 35%, rgba(255,143,171,0.35) 0 3px, transparent 4px), radial-gradient(circle at 40% 75%, rgba(247,168,198,0.4) 0 3.5px, transparent 4.5px)",
    };
  }
  if (pattern === "clouds") {
    return {
      backgroundColor: color,
      backgroundImage:
        "radial-gradient(ellipse at 20% 30%, rgba(255,255,255,0.9) 0 28px, transparent 30px), radial-gradient(ellipse at 28% 32%, rgba(255,255,255,0.85) 0 22px, transparent 24px), radial-gradient(ellipse at 75% 20%, rgba(255,255,255,0.8) 0 26px, transparent 28px), radial-gradient(ellipse at 82% 70%, rgba(255,255,255,0.75) 0 24px, transparent 26px)",
    };
  }
  if (pattern === "waves") {
    return {
      backgroundColor: color,
      backgroundImage:
        "repeating-radial-gradient(circle at 0 50%, transparent 0, transparent 14px, rgba(64,192,220,0.12) 14px, rgba(64,192,220,0.12) 18px)",
    };
  }
  if (pattern === "diagonal") {
    return {
      backgroundColor: color,
      backgroundImage:
        "repeating-linear-gradient(135deg, rgba(255,180,120,0.18) 0 12px, transparent 12px 24px)",
    };
  }
  return { backgroundColor: color };
}

export function hexToRgb(hex: string): [number, number, number] {
  const h = hex.replace("#", "");
  const full =
    h.length === 3
      ? h
          .split("")
          .map((c) => c + c)
          .join("")
      : h;
  const n = parseInt(full, 16);
  if (!Number.isFinite(n)) return [255, 255, 255];
  return [(n >> 16) & 255, (n >> 8) & 255, n & 255];
}
