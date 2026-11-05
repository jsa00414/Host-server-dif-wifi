import type {
  NewsletterSection,
  SectionTone,
  SectionVariant,
  SectionWidth,
} from "./types";

export type Decorations =
  | "none"
  | "stars-bunting"
  | "rainbow"
  | "daisy"
  | "spots"
  | "sun"
  | "paperclip"
  | "crayons"
  | "boho-rainbow"
  | "gingham"
  | "confetti"
  | "ink"
  | "hearts";

export type HeaderStyle =
  | "rainbow-letters"
  | "chunky-bar"
  | "boho"
  | "spots-band"
  | "ink-banner"
  | "soft-pill";

export type CardStyle =
  | "soft"
  | "outlined"
  | "top-strip"
  | "dashed"
  | "ink";

export type PagePattern = "none" | "dots" | "spots" | "gingham" | "confetti";

export type TonePalette = {
  fill: [number, number, number];
  heading: [number, number, number];
  body: [number, number, number];
  bar: [number, number, number];
  border?: [number, number, number];
};

export type NewsletterDesign = {
  id: string;
  name: string;
  tagline: string;
  decorations: Decorations;
  headerStyle: HeaderStyle;
  cardStyle: CardStyle;
  pagePattern: PagePattern;
  swatches: [string, string, string, string];
  letterColors: Array<[number, number, number]>;
  pageBg: [number, number, number];
  scriptColor: [number, number, number];
  bannerBar: [number, number, number];
  bannerText: [number, number, number];
  footerBar: [number, number, number];
  footerText: [number, number, number];
  ink: [number, number, number];
  muted: [number, number, number];
  tones: Record<SectionTone, TonePalette>;
  qrDark: string;
  qrLight: string;
  starterSections: Array<{
    heading: string;
    body: string;
    variant: SectionVariant;
    tone: SectionTone;
    width: SectionWidth;
  }>;
};

type RGB = [number, number, number];

function tone(
  fill: RGB,
  heading: RGB,
  body: RGB,
  bar: RGB,
  border?: RGB,
): TonePalette {
  return { fill, heading, body, bar, ...(border ? { border } : {}) };
}

function starter(
  heading: string,
  body: string,
  variant: SectionVariant,
  toneId: SectionTone,
  width: SectionWidth,
) {
  return { heading, body, variant, tone: toneId, width };
}

const CLASSROOM_STARTERS = [
  starter(
    "This Week in Class",
    "Welcome, families! Here is a peek at our learning, celebrations, and reminders for the week ahead.",
    "banner",
    "green",
    "full",
  ),
  starter(
    "Important Dates",
    "Mon – Library day\nWed – Picture retakes\nFri – Spirit day (wear class colors)",
    "list",
    "blue",
    "half",
  ),
  starter(
    "Learning Focus",
    "READING: Story elements\nMATH: Place value games\nSCIENCE: Weather watchers\nSEL: Kind words & friendship",
    "learning",
    "orange",
    "half",
  ),
  starter(
    "Reminders & At Home",
    "Please check Tuesday folders each Wednesday. Practice sight words for 10 minutes and return permission slips by Friday.",
    "card",
    "pink",
    "full",
  ),
];

function classroomTones(): Record<SectionTone, TonePalette> {
  return {
    green: tone(
      [220, 242, 214],
      [46, 125, 50],
      [55, 70, 55],
      [92, 168, 78],
      [120, 170, 120],
    ),
    blue: tone(
      [201, 230, 245],
      [30, 100, 160],
      [45, 62, 80],
      [90, 170, 210],
      [110, 155, 190],
    ),
    pink: tone(
      [250, 214, 224],
      [170, 70, 120],
      [70, 55, 70],
      [232, 140, 170],
      [210, 130, 160],
    ),
    orange: tone(
      [255, 224, 188],
      [180, 100, 40],
      [70, 55, 40],
      [245, 160, 80],
      [220, 150, 90],
    ),
    yellow: tone(
      [255, 244, 180],
      [160, 120, 20],
      [70, 60, 30],
      [245, 200, 60],
      [210, 180, 80],
    ),
    lavender: tone(
      [230, 220, 245],
      [100, 70, 160],
      [55, 50, 75],
      [170, 140, 210],
      [140, 110, 185],
    ),
    coral: tone(
      [255, 220, 210],
      [180, 70, 60],
      [70, 50, 45],
      [240, 130, 110],
      [210, 100, 90],
    ),
    mint: tone(
      [210, 240, 230],
      [20, 120, 110],
      [40, 70, 65],
      [90, 190, 170],
      [70, 160, 145],
    ),
  };
}

/** Single clean classroom look — no AI template pack. */
export const NEWSLETTER_DESIGNS: NewsletterDesign[] = [
  {
    id: "classroom",
    name: "Classroom",
    tagline: "Clean pastel blocks for family newsletters",
    decorations: "none",
    headerStyle: "soft-pill",
    cardStyle: "soft",
    pagePattern: "none",
    swatches: ["#5CA84E", "#5AAAD2", "#E88CB0", "#F5A050"],
    letterColors: [
      [92, 168, 78],
      [90, 170, 210],
      [232, 140, 170],
      [245, 160, 80],
      [92, 168, 78],
      [90, 170, 210],
      [232, 140, 170],
      [245, 160, 80],
      [92, 168, 78],
      [90, 170, 210],
    ],
    pageBg: [255, 255, 255],
    scriptColor: [35, 45, 55],
    bannerBar: [92, 168, 78],
    bannerText: [255, 255, 255],
    footerBar: [201, 230, 245],
    footerText: [35, 55, 75],
    ink: [35, 45, 55],
    muted: [100, 110, 120],
    tones: classroomTones(),
    qrDark: "#243040",
    qrLight: "#FFFFFF",
    starterSections: CLASSROOM_STARTERS,
  },
];

export const DEFAULT_DESIGN_ID = "classroom";

/** Older AI/Canva pack ids map onto the clean classroom design. */
const LEGACY_DESIGN_IDS = new Set([
  "simple-brights",
  "modern-boho",
  "daisy-gingham",
  "spotty-brights",
  "low-ink",
  "classroom-classic",
  "sunshine-days",
  "soft-rainbow",
  "crayon-pop",
  "paperclip-desk",
  "confetti-grid",
  "mint-hearts",
]);

export function getDesign(id?: string | null): NewsletterDesign {
  if (id && !LEGACY_DESIGN_IDS.has(id)) {
    const found = NEWSLETTER_DESIGNS.find((d) => d.id === id);
    if (found) return found;
  }
  return NEWSLETTER_DESIGNS[0];
}

export function isDesignId(id: string): boolean {
  return NEWSLETTER_DESIGNS.some((d) => d.id === id) || LEGACY_DESIGN_IDS.has(id);
}

export function sectionsFromStarter(
  designId?: string | null,
): NewsletterSection[] {
  const design = getDesign(designId);
  const base = design.starterSections.map((s) => ({
    id: crypto.randomUUID(),
    heading: s.heading,
    body: s.body,
    variant: s.variant,
    tone: s.tone,
    width: s.width,
  }));
  let y = 22;
  let z = 1;
  const out: NewsletterSection[] = [];
  let i = 0;
  while (i < base.length) {
    const cur = base[i];
    const next = base[i + 1];
    const pair =
      cur.width === "half" &&
      next &&
      next.width === "half" &&
      next.variant !== "banner";
    if (pair) {
      const h =
        cur.variant === "learning" || next.variant === "learning" ? 22 : 18;
      out.push({ ...cur, x: 6.5, y, boxW: 42, boxH: h, zIndex: z++ });
      out.push({ ...next, x: 51.5, y, boxW: 42, boxH: h, zIndex: z++ });
      y += h + 2.5;
      i += 2;
    } else {
      const h = cur.variant === "banner" ? 16 : 14;
      out.push({ ...cur, x: 6.5, y, boxW: 87, boxH: h, zIndex: z++ });
      y += h + 2.5;
      i += 1;
    }
  }
  return out;
}

export const SECTION_TONES: SectionTone[] = [
  "green",
  "blue",
  "pink",
  "orange",
  "yellow",
  "lavender",
  "coral",
  "mint",
];

export const SECTION_VARIANTS: Array<{
  id: SectionVariant;
  label: string;
}> = [
  { id: "banner", label: "Banner" },
  { id: "card", label: "Card" },
  { id: "list", label: "Events list" },
  { id: "learning", label: "Learning" },
];
