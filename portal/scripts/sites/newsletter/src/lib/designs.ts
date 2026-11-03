import type {
  NewsletterSection,
  SectionTone,
  SectionVariant,
  SectionWidth,
} from "./types";

export type Decorations =
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

const DEFAULT_STARTERS = [
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

function brightTones(): Record<SectionTone, TonePalette> {
  return {
    green: tone([182, 245, 130], [30, 110, 40], [40, 55, 40], [90, 190, 70], [40, 120, 50]),
    blue: tone([160, 220, 255], [20, 90, 170], [35, 55, 80], [70, 160, 230], [30, 110, 190]),
    pink: tone([255, 170, 210], [180, 40, 110], [70, 40, 60], [240, 110, 170], [200, 50, 120]),
    orange: tone([255, 200, 120], [190, 90, 20], [70, 45, 25], [255, 150, 60], [210, 100, 30]),
    yellow: tone([255, 240, 110], [170, 120, 10], [70, 60, 25], [250, 210, 40], [200, 160, 20]),
    lavender: tone([210, 180, 255], [110, 60, 180], [55, 40, 80], [160, 120, 230], [120, 70, 190]),
    coral: tone([255, 170, 150], [190, 55, 55], [70, 40, 40], [250, 110, 100], [210, 60, 60]),
    mint: tone([170, 245, 220], [15, 120, 110], [35, 65, 60], [70, 200, 175], [20, 140, 130]),
  };
}

function pastelTones(): Record<SectionTone, TonePalette> {
  return {
    green: tone([220, 242, 214], [70, 130, 80], [55, 70, 55], [140, 190, 140], [120, 170, 120]),
    blue: tone([214, 234, 248], [70, 120, 170], [50, 65, 80], [140, 180, 210], [110, 155, 190]),
    pink: tone([250, 224, 232], [170, 90, 130], [70, 55, 65], [230, 160, 185], [210, 130, 160]),
    orange: tone([255, 232, 210], [180, 110, 60], [70, 55, 40], [240, 180, 120], [220, 150, 90]),
    yellow: tone([255, 246, 210], [170, 140, 50], [70, 65, 40], [240, 210, 110], [210, 180, 80]),
    lavender: tone([235, 228, 250], [120, 95, 170], [60, 50, 80], [185, 165, 220], [150, 125, 195]),
    coral: tone([255, 226, 220], [180, 90, 90], [70, 50, 50], [235, 150, 140], [210, 120, 110]),
    mint: tone([220, 245, 238], [50, 130, 120], [45, 70, 65], [140, 200, 185], [100, 170, 155]),
  };
}

function bohoTones(): Record<SectionTone, TonePalette> {
  return {
    green: tone([214, 226, 200], [90, 120, 80], [60, 70, 55], [150, 170, 120], [120, 140, 95]),
    blue: tone([214, 226, 230], [90, 120, 140], [55, 65, 75], [140, 165, 180], [110, 135, 150]),
    pink: tone([240, 214, 210], [160, 100, 95], [70, 55, 55], [210, 150, 145], [180, 120, 115]),
    orange: tone([242, 214, 180], [170, 110, 60], [75, 55, 40], [220, 160, 100], [190, 130, 70]),
    yellow: tone([245, 230, 180], [160, 130, 50], [70, 60, 40], [220, 190, 110], [190, 160, 80]),
    lavender: tone([230, 214, 220], [140, 100, 130], [65, 50, 65], [190, 150, 175], [160, 120, 145]),
    coral: tone([236, 190, 170], [170, 90, 70], [75, 50, 45], [210, 130, 110], [180, 100, 80]),
    mint: tone([210, 230, 215], [70, 120, 100], [50, 70, 60], [130, 175, 150], [100, 145, 120]),
  };
}

function inkTones(): Record<SectionTone, TonePalette> {
  const ink: RGB = [30, 30, 30];
  const soft: RGB = [248, 248, 248];
  return {
    green: tone(soft, ink, [50, 50, 50], [40, 40, 40], ink),
    blue: tone([255, 255, 255], ink, [50, 50, 50], [60, 60, 60], ink),
    pink: tone(soft, ink, [50, 50, 50], [40, 40, 40], ink),
    orange: tone([255, 255, 255], ink, [50, 50, 50], [60, 60, 60], ink),
    yellow: tone(soft, ink, [50, 50, 50], [40, 40, 40], ink),
    lavender: tone([255, 255, 255], ink, [50, 50, 50], [60, 60, 60], ink),
    coral: tone(soft, ink, [50, 50, 50], [40, 40, 40], ink),
    mint: tone([255, 255, 255], ink, [50, 50, 50], [60, 60, 60], ink),
  };
}

export const NEWSLETTER_DESIGNS: NewsletterDesign[] = [
  {
    id: "simple-brights",
    name: "Simple Brights",
    tagline: "Hot pink, lime, cyan blocks — bold & playful",
    decorations: "rainbow",
    headerStyle: "chunky-bar",
    cardStyle: "top-strip",
    pagePattern: "none",
    swatches: ["#FF2E8B", "#7CFF4E", "#2EC4FF", "#FFD600"],
    letterColors: [
      [255, 46, 139],
      [124, 255, 78],
      [46, 196, 255],
      [255, 214, 0],
      [170, 80, 255],
      [255, 110, 50],
      [255, 46, 139],
      [46, 196, 255],
      [124, 255, 78],
      [255, 214, 0],
    ],
    pageBg: [255, 255, 255],
    scriptColor: [20, 20, 20],
    bannerBar: [255, 46, 139],
    bannerText: [255, 255, 255],
    footerBar: [46, 196, 255],
    footerText: [10, 40, 70],
    ink: [20, 20, 20],
    muted: [80, 80, 80],
    tones: brightTones(),
    qrDark: "#111111",
    qrLight: "#FFFFFF",
    starterSections: DEFAULT_STARTERS,
  },
  {
    id: "modern-boho",
    name: "Modern Boho",
    tagline: "Terracotta, sage & mustard with soft rainbows",
    decorations: "boho-rainbow",
    headerStyle: "boho",
    cardStyle: "outlined",
    pagePattern: "none",
    swatches: ["#C97B63", "#D4A373", "#A3B18A", "#E9C46A"],
    letterColors: [
      [201, 123, 99],
      [212, 163, 115],
      [163, 177, 138],
      [233, 196, 106],
      [188, 143, 143],
      [201, 123, 99],
      [163, 177, 138],
      [212, 163, 115],
      [233, 196, 106],
      [188, 143, 143],
    ],
    pageBg: [253, 248, 240],
    scriptColor: [90, 60, 45],
    bannerBar: [201, 123, 99],
    bannerText: [255, 248, 240],
    footerBar: [232, 216, 190],
    footerText: [90, 60, 45],
    ink: [70, 50, 40],
    muted: [120, 100, 85],
    tones: bohoTones(),
    qrDark: "#6B4226",
    qrLight: "#FDF8F0",
    starterSections: [
      starter("Our Class News", "A calm week of reading nooks, nature walks, and gratitude journals.", "banner", "coral", "full"),
      starter("Important Dates", "Tue – Art gallery walk\nThu – Family picnic RSVP due\nFri – Early release 1:00", "list", "orange", "half"),
      starter("Learning Focus", "LITERACY: Opinion writing\nMATH: Measurement\nSCIENCE: Soil & seeds\nSEL: Calm-down tools", "learning", "green", "half"),
      starter("At Home", "Ask your child to share one kind thing they noticed today. Keep reading logs in the Tuesday folder.", "card", "yellow", "full"),
    ],
  },
  {
    id: "daisy-gingham",
    name: "Daisy Gingham",
    tagline: "Pastel checks, daisies, and soft mint cards",
    decorations: "daisy",
    headerStyle: "soft-pill",
    cardStyle: "soft",
    pagePattern: "gingham",
    swatches: ["#F7A8C6", "#B8E0D2", "#D6C6E8", "#FFE5A0"],
    letterColors: [
      [247, 168, 198],
      [184, 224, 210],
      [214, 198, 232],
      [255, 229, 160],
      [170, 210, 230],
      [247, 168, 198],
      [184, 224, 210],
      [214, 198, 232],
      [255, 229, 160],
      [170, 210, 230],
    ],
    pageBg: [255, 252, 255],
    scriptColor: [120, 80, 110],
    bannerBar: [247, 168, 198],
    bannerText: [80, 40, 70],
    footerBar: [220, 245, 235],
    footerText: [60, 100, 90],
    ink: [70, 55, 70],
    muted: [120, 100, 120],
    tones: pastelTones(),
    qrDark: "#8B5A7A",
    qrLight: "#FFFCFF",
    starterSections: DEFAULT_STARTERS,
  },
  {
    id: "spotty-brights",
    name: "Spotty Brights",
    tagline: "Dalmatian dots + neon classroom blocks",
    decorations: "spots",
    headerStyle: "spots-band",
    cardStyle: "outlined",
    pagePattern: "spots",
    swatches: ["#111111", "#FF4D6D", "#4CC9F0", "#FFD166"],
    letterColors: [
      [255, 77, 109],
      [76, 201, 240],
      [255, 209, 102],
      [6, 214, 160],
      [131, 56, 236],
      [255, 77, 109],
      [76, 201, 240],
      [255, 209, 102],
      [6, 214, 160],
      [131, 56, 236],
    ],
    pageBg: [255, 255, 255],
    scriptColor: [15, 15, 15],
    bannerBar: [17, 17, 17],
    bannerText: [255, 255, 255],
    footerBar: [255, 209, 102],
    footerText: [40, 30, 10],
    ink: [20, 20, 20],
    muted: [90, 90, 90],
    tones: brightTones(),
    qrDark: "#111111",
    qrLight: "#FFFFFF",
    starterSections: DEFAULT_STARTERS,
  },
  {
    id: "low-ink",
    name: "Low Ink Classic",
    tagline: "Black & white patterns — printer friendly",
    decorations: "ink",
    headerStyle: "ink-banner",
    cardStyle: "ink",
    pagePattern: "dots",
    swatches: ["#111111", "#FFFFFF", "#777777", "#DDDDDD"],
    letterColors: [
      [30, 30, 30],
      [60, 60, 60],
      [30, 30, 30],
      [90, 90, 90],
      [30, 30, 30],
      [60, 60, 60],
      [30, 30, 30],
      [90, 90, 90],
      [30, 30, 30],
      [60, 60, 60],
    ],
    pageBg: [255, 255, 255],
    scriptColor: [20, 20, 20],
    bannerBar: [20, 20, 20],
    bannerText: [255, 255, 255],
    footerBar: [240, 240, 240],
    footerText: [30, 30, 30],
    ink: [20, 20, 20],
    muted: [100, 100, 100],
    tones: inkTones(),
    qrDark: "#111111",
    qrLight: "#FFFFFF",
    starterSections: [
      starter("Classroom Newsletter", "Just type your own updates — clean layout, easy to photocopy for every family.", "banner", "blue", "full"),
      starter("Important Dates", "Mon – Music\nWed – Library\nFri – Free choice Friday", "list", "green", "half"),
      starter("Learning Focus", "READING: Fluency partners\nMATH: Fact families\nSCIENCE: Push & pull\nWRITING: Friendly letters", "learning", "orange", "half"),
      starter("Reminders", "Label jackets and lunchboxes. Return reading logs each Friday. Thank you for your support!", "card", "pink", "full"),
    ],
  },
  {
    id: "classroom-classic",
    name: "Classroom Classic",
    tagline: "Pastel blocks, stars & bunting",
    decorations: "stars-bunting",
    headerStyle: "rainbow-letters",
    cardStyle: "soft",
    pagePattern: "none",
    swatches: ["#5CA84E", "#C9E6F5", "#FAD6E0", "#FFE0BC"],
    letterColors: [
      [230, 60, 70],
      [245, 180, 40],
      [70, 175, 90],
      [60, 140, 220],
      [245, 130, 50],
      [230, 90, 160],
      [120, 90, 200],
      [40, 170, 170],
      [230, 60, 70],
      [245, 180, 40],
    ],
    pageBg: [255, 255, 255],
    scriptColor: [30, 30, 30],
    bannerBar: [92, 168, 78],
    bannerText: [255, 255, 255],
    footerBar: [210, 239, 198],
    footerText: [40, 70, 50],
    ink: [35, 35, 40],
    muted: [80, 90, 95],
    tones: pastelTones(),
    qrDark: "#2E3A3F",
    qrLight: "#FFFFFF",
    starterSections: DEFAULT_STARTERS,
  },
  {
    id: "sunshine-days",
    name: "Sunshine Days",
    tagline: "Big sun header with warm classroom cards",
    decorations: "sun",
    headerStyle: "chunky-bar",
    cardStyle: "soft",
    pagePattern: "none",
    swatches: ["#FFB703", "#FB8500", "#8ECAE6", "#219EBC"],
    letterColors: [
      [255, 183, 3],
      [251, 133, 0],
      [142, 202, 230],
      [33, 158, 188],
      [255, 120, 80],
      [255, 183, 3],
      [251, 133, 0],
      [142, 202, 230],
      [33, 158, 188],
      [255, 120, 80],
    ],
    pageBg: [255, 252, 240],
    scriptColor: [120, 60, 10],
    bannerBar: [251, 133, 0],
    bannerText: [255, 255, 255],
    footerBar: [255, 230, 170],
    footerText: [100, 60, 20],
    ink: [60, 40, 20],
    muted: [120, 95, 60],
    tones: brightTones(),
    qrDark: "#9A3412",
    qrLight: "#FFFCF0",
    starterSections: DEFAULT_STARTERS,
  },
  {
    id: "soft-rainbow",
    name: "Soft Rainbow",
    tagline: "Pastel arcs over gentle color cards",
    decorations: "rainbow",
    headerStyle: "rainbow-letters",
    cardStyle: "outlined",
    pagePattern: "none",
    swatches: ["#FFADAD", "#FFD6A5", "#FDFFB6", "#CAFFBF"],
    letterColors: [
      [255, 130, 130],
      [255, 180, 100],
      [240, 210, 70],
      [120, 200, 130],
      [100, 180, 230],
      [170, 140, 230],
      [255, 130, 130],
      [255, 180, 100],
      [120, 200, 130],
      [100, 180, 230],
    ],
    pageBg: [255, 255, 255],
    scriptColor: [60, 50, 80],
    bannerBar: [170, 140, 230],
    bannerText: [255, 255, 255],
    footerBar: [255, 220, 230],
    footerText: [90, 50, 80],
    ink: [50, 45, 60],
    muted: [110, 100, 120],
    tones: pastelTones(),
    qrDark: "#5B4B8A",
    qrLight: "#FFFFFF",
    starterSections: DEFAULT_STARTERS,
  },
  {
    id: "crayon-pop",
    name: "Crayon Pop",
    tagline: "Primary crayons and scrapbook-style cards",
    decorations: "crayons",
    headerStyle: "rainbow-letters",
    cardStyle: "top-strip",
    pagePattern: "confetti",
    swatches: ["#E63946", "#F4A261", "#2A9D8F", "#457B9D"],
    letterColors: [
      [230, 57, 70],
      [244, 162, 97],
      [42, 157, 143],
      [69, 123, 157],
      [241, 196, 15],
      [155, 89, 182],
      [230, 57, 70],
      [42, 157, 143],
      [69, 123, 157],
      [244, 162, 97],
    ],
    pageBg: [255, 252, 245],
    scriptColor: [40, 40, 40],
    bannerBar: [230, 57, 70],
    bannerText: [255, 255, 255],
    footerBar: [255, 230, 200],
    footerText: [80, 50, 30],
    ink: [40, 40, 40],
    muted: [90, 90, 90],
    tones: brightTones(),
    qrDark: "#1D3557",
    qrLight: "#FFFCF5",
    starterSections: DEFAULT_STARTERS,
  },
  {
    id: "paperclip-desk",
    name: "Paperclip Desk",
    tagline: "Teacher-desk neutrals with paperclip accents",
    decorations: "paperclip",
    headerStyle: "soft-pill",
    cardStyle: "dashed",
    pagePattern: "dots",
    swatches: ["#ADB5BD", "#FFD6A5", "#A0C4FF", "#BDB2FF"],
    letterColors: [
      [100, 110, 125],
      [255, 180, 120],
      [120, 160, 230],
      [160, 140, 230],
      [120, 190, 160],
      [100, 110, 125],
      [255, 180, 120],
      [120, 160, 230],
      [160, 140, 230],
      [120, 190, 160],
    ],
    pageBg: [250, 250, 252],
    scriptColor: [50, 55, 65],
    bannerBar: [100, 110, 125],
    bannerText: [255, 255, 255],
    footerBar: [230, 232, 238],
    footerText: [50, 55, 65],
    ink: [45, 50, 60],
    muted: [110, 115, 125],
    tones: pastelTones(),
    qrDark: "#343A40",
    qrLight: "#FAFAFC",
    starterSections: DEFAULT_STARTERS,
  },
  {
    id: "confetti-grid",
    name: "Confetti Grid",
    tagline: "Party dots and tidy three-tone cards",
    decorations: "confetti",
    headerStyle: "chunky-bar",
    cardStyle: "soft",
    pagePattern: "confetti",
    swatches: ["#FF006E", "#8338EC", "#3A86FF", "#FFBE0B"],
    letterColors: [
      [255, 0, 110],
      [131, 56, 236],
      [58, 134, 255],
      [255, 190, 11],
      [6, 214, 160],
      [255, 0, 110],
      [131, 56, 236],
      [58, 134, 255],
      [255, 190, 11],
      [6, 214, 160],
    ],
    pageBg: [255, 255, 255],
    scriptColor: [25, 25, 40],
    bannerBar: [131, 56, 236],
    bannerText: [255, 255, 255],
    footerBar: [255, 230, 245],
    footerText: [90, 30, 80],
    ink: [30, 25, 45],
    muted: [100, 95, 120],
    tones: brightTones(),
    qrDark: "#3A0CA3",
    qrLight: "#FFFFFF",
    starterSections: DEFAULT_STARTERS,
  },
  {
    id: "mint-hearts",
    name: "Mint Hearts",
    tagline: "Fresh mint & coral hearts for kindness weeks",
    decorations: "hearts",
    headerStyle: "soft-pill",
    cardStyle: "outlined",
    pagePattern: "none",
    swatches: ["#80ED99", "#57CC99", "#FF8FAB", "#FFC2D1"],
    letterColors: [
      [87, 204, 153],
      [255, 143, 171],
      [128, 237, 153],
      [255, 194, 209],
      [70, 170, 200],
      [87, 204, 153],
      [255, 143, 171],
      [128, 237, 153],
      [255, 194, 209],
      [70, 170, 200],
    ],
    pageBg: [245, 255, 250],
    scriptColor: [30, 90, 70],
    bannerBar: [87, 204, 153],
    bannerText: [20, 60, 50],
    footerBar: [255, 220, 230],
    footerText: [120, 50, 70],
    ink: [30, 70, 55],
    muted: [80, 110, 100],
    tones: pastelTones(),
    qrDark: "#1B4332",
    qrLight: "#F5FFFA",
    starterSections: [
      starter("Kindness Corner", "We celebrated helpers, wrote thank-you notes, and practiced calm greeting routines.", "banner", "mint", "full"),
      starter("Important Dates", "Wed – Buddy reading\nFri – Kindness parade\nMon – New reading groups", "list", "pink", "half"),
      starter("Learning Focus", "SEL: Empathy stories\nREADING: Character feelings\nMATH: Sharing equally\nART: Heart collages", "learning", "coral", "half"),
      starter("At Home", "Ask: Who did you help today? Keep a family kindness jar and celebrate one act each evening.", "card", "green", "full"),
    ],
  },
];

export const DEFAULT_DESIGN_ID = "simple-brights";

export function getDesign(id?: string | null): NewsletterDesign {
  return NEWSLETTER_DESIGNS.find((d) => d.id === id) || NEWSLETTER_DESIGNS[0];
}

export function isDesignId(id: string): boolean {
  return NEWSLETTER_DESIGNS.some((d) => d.id === id);
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
  // ensureSectionFrames lives in sections.ts — inline defaults to avoid cycle
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
