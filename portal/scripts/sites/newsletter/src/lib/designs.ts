import type {
  NewsletterSection,
  SectionTone,
  SectionVariant,
  SectionWidth,
} from "./types";

export type Decoration =
  | "stars-bunting"
  | "crayons"
  | "sticky"
  | "storytime"
  | "playground"
  | "garden"
  | "aqua"
  | "candy"
  | "space"
  | "harvest";

export type TonePalette = {
  fill: [number, number, number];
  heading: [number, number, number];
  body: [number, number, number];
  bar: [number, number, number];
};

export type NewsletterDesign = {
  id: string;
  name: string;
  tagline: string;
  decorations: Decoration;
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
  /** Starter blocks that mirror the classroom template */
  starterSections: Array<{
    heading: string;
    body: string;
    variant: SectionVariant;
    tone: SectionTone;
    width: SectionWidth;
  }>;
};

const CLASSROOM_TONES: Record<SectionTone, TonePalette> = {
  green: {
    fill: [210, 239, 198],
    heading: [46, 125, 50],
    body: [55, 70, 55],
    bar: [92, 168, 78],
  },
  blue: {
    fill: [201, 230, 245],
    heading: [214, 90, 49],
    body: [45, 62, 80],
    bar: [90, 170, 210],
  },
  pink: {
    fill: [250, 214, 224],
    heading: [56, 120, 196],
    body: [70, 55, 70],
    bar: [232, 140, 170],
  },
  orange: {
    fill: [255, 224, 188],
    heading: [70, 170, 90],
    body: [70, 55, 40],
    bar: [245, 160, 80],
  },
  yellow: {
    fill: [255, 244, 180],
    heading: [200, 120, 30],
    body: [70, 60, 30],
    bar: [245, 200, 60],
  },
  lavender: {
    fill: [230, 220, 250],
    heading: [120, 80, 180],
    body: [60, 50, 80],
    bar: [170, 140, 220],
  },
  coral: {
    fill: [255, 214, 205],
    heading: [200, 70, 80],
    body: [70, 45, 45],
    bar: [240, 120, 110],
  },
  mint: {
    fill: [205, 242, 230],
    heading: [20, 130, 120],
    body: [40, 70, 65],
    bar: [90, 190, 170],
  },
};

function starter(
  heading: string,
  body: string,
  variant: SectionVariant,
  tone: SectionTone,
  width: SectionWidth,
) {
  return { heading, body, variant, tone, width };
}

export const NEWSLETTER_DESIGNS: NewsletterDesign[] = [
  {
    id: "classroom-classic",
    name: "Classroom Classic",
    tagline: "Like the sample — pastel blocks, stars & bunting",
    decorations: "stars-bunting",
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
    tones: CLASSROOM_TONES,
    qrDark: "#2E3A3F",
    qrLight: "#FFFFFF",
    starterSections: [
      starter(
        "August Class News",
        "Welcome back, families! We are so excited for a year of reading, discovery, and kindness. Thank you for sharing your children with us.",
        "banner",
        "green",
        "full",
      ),
      starter(
        "Upcoming Events",
        "Aug 15 – Picture Day\nAug 22 – Curriculum Night 6:00 PM\nAug 29 – No School (Teacher Workday)",
        "list",
        "blue",
        "half",
      ),
      starter(
        "What We're Learning",
        "ENGLISH: Friendship stories & sight words\nMATH: Place value & number talks\nSCIENCE: Weather watchers\nART: Color mixing & collage",
        "learning",
        "orange",
        "half",
      ),
      starter(
        "Reminders & Notes",
        "Please return Tuesday folders each Wednesday. Label water bottles and jackets. Reach out anytime — we are a team!",
        "card",
        "pink",
        "full",
      ),
    ],
  },
  {
    id: "crayon-box",
    name: "Crayon Box",
    tagline: "Bold primary blocks like a fresh crayon tin",
    decorations: "crayons",
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
    tones: {
      ...CLASSROOM_TONES,
      green: { fill: [210, 240, 230], heading: [42, 157, 143], body: [40, 60, 55], bar: [42, 157, 143] },
      blue: { fill: [210, 228, 240], heading: [69, 123, 157], body: [40, 55, 70], bar: [69, 123, 157] },
      coral: { fill: [255, 220, 214], heading: [230, 57, 70], body: [70, 40, 40], bar: [230, 57, 70] },
      orange: { fill: [255, 232, 210], heading: [220, 120, 40], body: [70, 50, 30], bar: [244, 162, 97] },
    },
    qrDark: "#1D3557",
    qrLight: "#FFFCF5",
    starterSections: [
      starter("This Week's Glow", "Our crayon crew is off to a colorful start with shared reading and math games.", "banner", "coral", "full"),
      starter("Upcoming Events", "Fri – Spirit Day (wear bright colors)\nNext Mon – Library visit", "list", "blue", "half"),
      starter("What We're Learning", "READING: Character traits\nMATH: Addition strategies\nSCIENCE: Solids & liquids\nART: Warm vs cool colors", "learning", "orange", "half"),
      starter("Reminders & Notes", "Pack an extra set of crayons for centers. Snack helper calendar is on the class portal.", "card", "green", "full"),
    ],
  },
  {
    id: "sticky-notes",
    name: "Sticky Notes",
    tagline: "Soft sticky-note cards in neat columns",
    decorations: "sticky",
    swatches: ["#FFE066", "#B2F2BB", "#A5D8FF", "#FFC9C9"],
    letterColors: [
      [250, 176, 5],
      [64, 192, 87],
      [34, 139, 230],
      [250, 82, 82],
      [121, 80, 242],
      [250, 176, 5],
      [64, 192, 87],
      [34, 139, 230],
      [250, 82, 82],
      [121, 80, 242],
    ],
    pageBg: [252, 252, 250],
    scriptColor: [50, 50, 50],
    bannerBar: [250, 176, 5],
    bannerText: [50, 40, 10],
    footerBar: [255, 240, 180],
    footerText: [70, 60, 20],
    ink: [45, 45, 45],
    muted: [100, 100, 100],
    tones: CLASSROOM_TONES,
    qrDark: "#495057",
    qrLight: "#FCFCFA",
    starterSections: [
      starter("Class Sticky Notes", "Little notes, big news — here is what stuck with us this week.", "banner", "yellow", "full"),
      starter("Upcoming Events", "Wed – Music showcase\nThu – Math night", "list", "mint", "half"),
      starter("What We're Learning", "WRITING: How-to lists\nMATH: Measuring with cubes\nSCIENCE: Plant journals\nSEL: Kind words", "learning", "lavender", "half"),
      starter("Reminders & Notes", "Check the take-home folder for permission slips. Thanks for reading with your child nightly!", "card", "pink", "full"),
    ],
  },
  {
    id: "storytime",
    name: "Storytime",
    tagline: "Lavender fairy-tale classroom pages",
    decorations: "storytime",
    swatches: ["#B197FC", "#FFA8A8", "#FFE066", "#74C0FC"],
    letterColors: [
      [177, 151, 252],
      [255, 168, 168],
      [255, 224, 102],
      [116, 192, 252],
      [145, 216, 168],
      [177, 151, 252],
      [255, 168, 168],
      [255, 224, 102],
      [116, 192, 252],
      [145, 216, 168],
    ],
    pageBg: [252, 248, 255],
    scriptColor: [70, 40, 100],
    bannerBar: [150, 120, 210],
    bannerText: [255, 255, 255],
    footerBar: [235, 225, 255],
    footerText: [70, 40, 100],
    ink: [55, 35, 75],
    muted: [100, 85, 120],
    tones: CLASSROOM_TONES,
    qrDark: "#5F3DC4",
    qrLight: "#FCF8FF",
    starterSections: [
      starter("Chapter News", "Once upon a week… our readers adventured through new chapter books and cozy corners.", "banner", "lavender", "full"),
      starter("Upcoming Events", "Book character day Friday\nFamily reading picnic next Saturday", "list", "pink", "half"),
      starter("What We're Learning", "READING: Retelling with beginning/middle/end\nMATH: Even & odd\nSCIENCE: Animal habitats\nART: Story illustrations", "learning", "blue", "half"),
      starter("Reminders & Notes", "Return library books on Thursdays. New classroom library wish list is on the portal.", "card", "yellow", "full"),
    ],
  },
  {
    id: "playground",
    name: "Playground",
    tagline: "High-energy playground brights",
    decorations: "playground",
    swatches: ["#FF6B6B", "#4D96FF", "#6BCB77", "#FFD93D"],
    letterColors: [
      [255, 107, 107],
      [77, 150, 255],
      [107, 203, 119],
      [255, 217, 61],
      [255, 140, 66],
      [162, 89, 255],
      [255, 107, 107],
      [77, 150, 255],
      [107, 203, 119],
      [255, 217, 61],
    ],
    pageBg: [255, 255, 255],
    scriptColor: [25, 25, 25],
    bannerBar: [77, 150, 255],
    bannerText: [255, 255, 255],
    footerBar: [220, 240, 255],
    footerText: [30, 60, 100],
    ink: [30, 30, 30],
    muted: [90, 90, 90],
    tones: CLASSROOM_TONES,
    qrDark: "#1B3A4B",
    qrLight: "#FFFFFF",
    starterSections: [
      starter("Recess Report", "We practiced sharing equipment, cheering teammates, and cool-downs after big games.", "banner", "blue", "full"),
      starter("Upcoming Events", "Field day practice Tue\nP.E. helper sign-ups due Fri", "list", "coral", "half"),
      starter("What We're Learning", "PE: Team relays\nMATH: Graphing favorites\nSCIENCE: Heart rates\nMUSIC: Rhythm patterns", "learning", "green", "half"),
      starter("Reminders & Notes", "Sneakers on PE days. Water bottles welcome — please label them.", "card", "yellow", "full"),
    ],
  },
  {
    id: "garden-day",
    name: "Garden Day",
    tagline: "Leafy greens and sunny flower beds",
    decorations: "garden",
    swatches: ["#8AC926", "#FFCA3A", "#1982C4", "#FF595E"],
    letterColors: [
      [138, 201, 38],
      [255, 202, 58],
      [25, 130, 196],
      [255, 89, 94],
      [106, 76, 147],
      [138, 201, 38],
      [255, 202, 58],
      [25, 130, 196],
      [255, 89, 94],
      [106, 76, 147],
    ],
    pageBg: [248, 255, 248],
    scriptColor: [35, 70, 40],
    bannerBar: [90, 170, 70],
    bannerText: [255, 255, 255],
    footerBar: [220, 245, 210],
    footerText: [40, 80, 45],
    ink: [35, 60, 40],
    muted: [80, 100, 80],
    tones: CLASSROOM_TONES,
    qrDark: "#2D6A4F",
    qrLight: "#F8FFF8",
    starterSections: [
      starter("From Our Class Garden", "Seedlings sprouted! Students measured growth and wrote garden observations.", "banner", "green", "full"),
      starter("Upcoming Events", "Garden workday Sat 9 AM\nCompost club lunch Tuesday", "list", "yellow", "half"),
      starter("What We're Learning", "SCIENCE: Plant life cycles\nMATH: Measuring centimeters\nWRITING: Nature journals\nART: Leaf rubbings", "learning", "mint", "half"),
      starter("Reminders & Notes", "Send a labeled hat for outdoor learning. Allergy notes welcomed anytime.", "card", "orange", "full"),
    ],
  },
  {
    id: "aqua-splash",
    name: "Aqua Splash",
    tagline: "Ocean blues with seafoam cards",
    decorations: "aqua",
    swatches: ["#00B4D8", "#90E0EF", "#0077B6", "#FFE66D"],
    letterColors: [
      [0, 180, 216],
      [0, 119, 182],
      [72, 202, 228],
      [255, 230, 109],
      [0, 150, 199],
      [144, 224, 239],
      [0, 180, 216],
      [0, 119, 182],
      [255, 230, 109],
      [72, 202, 228],
    ],
    pageBg: [240, 250, 255],
    scriptColor: [10, 50, 80],
    bannerBar: [0, 150, 199],
    bannerText: [255, 255, 255],
    footerBar: [200, 235, 245],
    footerText: [20, 70, 95],
    ink: [15, 50, 75],
    muted: [70, 100, 120],
    tones: CLASSROOM_TONES,
    qrDark: "#023E8A",
    qrLight: "#F0FAFF",
    starterSections: [
      starter("Splash of News", "We explored sink-or-float stations and wrote ocean poems together.", "banner", "blue", "full"),
      starter("Upcoming Events", "Aquarium virtual tour Wed\nWater day next Fri (bring towel)", "list", "mint", "half"),
      starter("What We're Learning", "SCIENCE: Properties of water\nMATH: Capacity & cups\nREADING: Nonfiction sea animals\nART: Watercolor waves", "learning", "lavender", "half"),
      starter("Reminders & Notes", "Label towels and extra clothes for water day. Sunscreen applied at home, please.", "card", "yellow", "full"),
    ],
  },
  {
    id: "candy-shop",
    name: "Candy Shop",
    tagline: "Sweet pinks, cherries, and gumdrop cards",
    decorations: "candy",
    swatches: ["#FF8FAB", "#FFB3C1", "#FFC2E2", "#C77DFF"],
    letterColors: [
      [255, 100, 150],
      [255, 150, 180],
      [200, 120, 255],
      [255, 190, 100],
      [120, 200, 220],
      [255, 100, 150],
      [200, 120, 255],
      [255, 150, 180],
      [255, 190, 100],
      [120, 200, 220],
    ],
    pageBg: [255, 247, 250],
    scriptColor: [90, 30, 60],
    bannerBar: [255, 120, 160],
    bannerText: [255, 255, 255],
    footerBar: [255, 230, 240],
    footerText: [100, 40, 70],
    ink: [70, 30, 50],
    muted: [120, 80, 100],
    tones: CLASSROOM_TONES,
    qrDark: "#9D174D",
    qrLight: "#FFF7FA",
    starterSections: [
      starter("Sweet Class Updates", "Kindness coupons and partner reading made our room feel extra sweet this week.", "banner", "pink", "full"),
      starter("Upcoming Events", "Valentine exchange (optional)\nClass celebration Friday", "list", "lavender", "half"),
      starter("What We're Learning", "MATH: Counting collections\nREADING: Opinion writing\nSCIENCE: States of matter (melting)\nART: Patterned paper crafts", "learning", "coral", "half"),
      starter("Reminders & Notes", "Allergy-friendly treats only, please. Check the class list before sending snacks.", "card", "yellow", "full"),
    ],
  },
  {
    id: "space-explorers",
    name: "Space Explorers",
    tagline: "Night-sky navy with comet accents",
    decorations: "space",
    swatches: ["#3A0CA3", "#4361EE", "#4CC9F0", "#F72585"],
    letterColors: [
      [67, 97, 238],
      [76, 201, 240],
      [247, 37, 133],
      [255, 214, 10],
      [114, 9, 183],
      [67, 97, 238],
      [76, 201, 240],
      [247, 37, 133],
      [255, 214, 10],
      [114, 9, 183],
    ],
    pageBg: [245, 247, 255],
    scriptColor: [30, 20, 70],
    bannerBar: [58, 12, 163],
    bannerText: [255, 255, 255],
    footerBar: [220, 225, 255],
    footerText: [40, 30, 90],
    ink: [30, 25, 70],
    muted: [90, 90, 130],
    tones: CLASSROOM_TONES,
    qrDark: "#240046",
    qrLight: "#F5F7FF",
    starterSections: [
      starter("Mission Log", "Cadets tracked moon phases and built constellation stories on black paper.", "banner", "lavender", "full"),
      starter("Upcoming Events", "Planetarium trip permission due Mon\nSTEM night Thursday", "list", "blue", "half"),
      starter("What We're Learning", "SCIENCE: Solar system\nMATH: Ordinal numbers\nREADING: Space nonfiction\nART: Galaxy pastels", "learning", "mint", "half"),
      starter("Reminders & Notes", "Permission slips need a signature and emergency contact. Pack a light jacket for the trip.", "card", "pink", "full"),
    ],
  },
  {
    id: "harvest-fair",
    name: "Harvest Fair",
    tagline: "Autumn classroom fair — rust, gold, squash",
    decorations: "harvest",
    swatches: ["#D8572A", "#F4A261", "#E9C46A", "#2A9D8F"],
    letterColors: [
      [216, 87, 42],
      [244, 162, 97],
      [233, 196, 106],
      [42, 157, 143],
      [188, 108, 37],
      [216, 87, 42],
      [244, 162, 97],
      [233, 196, 106],
      [42, 157, 143],
      [188, 108, 37],
    ],
    pageBg: [255, 250, 242],
    scriptColor: [70, 40, 20],
    bannerBar: [216, 87, 42],
    bannerText: [255, 255, 255],
    footerBar: [255, 230, 200],
    footerText: [90, 50, 25],
    ink: [60, 35, 20],
    muted: [110, 85, 60],
    tones: CLASSROOM_TONES,
    qrDark: "#6B2D12",
    qrLight: "#FFFAF2",
    starterSections: [
      starter("Harvest Highlights", "Pumpkin investigations, gratitude journals, and cozy reading nooks filled our week.", "banner", "orange", "full"),
      starter("Upcoming Events", "Harvest parade Fri 1:30\nFamily potluck sign-up online", "list", "yellow", "half"),
      starter("What We're Learning", "SCIENCE: Pumpkin life cycle\nMATH: Estimating & weighing\nREADING: Fall poems\nART: Leaf prints", "learning", "green", "half"),
      starter("Reminders & Notes", "Costume guidelines are attached. Please keep outfits school-friendly and easy for recess.", "card", "coral", "full"),
    ],
  },
];

export const DEFAULT_DESIGN_ID = NEWSLETTER_DESIGNS[0].id;

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
  return design.starterSections.map((s) => ({
    id: crypto.randomUUID(),
    heading: s.heading,
    body: s.body,
    variant: s.variant,
    tone: s.tone,
    width: s.width,
  }));
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
