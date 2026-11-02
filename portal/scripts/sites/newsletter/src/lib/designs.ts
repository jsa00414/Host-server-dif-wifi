export type DesignLayout =
  | "banner"
  | "sidebar"
  | "cards"
  | "stripes"
  | "blocks"
  | "wave"
  | "ribbon"
  | "grid"
  | "magazine"
  | "playful";

export type NewsletterDesign = {
  id: string;
  name: string;
  tagline: string;
  layout: DesignLayout;
  /** Swatch colors for the picker UI */
  swatches: [string, string, string, string];
  colors: {
    pageBg: [number, number, number];
    headerBg: [number, number, number];
    headerBg2: [number, number, number];
    accent: [number, number, number];
    accent2: [number, number, number];
    accent3: [number, number, number];
    sectionBg: [number, number, number];
    text: [number, number, number];
    muted: [number, number, number];
    onHeader: [number, number, number];
    qrDark: string;
    qrLight: string;
  };
};

export const NEWSLETTER_DESIGNS: NewsletterDesign[] = [
  {
    id: "sunshine-sky",
    name: "Sunshine Sky",
    tagline: "Bright blue banner with sunny stripe",
    layout: "banner",
    swatches: ["#4BA3C3", "#F5D76E", "#5DAE8B", "#1E3A5F"],
    colors: {
      pageBg: [243, 248, 251],
      headerBg: [75, 163, 195],
      headerBg2: [47, 126, 160],
      accent: [245, 215, 110],
      accent2: [93, 174, 139],
      accent3: [224, 122, 95],
      sectionBg: [255, 255, 255],
      text: [30, 58, 95],
      muted: [74, 98, 120],
      onHeader: [255, 255, 255],
      qrDark: "#1E3A5F",
      qrLight: "#FFFFFF",
    },
  },
  {
    id: "coral-garden",
    name: "Coral Garden",
    tagline: "Warm coral header with leafy accents",
    layout: "ribbon",
    swatches: ["#E07A5F", "#F2CC8F", "#81B29A", "#3D405B"],
    colors: {
      pageBg: [255, 248, 243],
      headerBg: [224, 122, 95],
      headerBg2: [192, 86, 66],
      accent: [242, 204, 143],
      accent2: [129, 178, 154],
      accent3: [61, 64, 91],
      sectionBg: [255, 255, 255],
      text: [61, 64, 91],
      muted: [110, 104, 120],
      onHeader: [255, 255, 255],
      qrDark: "#3D405B",
      qrLight: "#FFF8F3",
    },
  },
  {
    id: "rainbow-blocks",
    name: "Rainbow Blocks",
    tagline: "Colorful section cards in a playful stack",
    layout: "blocks",
    swatches: ["#EF476F", "#FFD166", "#06D6A0", "#118AB2"],
    colors: {
      pageBg: [255, 252, 245],
      headerBg: [17, 138, 178],
      headerBg2: [7, 59, 76],
      accent: [239, 71, 111],
      accent2: [255, 209, 102],
      accent3: [6, 214, 160],
      sectionBg: [255, 255, 255],
      text: [7, 59, 76],
      muted: [73, 80, 87],
      onHeader: [255, 255, 255],
      qrDark: "#073B4C",
      qrLight: "#FFFFFF",
    },
  },
  {
    id: "berry-burst",
    name: "Berry Burst",
    tagline: "Bold magenta and grape energy",
    layout: "magazine",
    swatches: ["#9B5DE5", "#F15BB5", "#FEE440", "#00BBF9"],
    colors: {
      pageBg: [252, 246, 255],
      headerBg: [155, 93, 229],
      headerBg2: [241, 91, 181],
      accent: [254, 228, 64],
      accent2: [0, 187, 249],
      accent3: [241, 91, 181],
      sectionBg: [255, 255, 255],
      text: [56, 30, 82],
      muted: [110, 90, 130],
      onHeader: [255, 255, 255],
      qrDark: "#381E52",
      qrLight: "#FCF6FF",
    },
  },
  {
    id: "lemon-lime",
    name: "Lemon Lime",
    tagline: "Zesty yellow and lime sidebar",
    layout: "sidebar",
    swatches: ["#F9C74F", "#90BE6D", "#43AA8B", "#277DA1"],
    colors: {
      pageBg: [255, 253, 240],
      headerBg: [249, 199, 79],
      headerBg2: [144, 190, 109],
      accent: [67, 170, 139],
      accent2: [39, 125, 161],
      accent3: [249, 199, 79],
      sectionBg: [255, 255, 255],
      text: [33, 53, 71],
      muted: [90, 110, 100],
      onHeader: [33, 53, 71],
      qrDark: "#215347",
      qrLight: "#FFFFF0",
    },
  },
  {
    id: "ocean-waves",
    name: "Ocean Waves",
    tagline: "Deep teal waves and seafoam cards",
    layout: "wave",
    swatches: ["#0077B6", "#00B4D8", "#90E0EF", "#03045E"],
    colors: {
      pageBg: [232, 247, 252],
      headerBg: [0, 119, 182],
      headerBg2: [3, 4, 94],
      accent: [0, 180, 216],
      accent2: [144, 224, 239],
      accent3: [72, 202, 228],
      sectionBg: [255, 255, 255],
      text: [3, 4, 94],
      muted: [70, 100, 130],
      onHeader: [255, 255, 255],
      qrDark: "#03045E",
      qrLight: "#E8F7FC",
    },
  },
  {
    id: "autumn-leaves",
    name: "Autumn Leaves",
    tagline: "Cozy orange, rust, and gold stripes",
    layout: "stripes",
    swatches: ["#D8572A", "#F4A261", "#E9C46A", "#264653"],
    colors: {
      pageBg: [255, 249, 240],
      headerBg: [216, 87, 42],
      headerBg2: [244, 162, 97],
      accent: [233, 196, 106],
      accent2: [38, 70, 83],
      accent3: [231, 111, 81],
      sectionBg: [255, 255, 255],
      text: [38, 70, 83],
      muted: [100, 90, 70],
      onHeader: [255, 255, 255],
      qrDark: "#264653",
      qrLight: "#FFF9F0",
    },
  },
  {
    id: "confetti-parade",
    name: "Confetti Parade",
    tagline: "Party dots and cheerful color pops",
    layout: "playful",
    swatches: ["#FF6B6B", "#4ECDC4", "#FFE66D", "#1A535C"],
    colors: {
      pageBg: [255, 250, 245],
      headerBg: [255, 107, 107],
      headerBg2: [78, 205, 196],
      accent: [255, 230, 109],
      accent2: [26, 83, 92],
      accent3: [255, 107, 107],
      sectionBg: [255, 255, 255],
      text: [26, 83, 92],
      muted: [90, 110, 115],
      onHeader: [255, 255, 255],
      qrDark: "#1A535C",
      qrLight: "#FFFAF5",
    },
  },
  {
    id: "mint-meadow",
    name: "Mint Meadow",
    tagline: "Soft mint panels with organized grid",
    layout: "grid",
    swatches: ["#2A9D8F", "#A8DADC", "#E9C46A", "#264653"],
    colors: {
      pageBg: [240, 249, 247],
      headerBg: [42, 157, 143],
      headerBg2: [38, 70, 83],
      accent: [233, 196, 106],
      accent2: [168, 218, 220],
      accent3: [42, 157, 143],
      sectionBg: [255, 255, 255],
      text: [38, 70, 83],
      muted: [80, 110, 105],
      onHeader: [255, 255, 255],
      qrDark: "#264653",
      qrLight: "#F0F9F7",
    },
  },
  {
    id: "sunset-stripe",
    name: "Sunset Stripe",
    tagline: "Orange-to-purple sunset bands",
    layout: "cards",
    swatches: ["#F77F00", "#FCBF49", "#D62828", "#8338EC"],
    colors: {
      pageBg: [255, 246, 238],
      headerBg: [247, 127, 0],
      headerBg2: [131, 56, 236],
      accent: [252, 191, 73],
      accent2: [214, 40, 40],
      accent3: [131, 56, 236],
      sectionBg: [255, 255, 255],
      text: [60, 30, 50],
      muted: [110, 80, 90],
      onHeader: [255, 255, 255],
      qrDark: "#3C1E32",
      qrLight: "#FFF6EE",
    },
  },
];

export const DEFAULT_DESIGN_ID = NEWSLETTER_DESIGNS[0].id;

export function getDesign(id?: string | null): NewsletterDesign {
  return (
    NEWSLETTER_DESIGNS.find((d) => d.id === id) || NEWSLETTER_DESIGNS[0]
  );
}

export function isDesignId(id: string): boolean {
  return NEWSLETTER_DESIGNS.some((d) => d.id === id);
}
