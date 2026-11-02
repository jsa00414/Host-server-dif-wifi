import type { SectionTone } from "./types";
import type { NewsletterDesign } from "./designs";

export const TONE_FILL: Record<SectionTone, string> = {
  green: "#D2EFC6",
  blue: "#C9E6F5",
  pink: "#FAD6E0",
  orange: "#FFE0BC",
  yellow: "#FFF4B4",
  lavender: "#E6DCFA",
  coral: "#FFD6CD",
  mint: "#CDF2E6",
};

export const TONE_HEADING: Record<SectionTone, string> = {
  green: "#2E7D32",
  blue: "#D65A31",
  pink: "#3878C4",
  orange: "#46AA5A",
  yellow: "#C8781E",
  lavender: "#7850B4",
  coral: "#C84650",
  mint: "#148278",
};

export function rgbCss(rgb: [number, number, number]): string {
  return `rgb(${rgb[0]}, ${rgb[1]}, ${rgb[2]})`;
}

export function letterColorCss(design: NewsletterDesign): string[] {
  return design.letterColors.map((c) => rgbCss(c));
}
