import type { CSSProperties } from "react";
import type { SectionTone } from "./types";
import type { NewsletterDesign, TonePalette } from "./designs";

/** Fallback fills when a design is unavailable. */
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

export function toneCss(tone: TonePalette) {
  return {
    fill: rgbCss(tone.fill),
    heading: rgbCss(tone.heading),
    body: rgbCss(tone.body),
    bar: rgbCss(tone.bar),
    border: rgbCss(tone.border || tone.bar),
  };
}

export function designToneCss(design: NewsletterDesign, tone: SectionTone) {
  return toneCss(design.tones[tone]);
}

export function pagePatternStyle(design: NewsletterDesign): CSSProperties {
  if (design.pagePattern === "dots") {
    return {
      backgroundColor: rgbCss(design.pageBg),
      backgroundImage: "radial-gradient(#d2d2d8 1.2px, transparent 1.2px)",
      backgroundSize: "18px 18px",
    };
  }
  if (design.pagePattern === "spots") {
    return {
      backgroundColor: rgbCss(design.pageBg),
      backgroundImage: "radial-gradient(#111 2px, transparent 2px)",
      backgroundSize: "26px 26px",
    };
  }
  if (design.pagePattern === "gingham") {
    return {
      backgroundColor: rgbCss(design.pageBg),
      backgroundImage:
        "linear-gradient(90deg, rgba(247,168,198,0.18) 50%, transparent 50%), linear-gradient(rgba(184,224,210,0.18) 50%, transparent 50%)",
      backgroundSize: "22px 22px",
    };
  }
  if (design.pagePattern === "confetti") {
    return {
      backgroundColor: rgbCss(design.pageBg),
      backgroundImage:
        "radial-gradient(circle at 10% 20%, rgba(255,0,110,0.18) 0 3px, transparent 4px), radial-gradient(circle at 80% 30%, rgba(58,134,255,0.18) 0 3px, transparent 4px), radial-gradient(circle at 40% 70%, rgba(255,190,11,0.2) 0 3px, transparent 4px)",
    };
  }
  return { backgroundColor: rgbCss(design.pageBg) };
}
