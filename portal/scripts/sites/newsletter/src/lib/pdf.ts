import { jsPDF } from "jspdf";
import QRCode from "qrcode";
import { getDesign, type NewsletterDesign, type TonePalette } from "./designs";
import { resolvePdfImage } from "./imageData";
import { sortLayers } from "./layers";
import type {
  Newsletter,
  NewsletterLayer,
  NewsletterSection,
  SectionTone,
  SiteConfig,
} from "./types";
import { slideshowUrl } from "./url";

type RGB = [number, number, number];

const DEFAULT_TONES: SectionTone[] = ["green", "blue", "orange", "pink"];

function rgb(doc: jsPDF, color: RGB, mode: "fill" | "draw" | "text") {
  if (mode === "fill") doc.setFillColor(...color);
  else if (mode === "draw") doc.setDrawColor(...color);
  else doc.setTextColor(...color);
}

function toneFor(
  design: NewsletterDesign,
  section: NewsletterSection,
  index: number,
): TonePalette {
  const key = section.tone || DEFAULT_TONES[index % DEFAULT_TONES.length];
  return design.tones[key];
}

function formatIssueDate(issueDate: string) {
  return new Date(issueDate + "T12:00:00").toLocaleDateString("en-US", {
    month: "long",
    day: "numeric",
    year: "numeric",
  });
}

function drawStar(
  doc: jsPDF,
  cx: number,
  cy: number,
  r: number,
  color: RGB,
) {
  rgb(doc, color, "fill");
  const pts: Array<[number, number]> = [];
  for (let i = 0; i < 5; i += 1) {
    const a = -Math.PI / 2 + (i * 2 * Math.PI) / 5;
    pts.push([cx + Math.cos(a) * r, cy + Math.sin(a) * r]);
    const b = a + Math.PI / 5;
    pts.push([cx + Math.cos(b) * r * 0.42, cy + Math.sin(b) * r * 0.42]);
  }
  for (let i = 0; i < pts.length; i += 1) {
    const n = (i + 1) % pts.length;
    doc.triangle(cx, cy, pts[i][0], pts[i][1], pts[n][0], pts[n][1], "F");
  }
}

function drawBunting(doc: jsPDF, pageWidth: number, colors: RGB[]) {
  const startX = pageWidth - 210;
  const startY = 28;
  doc.setDrawColor(120, 120, 120);
  doc.setLineWidth(0.8);
  doc.line(startX, startY, pageWidth - 28, startY + 8);
  for (let i = 0; i < 7; i += 1) {
    const x = startX + i * 24;
    const y = startY + i * 1.1;
    rgb(doc, colors[i % colors.length], "fill");
    doc.circle(x, y + 10, 7, "F");
  }
}

function drawPencil(doc: jsPDF, x: number, y: number, scale = 1) {
  const w = 8 * scale;
  const h = 22 * scale;
  doc.setFillColor(255, 214, 102);
  doc.roundedRect(x, y, w, h, 1, 1, "F");
  doc.setFillColor(255, 180, 80);
  doc.triangle(x, y, x + w, y, x + w / 2, y - 8 * scale, "F");
  doc.setFillColor(80, 80, 80);
  doc.triangle(
    x + w * 0.28,
    y - 3 * scale,
    x + w * 0.72,
    y - 3 * scale,
    x + w / 2,
    y - 8 * scale,
    "F",
  );
  doc.setFillColor(80, 180, 220);
  doc.rect(x, y + h - 5 * scale, w, 5 * scale, "F");
}

function drawRainbowArc(
  doc: jsPDF,
  x: number,
  y: number,
  colors: RGB[],
  radius = 36,
  maskBg?: RGB,
) {
  const bands = colors.slice(0, 6);
  bands.forEach((c, i) => {
    doc.setDrawColor(...c);
    doc.setLineWidth(3.4);
    doc.circle(x, y, radius - i * 3.6, "S");
  });
  rgb(doc, maskBg || [255, 255, 255], "fill");
  doc.rect(x - radius - 4, y, radius * 2 + 8, radius + 8, "F");
}

function drawDaisy(doc: jsPDF, cx: number, cy: number, r = 10) {
  for (let i = 0; i < 8; i += 1) {
    const a = (i * Math.PI) / 4;
    doc.setFillColor(255, 255, 255);
    doc.ellipse(
      cx + Math.cos(a) * r * 0.7,
      cy + Math.sin(a) * r * 0.7,
      r * 0.45,
      r * 0.28,
      "F",
    );
    doc.setDrawColor(220, 220, 220);
    doc.setLineWidth(0.4);
    doc.ellipse(
      cx + Math.cos(a) * r * 0.7,
      cy + Math.sin(a) * r * 0.7,
      r * 0.45,
      r * 0.28,
      "S",
    );
  }
  doc.setFillColor(255, 210, 70);
  doc.circle(cx, cy, r * 0.38, "F");
}

function drawSun(doc: jsPDF, cx: number, cy: number, r = 16) {
  doc.setFillColor(255, 200, 40);
  for (let i = 0; i < 10; i += 1) {
    const a = (i * Math.PI) / 5;
    doc.triangle(
      cx,
      cy,
      cx + Math.cos(a) * (r + 8),
      cy + Math.sin(a) * (r + 8),
      cx + Math.cos(a + 0.2) * (r + 2),
      cy + Math.sin(a + 0.2) * (r + 2),
      "F",
    );
  }
  doc.circle(cx, cy, r, "F");
}

function drawHeart(doc: jsPDF, x: number, y: number, s = 8, color: RGB = [255, 120, 150]) {
  rgb(doc, color, "fill");
  doc.circle(x - s * 0.35, y, s * 0.4, "F");
  doc.circle(x + s * 0.35, y, s * 0.4, "F");
  doc.triangle(x - s * 0.72, y + s * 0.1, x + s * 0.72, y + s * 0.1, x, y + s, "F");
}

function drawPaperclip(doc: jsPDF, x: number, y: number) {
  doc.setDrawColor(140, 150, 165);
  doc.setLineWidth(1.6);
  doc.roundedRect(x, y, 10, 22, 4, 4, "S");
  doc.roundedRect(x + 3, y + 4, 4, 14, 2, 2, "S");
}

function drawPagePattern(
  doc: jsPDF,
  design: NewsletterDesign,
  pageWidth: number,
  pageHeight: number,
) {
  if (design.pagePattern === "none") return;
  if (design.pagePattern === "dots" || design.pagePattern === "spots") {
    const step = design.pagePattern === "spots" ? 28 : 22;
    const r = design.pagePattern === "spots" ? 2.2 : 1.1;
    const color: RGB =
      design.pagePattern === "spots" ? [25, 25, 25] : [210, 210, 215];
    rgb(doc, color, "fill");
    for (let y = 18; y < pageHeight - 20; y += step) {
      for (let x = 18; x < pageWidth - 12; x += step) {
        const offset = Math.floor(y / step) % 2 === 0 ? 0 : step / 2;
        doc.circle(x + offset, y, r, "F");
      }
    }
  }
  if (design.pagePattern === "gingham") {
    const step = 18;
    doc.setFillColor(247, 220, 232);
    for (let x = 0; x < pageWidth; x += step * 2) {
      doc.rect(x, 0, step, pageHeight, "F");
    }
    doc.setFillColor(220, 240, 232);
    for (let y = 0; y < pageHeight; y += step * 2) {
      doc.rect(0, y, pageWidth, step, "F");
    }
    // soften with white overlay wash
    doc.setFillColor(255, 255, 255);
    // jsPDF doesn't support opacity easily; redraw content area wash lightly via small skip
  }
  if (design.pagePattern === "confetti") {
    const colors = design.letterColors;
    for (let i = 0; i < 48; i += 1) {
      const x = 24 + ((i * 73) % (pageWidth - 48));
      const y = 24 + ((i * 97) % (pageHeight - 48));
      rgb(doc, colors[i % colors.length], "fill");
      if (i % 3 === 0) doc.circle(x, y, 2.2, "F");
      else if (i % 3 === 1) doc.rect(x, y, 4, 2.2, "F");
      else doc.triangle(x, y, x + 4, y, x + 2, y + 4, "F");
    }
  }
}

function drawDecorations(
  doc: jsPDF,
  design: NewsletterDesign,
  pageWidth: number,
) {
  const colors = design.letterColors;
  const d = design.decorations;
  if (d === "stars-bunting") {
    drawStar(doc, 48, 34, 8, colors[0]);
    drawStar(doc, 78, 58, 6, colors[2]);
    drawStar(doc, 120, 28, 5, colors[4]);
    drawBunting(doc, pageWidth, colors);
  }
  if (d === "rainbow" || d === "boho-rainbow") {
    drawRainbowArc(
      doc,
      pageWidth - 70,
      58,
      d === "boho-rainbow"
        ? [
            [201, 123, 99],
            [212, 163, 115],
            [233, 196, 106],
            [163, 177, 138],
            [188, 143, 143],
          ]
        : colors,
      d === "boho-rainbow" ? 30 : 38,
      design.pageBg,
    );
    drawStar(doc, 42, 36, 6, colors[1]);
  }
  if (d === "daisy" || d === "gingham") {
    drawDaisy(doc, pageWidth - 58, 42, 12);
    drawDaisy(doc, pageWidth - 92, 58, 8);
    drawDaisy(doc, 48, 40, 7);
  }
  if (d === "spots") {
    rgb(doc, [20, 20, 20], "fill");
    for (const [x, y, r] of [
      [48, 36, 4],
      [70, 52, 3],
      [96, 30, 5],
      [pageWidth - 60, 40, 4],
      [pageWidth - 88, 58, 3],
    ] as Array<[number, number, number]>) {
      doc.circle(x, y, r, "F");
    }
  }
  if (d === "sun") {
    drawSun(doc, pageWidth - 62, 48, 15);
    drawStar(doc, 44, 38, 6, colors[0]);
  }
  if (d === "paperclip") {
    drawPaperclip(doc, pageWidth - 58, 28);
    drawPaperclip(doc, pageWidth - 42, 40);
    drawStar(doc, 46, 36, 5, colors[1]);
  }
  if (d === "crayons") {
    drawPencil(doc, pageWidth - 70, 36, 1.1);
    drawPencil(doc, pageWidth - 54, 40, 0.95);
    drawPencil(doc, pageWidth - 38, 38, 0.85);
  }
  if (d === "confetti") {
    for (let i = 0; i < 12; i += 1) {
      rgb(doc, colors[i % colors.length], "fill");
      const x = 36 + i * 18;
      doc.circle(x, 28 + (i % 3) * 8, 2.5, "F");
    }
    drawStar(doc, pageWidth - 56, 40, 7, colors[0]);
  }
  if (d === "ink") {
    doc.setDrawColor(30, 30, 30);
    doc.setLineWidth(1.4);
    doc.roundedRect(pageWidth - 86, 24, 48, 48, 6, 6, "S");
    doc.setLineWidth(0.8);
    doc.setLineDashPattern([2, 2], 0);
    doc.roundedRect(pageWidth - 78, 32, 32, 32, 4, 4, "S");
    doc.setLineDashPattern([], 0);
    drawStar(doc, 46, 38, 7, [30, 30, 30]);
  }
  if (d === "hearts") {
    drawHeart(doc, pageWidth - 56, 40, 9, colors[1]);
    drawHeart(doc, pageWidth - 84, 54, 6, colors[0]);
    drawHeart(doc, 52, 38, 7, colors[2]);
  }
}

function drawMulticolorTitle(
  doc: jsPDF,
  text: string,
  x: number,
  y: number,
  colors: RGB[],
  size = 34,
) {
  const word = text.toUpperCase();
  doc.setFont("helvetica", "bold");
  doc.setFontSize(size);
  let cursor = x;
  for (let i = 0; i < word.length; i += 1) {
    const ch = word[i];
    rgb(doc, colors[i % colors.length], "text");
    doc.text(ch, cursor, y);
    cursor += doc.getTextWidth(ch) + 1.5;
  }
}

function drawHeader(
  doc: jsPDF,
  design: NewsletterDesign,
  newsletter: Newsletter,
  config: SiteConfig,
  pageWidth: number,
  margin: number,
) {
  drawDecorations(doc, design, pageWidth);
  const script = newsletter.title?.trim() || config.className || "Classroom";
  const meta = `${config.className} · ${config.grade} · Room ${config.room} · ${formatIssueDate(newsletter.issueDate)}`;
  const label = (
    newsletter.bannerLabel ||
    newsletter.subtitle ||
    "CLASS NEWS"
  ).toUpperCase();

  if (design.headerStyle === "chunky-bar") {
    rgb(doc, design.bannerBar, "fill");
    doc.roundedRect(margin, 28, pageWidth - margin * 2, 72, 12, 12, "F");
    rgb(doc, design.bannerText, "text");
    doc.setFont("helvetica", "bold");
    doc.setFontSize(26);
    doc.text(script.toUpperCase(), pageWidth / 2, 58, { align: "center" });
    doc.setFontSize(12);
    doc.text("NEWSLETTER", pageWidth / 2, 78, { align: "center" });
    doc.setFont("helvetica", "normal");
    doc.setFontSize(9);
    rgb(doc, design.muted, "text");
    doc.text(meta, pageWidth / 2, 118, { align: "center" });
    rgb(doc, design.tones.yellow?.bar || design.letterColors[3], "fill");
    doc.roundedRect(margin, 130, pageWidth - margin * 2, 26, 8, 8, "F");
    rgb(doc, design.ink, "text");
    doc.setFont("helvetica", "bold");
    doc.setFontSize(11);
    doc.text(label, pageWidth / 2, 147, { align: "center" });
    return 170;
  }

  if (design.headerStyle === "boho") {
    rgb(doc, design.scriptColor, "text");
    doc.setFont("times", "italic");
    doc.setFontSize(30);
    doc.text(script, margin, 56);
    doc.setFont("helvetica", "bold");
    doc.setFontSize(18);
    rgb(doc, design.bannerBar, "text");
    doc.text("OUR CLASS NEWS", margin, 84);
    drawRainbowArc(doc, pageWidth - 78, 70, design.letterColors, 28, design.pageBg);
    doc.setFont("helvetica", "normal");
    doc.setFontSize(9);
    rgb(doc, design.muted, "text");
    doc.text(meta, margin, 108);
    doc.setDrawColor(...design.bannerBar);
    doc.setLineWidth(1.5);
    doc.line(margin, 122, pageWidth - margin, 122);
    doc.setFont("helvetica", "bold");
    doc.setFontSize(10);
    rgb(doc, design.scriptColor, "text");
    doc.text(label, margin, 140);
    return 158;
  }

  if (design.headerStyle === "spots-band") {
    rgb(doc, design.bannerBar, "fill");
    doc.roundedRect(margin, 28, pageWidth - margin * 2, 64, 10, 10, "F");
    // white spots on band
    doc.setFillColor(255, 255, 255);
    for (let i = 0; i < 18; i += 1) {
      doc.circle(margin + 18 + i * 28, 44 + (i % 2) * 16, 3.2, "F");
    }
    rgb(doc, design.bannerText, "text");
    doc.setFont("helvetica", "bold");
    doc.setFontSize(24);
    doc.text(script.toUpperCase(), pageWidth / 2, 58, { align: "center" });
    doc.setFontSize(11);
    doc.text("NEWSLETTER", pageWidth / 2, 76, { align: "center" });
    doc.setFont("helvetica", "normal");
    doc.setFontSize(9);
    rgb(doc, design.muted, "text");
    doc.text(meta, pageWidth / 2, 112, { align: "center" });
    rgb(doc, design.letterColors[0], "fill");
    doc.roundedRect(margin, 124, pageWidth - margin * 2, 24, 6, 6, "F");
    rgb(doc, [255, 255, 255], "text");
    doc.setFont("helvetica", "bold");
    doc.setFontSize(11);
    doc.text(label, pageWidth / 2, 140, { align: "center" });
    return 162;
  }

  if (design.headerStyle === "ink-banner") {
    doc.setDrawColor(20, 20, 20);
    doc.setLineWidth(2);
    doc.roundedRect(margin, 28, pageWidth - margin * 2, 70, 4, 4, "S");
    doc.setFont("helvetica", "bold");
    doc.setFontSize(22);
    rgb(doc, design.ink, "text");
    doc.text(script.toUpperCase(), pageWidth / 2, 56, { align: "center" });
    doc.setFontSize(12);
    doc.text("CLASSROOM NEWSLETTER", pageWidth / 2, 76, { align: "center" });
    doc.setLineDashPattern([1.5, 1.5], 0);
    doc.line(margin + 16, 86, pageWidth - margin - 16, 86);
    doc.setLineDashPattern([], 0);
    doc.setFont("helvetica", "normal");
    doc.setFontSize(9);
    rgb(doc, design.muted, "text");
    doc.text(meta, pageWidth / 2, 118, { align: "center" });
    rgb(doc, design.bannerBar, "fill");
    doc.rect(margin, 130, pageWidth - margin * 2, 22, "F");
    rgb(doc, design.bannerText, "text");
    doc.setFont("helvetica", "bold");
    doc.setFontSize(10);
    doc.text(label, pageWidth / 2, 145, { align: "center" });
    return 166;
  }

  if (design.headerStyle === "soft-pill") {
    rgb(doc, design.scriptColor, "text");
    doc.setFont("times", "italic");
    doc.setFontSize(28);
    doc.text(script, margin, 54);
    drawMulticolorTitle(doc, "Newsletter", margin, 88, design.letterColors, 30);
    doc.setFont("helvetica", "normal");
    doc.setFontSize(9);
    rgb(doc, design.muted, "text");
    doc.text(meta, margin, 108);
    rgb(doc, design.bannerBar, "fill");
    doc.roundedRect(margin, 122, pageWidth - margin * 2, 28, 14, 14, "F");
    rgb(doc, design.bannerText, "text");
    doc.setFont("helvetica", "bold");
    doc.setFontSize(11);
    doc.text(label, pageWidth / 2, 140, { align: "center" });
    return 164;
  }

  // rainbow-letters (default)
  rgb(doc, design.scriptColor, "text");
  doc.setFont("times", "italic");
  doc.setFontSize(28);
  doc.text(script, margin, 58);
  drawMulticolorTitle(doc, "Newsletter", margin, 96, design.letterColors);
  doc.setFont("helvetica", "normal");
  doc.setFontSize(10);
  rgb(doc, design.muted, "text");
  doc.text(meta, margin, 116);
  const barY = 130;
  rgb(doc, design.bannerBar, "fill");
  doc.roundedRect(margin, barY, pageWidth - margin * 2, 28, 6, 6, "F");
  drawPencil(doc, margin + 10, barY + 4, 0.85);
  drawPencil(doc, pageWidth - margin - 28, barY + 4, 0.85);
  rgb(doc, design.bannerText, "text");
  doc.setFont("helvetica", "bold");
  doc.setFontSize(12);
  doc.text(label, pageWidth / 2, barY + 18, { align: "center" });
  return barY + 44;
}

function measureBlock(
  doc: jsPDF,
  section: NewsletterSection,
  width: number,
  pad: number,
) {
  const inner = width - pad * 2;
  const bodyLines = doc.splitTextToSize(section.body || "", inner);
  const headingLines = doc.splitTextToSize(
    (section.heading || "Update").toUpperCase(),
    inner,
  );
  const imageH = section.imageSrc ? Math.min(110, inner * 0.45) + 8 : 0;
  return 18 + headingLines.length * 14 + bodyLines.length * 13 + pad * 2 + imageH;
}

function drawCardShell(
  doc: jsPDF,
  design: NewsletterDesign,
  tone: TonePalette,
  x: number,
  y: number,
  width: number,
  height: number,
) {
  const border = tone.border || tone.bar;
  if (design.cardStyle === "outlined" || design.cardStyle === "dashed") {
    doc.setFillColor(255, 255, 255);
    doc.roundedRect(x, y, width, height, 12, 12, "F");
    rgb(doc, border, "draw");
    doc.setLineWidth(design.cardStyle === "dashed" ? 1.2 : 2.2);
    if (design.cardStyle === "dashed") doc.setLineDashPattern([2.5, 2], 0);
    doc.roundedRect(x, y, width, height, 12, 12, "S");
    doc.setLineDashPattern([], 0);
    // accent corner
    rgb(doc, tone.fill, "fill");
    doc.roundedRect(x + 6, y + 6, 18, 8, 2, 2, "F");
    return;
  }
  if (design.cardStyle === "ink") {
    doc.setFillColor(255, 255, 255);
    doc.roundedRect(x, y, width, height, 4, 4, "F");
    doc.setDrawColor(20, 20, 20);
    doc.setLineWidth(1.6);
    doc.roundedRect(x, y, width, height, 4, 4, "S");
    doc.setLineDashPattern([1.5, 1.5], 0);
    doc.setLineWidth(0.8);
    doc.roundedRect(x + 4, y + 4, width - 8, height - 8, 2, 2, "S");
    doc.setLineDashPattern([], 0);
    return;
  }
  if (design.cardStyle === "top-strip") {
    rgb(doc, tone.fill, "fill");
    doc.roundedRect(x, y, width, height, 12, 12, "F");
    rgb(doc, tone.bar, "fill");
    doc.roundedRect(x, y, width, 10, 12, 12, "F");
    doc.rect(x, y + 6, width, 6, "F");
    return;
  }
  // soft
  rgb(doc, tone.fill, "fill");
  doc.roundedRect(x, y, width, height, 14, 14, "F");
}

function drawBlock(
  doc: jsPDF,
  design: NewsletterDesign,
  section: NewsletterSection,
  index: number,
  x: number,
  y: number,
  width: number,
  showRainbow: boolean,
) {
  const tone = toneFor(design, section, index);
  const pad = 12;
  const variant = section.variant || (index === 0 ? "banner" : "card");
  const height = measureBlock(doc, section, width, pad);

  if (variant === "banner") {
    rgb(doc, tone.bar, "fill");
    doc.roundedRect(x, y, width, 24, 5, 5, "F");
    if (design.decorations === "crayons" || design.headerStyle === "rainbow-letters") {
      drawPencil(doc, x + 8, y + 3, 0.75);
      drawPencil(doc, x + width - 24, y + 3, 0.75);
    }
    rgb(doc, [255, 255, 255], "text");
    if (design.cardStyle === "ink") rgb(doc, [255, 255, 255], "text");
    doc.setFont("helvetica", "bold");
    doc.setFontSize(11);
    doc.text((section.heading || "CLASS NEWS").toUpperCase(), x + width / 2, y + 16, {
      align: "center",
    });
    drawCardShell(doc, design, tone, x, y + 28, width, height - 20);
    rgb(doc, tone.body, "text");
    doc.setFont("helvetica", "normal");
    doc.setFontSize(10);
    const lines = doc.splitTextToSize(section.body || "", width - pad * 2);
    doc.text(lines, x + pad, y + 48);
    return height + 14;
  }

  drawCardShell(doc, design, tone, x, y, width, height);

  rgb(doc, tone.heading, "text");
  doc.setFont("helvetica", "bold");
  doc.setFontSize(13);
  const heading = (section.heading || "UPDATE").toUpperCase();
  const textTop = design.cardStyle === "top-strip" ? y + pad + 16 : y + pad + 12;
  doc.text(heading, x + pad, textTop, { maxWidth: width - pad * 2 });

  rgb(doc, tone.body, "text");
  doc.setFont("helvetica", "normal");
  doc.setFontSize(10);
  const bodyLines = doc.splitTextToSize(section.body || "", width - pad * 2);
  const headingHeight =
    doc.splitTextToSize(heading, width - pad * 2).length * 14;
  const textY = textTop + 6 + headingHeight;
  doc.text(bodyLines, x + pad, textY);

  if (showRainbow && (variant === "learning" || index === 2)) {
    if (design.decorations === "rainbow" || design.decorations === "boho-rainbow") {
      drawRainbowArc(doc, x + width - 42, y + height - 8, design.letterColors, 22, tone.fill);
    } else if (design.decorations === "hearts") {
      drawHeart(doc, x + width - 28, y + height - 22, 7, design.letterColors[1]);
    } else if (design.decorations === "daisy") {
      drawDaisy(doc, x + width - 28, y + height - 22, 8);
    } else if (design.decorations !== "ink") {
      drawRainbowArc(doc, x + width - 42, y + height - 8, design.letterColors, 20, tone.fill);
    }
  }

  return height + 12;
}

async function drawSectionImage(
  doc: jsPDF,
  section: NewsletterSection,
  x: number,
  y: number,
  width: number,
  pad: number,
  baseUrl?: string,
) {
  if (!section.imageSrc) return;
  const img = await resolvePdfImage(section.imageSrc, baseUrl);
  if (!img) return;
  const headingLines = doc.splitTextToSize(
    (section.heading || "UPDATE").toUpperCase(),
    width - pad * 2,
  );
  const bodyLines = doc.splitTextToSize(section.body || "", width - pad * 2);
  const top =
    y +
    pad +
    18 +
    headingLines.length * 14 +
    bodyLines.length * 13 +
    6;
  const maxW = width - pad * 2;
  const maxH = Math.min(110, maxW * 0.45);
  try {
    doc.addImage(img.dataUrl, img.format, x + pad, top, maxW, maxH);
  } catch {
    /* ignore bad image */
  }
}

type JsPdfGfx = jsPDF & {
  GState?: new (opts: { opacity: number }) => unknown;
  setGState?: (state: unknown) => void;
};

async function drawLayers(
  doc: jsPDF,
  layers: NewsletterLayer[] | undefined,
  pageWidth: number,
  pageHeight: number,
  baseUrl?: string,
) {
  const gfx = doc as JsPdfGfx;
  for (const layer of sortLayers(layers || [])) {
    const img = await resolvePdfImage(layer.src, baseUrl);
    if (!img) continue;
    const w = (layer.width / 100) * pageWidth;
    const h = (layer.height / 100) * pageHeight;
    const x = (layer.x / 100) * pageWidth;
    const y = (layer.y / 100) * pageHeight;
    try {
      if (gfx.GState && gfx.setGState && layer.opacity < 1) {
        gfx.setGState(new gfx.GState({ opacity: layer.opacity }));
      }
      doc.addImage(
        img.dataUrl,
        img.format,
        x,
        y,
        w,
        h,
        undefined,
        "FAST",
        layer.rotation || 0,
      );
      if (gfx.GState && gfx.setGState && layer.opacity < 1) {
        gfx.setGState(new gfx.GState({ opacity: 1 }));
      }
    } catch {
      try {
        doc.addImage(img.dataUrl, img.format, x, y, w, h);
      } catch {
        /* skip unreadable image */
      }
    }
  }
}

async function stampFooterAndQr(
  doc: jsPDF,
  design: NewsletterDesign,
  newsletter: Newsletter,
  config: SiteConfig,
  request: Request | undefined,
  pageWidth: number,
  pageHeight: number,
  margin: number,
) {
  const qrSize = 64;
  const slideLink = slideshowUrl(newsletter.slideshowToken || "preview", request);
  const qrDataUrl = await QRCode.toDataURL(slideLink, {
    errorCorrectionLevel: "M",
    margin: 1,
    width: 220,
    color: { dark: design.qrDark, light: design.qrLight },
  });

  const pageCount = doc.getNumberOfPages();
  for (let i = 1; i <= pageCount; i += 1) {
    doc.setPage(i);
    const footerY = pageHeight - 52;
    rgb(doc, design.footerBar, "fill");
    doc.roundedRect(margin, footerY, pageWidth - margin * 2 - qrSize - 18, 30, 8, 8, "F");
    rgb(doc, design.footerText, "text");
    doc.setFont("helvetica", "normal");
    doc.setFontSize(9);
    const footer =
      newsletter.footerNote ||
      `Contact: ${config.teacherName} · ${config.schoolName} · Room ${config.room}`;
    doc.text(footer, margin + 12, footerY + 18, {
      maxWidth: pageWidth - margin * 2 - qrSize - 40,
    });

    const qrX = pageWidth - margin - qrSize;
    const qrY = pageHeight - margin - qrSize - 4;
    doc.setFillColor(255, 255, 255);
    doc.roundedRect(qrX - 4, qrY - 4, qrSize + 8, qrSize + 18, 6, 6, "F");
    doc.addImage(qrDataUrl, "PNG", qrX, qrY, qrSize, qrSize);
    doc.setFontSize(7);
    rgb(doc, design.muted, "text");
    doc.text("Slideshow", qrX + qrSize / 2, qrY + qrSize + 9, {
      align: "center",
    });
  }
}

function requestOrigin(request?: Request): string | undefined {
  if (!request) {
    if (typeof window !== "undefined") return window.location.origin;
    return undefined;
  }
  try {
    return new URL(request.url).origin;
  } catch {
    return undefined;
  }
}

export async function buildNewsletterPdf(
  newsletter: Newsletter,
  config: SiteConfig,
  request?: Request,
): Promise<Uint8Array> {
  const design = getDesign(newsletter.designId);
  const doc = new jsPDF({ unit: "pt", format: "letter" });
  const pageWidth = doc.internal.pageSize.getWidth();
  const pageHeight = doc.internal.pageSize.getHeight();
  const margin = 40;
  const gap = 14;
  const contentWidth = pageWidth - margin * 2;
  const half = (contentWidth - gap) / 2;
  const bottomSafe = 100;
  const baseUrl = requestOrigin(request);

  rgb(doc, design.pageBg, "fill");
  doc.rect(0, 0, pageWidth, pageHeight, "F");
  drawPagePattern(doc, design, pageWidth, pageHeight);

  let y = drawHeader(doc, design, newsletter, config, pageWidth, margin);

  const sections = (newsletter.sections || []).filter(
    (s) => s.heading.trim() || s.body.trim(),
  );

  let i = 0;
  while (i < sections.length) {
    const section = sections[i];
    const widthMode = section.width || (section.variant === "banner" ? "full" : i === 0 ? "full" : "half");

    if (widthMode === "full" || !sections[i + 1] || sections[i + 1].width === "full" || sections[i + 1].variant === "banner") {
      const h = measureBlock(doc, section, contentWidth, 12) + (section.variant === "banner" ? 14 : 12);
      if (y + h > pageHeight - bottomSafe) {
        doc.addPage();
        rgb(doc, design.pageBg, "fill");
        doc.rect(0, 0, pageWidth, pageHeight, "F");
        drawPagePattern(doc, design, pageWidth, pageHeight);
        y = 48;
      }
      const blockY = y;
      y += drawBlock(doc, design, section, i, margin, blockY, contentWidth, true);
      if (section.variant !== "banner") {
        await drawSectionImage(doc, section, margin, blockY, contentWidth, 12, baseUrl);
      }
      i += 1;
      continue;
    }

    const left = section;
    const right = sections[i + 1];
    const leftH = measureBlock(doc, left, half, 12) + 12;
    const rightH = measureBlock(doc, right, half, 12) + 12;
    const rowH = Math.max(leftH, rightH);
    if (y + rowH > pageHeight - bottomSafe) {
      doc.addPage();
      rgb(doc, design.pageBg, "fill");
      doc.rect(0, 0, pageWidth, pageHeight, "F");
      drawPagePattern(doc, design, pageWidth, pageHeight);
      y = 48;
    }
    const leftY = y;
    drawBlock(doc, design, left, i, margin, leftY, half, false);
    await drawSectionImage(doc, left, margin, leftY, half, 12, baseUrl);
    drawBlock(doc, design, right, i + 1, margin + half + gap, leftY, half, true);
    await drawSectionImage(doc, right, margin + half + gap, leftY, half, 12, baseUrl);
    y += rowH;
    i += 2;
  }

  await drawLayers(doc, newsletter.layers, pageWidth, pageHeight, baseUrl);

  await stampFooterAndQr(
    doc,
    design,
    newsletter,
    config,
    request,
    pageWidth,
    pageHeight,
    margin,
  );

  return new Uint8Array(doc.output("arraybuffer"));
}
