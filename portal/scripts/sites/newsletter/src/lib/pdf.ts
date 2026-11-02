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
  // jsPDF triangle fan approximation with small filled triangles
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

function drawRainbow(doc: jsPDF, x: number, y: number) {
  const bands: RGB[] = [
    [255, 99, 99],
    [255, 170, 60],
    [255, 220, 70],
    [90, 200, 110],
    [80, 160, 230],
    [150, 110, 220],
  ];
  bands.forEach((c, i) => {
    doc.setDrawColor(...c);
    doc.setLineWidth(4);
    doc.circle(x, y, 34 - i * 4.2, "S");
  });
  // mask lower half with a white semi by covering
  doc.setFillColor(255, 255, 255);
  doc.rect(x - 40, y, 80, 44, "F");
  doc.setFillColor(255, 210, 70);
  doc.circle(x + 28, y + 6, 8, "F");
}

function drawDecorations(
  doc: jsPDF,
  design: NewsletterDesign,
  pageWidth: number,
) {
  const colors = design.letterColors;
  if (
    design.decorations === "stars-bunting" ||
    design.decorations === "storytime" ||
    design.decorations === "space" ||
    design.decorations === "playground"
  ) {
    drawStar(doc, 48, 34, 8, colors[0]);
    drawStar(doc, 78, 58, 6, colors[2]);
    drawStar(doc, 120, 28, 5, colors[4]);
    drawStar(doc, pageWidth - 250, 52, 6, colors[1]);
    drawBunting(doc, pageWidth, colors);
  }
  if (design.decorations === "crayons" || design.decorations === "candy") {
    drawPencil(doc, pageWidth - 70, 36, 1.1);
    drawPencil(doc, pageWidth - 54, 40, 0.95);
    drawStar(doc, 40, 40, 7, colors[0]);
  }
  if (design.decorations === "garden" || design.decorations === "harvest") {
    drawStar(doc, 42, 36, 7, colors[1]);
    rgb(doc, colors[0], "fill");
    doc.circle(pageWidth - 56, 46, 10, "F");
    rgb(doc, colors[2], "fill");
    doc.circle(pageWidth - 40, 58, 7, "F");
  }
  if (design.decorations === "aqua") {
    rgb(doc, colors[0], "fill");
    doc.ellipse(pageWidth - 60, 50, 16, 8, "F");
    rgb(doc, colors[2], "fill");
    doc.ellipse(pageWidth - 90, 62, 12, 6, "F");
  }
  if (design.decorations === "sticky") {
    rgb(doc, colors[0], "fill");
    doc.roundedRect(pageWidth - 78, 28, 36, 36, 3, 3, "F");
    rgb(doc, colors[2], "fill");
    doc.roundedRect(pageWidth - 52, 44, 32, 32, 3, 3, "F");
  }
}

function drawMulticolorTitle(
  doc: jsPDF,
  text: string,
  x: number,
  y: number,
  colors: RGB[],
) {
  const word = text.toUpperCase();
  doc.setFont("helvetica", "bold");
  doc.setFontSize(34);
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

  // Script-style class label
  rgb(doc, design.scriptColor, "text");
  doc.setFont("times", "italic");
  doc.setFontSize(28);
  const script = newsletter.title?.trim() || config.className || "Classroom";
  doc.text(script, margin, 58);

  drawMulticolorTitle(doc, "Newsletter", margin, 96, design.letterColors);

  doc.setFont("helvetica", "normal");
  doc.setFontSize(10);
  rgb(doc, design.muted, "text");
  doc.text(
    `${config.className} · ${config.grade} · Room ${config.room} · ${formatIssueDate(newsletter.issueDate)}`,
    margin,
    116,
  );

  // Banner bar with pencils
  const label =
    (newsletter.bannerLabel || newsletter.subtitle || "CLASS NEWS").toUpperCase();
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
    drawPencil(doc, x + 8, y + 3, 0.75);
    drawPencil(doc, x + width - 24, y + 3, 0.75);
    rgb(doc, [255, 255, 255], "text");
    doc.setFont("helvetica", "bold");
    doc.setFontSize(11);
    doc.text((section.heading || "CLASS NEWS").toUpperCase(), x + width / 2, y + 16, {
      align: "center",
    });
    rgb(doc, tone.fill, "fill");
    doc.roundedRect(x, y + 28, width, height - 20, 10, 10, "F");
    rgb(doc, tone.body, "text");
    doc.setFont("helvetica", "normal");
    doc.setFontSize(10);
    const lines = doc.splitTextToSize(section.body || "", width - pad * 2);
    doc.text(lines, x + pad, y + 48);
    return height + 14;
  }

  rgb(doc, tone.fill, "fill");
  doc.roundedRect(x, y, width, height, 14, 14, "F");

  rgb(doc, tone.heading, "text");
  doc.setFont("helvetica", "bold");
  doc.setFontSize(13);
  const heading = (section.heading || "UPDATE").toUpperCase();
  doc.text(heading, x + pad, y + pad + 12, { maxWidth: width - pad * 2 });

  rgb(doc, tone.body, "text");
  doc.setFont("helvetica", "normal");
  doc.setFontSize(10);
  const bodyLines = doc.splitTextToSize(section.body || "", width - pad * 2);
  const headingHeight =
    doc.splitTextToSize(heading, width - pad * 2).length * 14;
  const textY = y + pad + 18 + headingHeight;
  doc.text(bodyLines, x + pad, textY);

  if (showRainbow && (variant === "learning" || index === 2)) {
    drawRainbow(doc, x + width - 48, y + height - 18);
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

    // pair two half-width cards side by side
    const left = section;
    const right = sections[i + 1];
    const leftH = measureBlock(doc, left, half, 12) + 12;
    const rightH = measureBlock(doc, right, half, 12) + 12;
    const rowH = Math.max(leftH, rightH);
    if (y + rowH > pageHeight - bottomSafe) {
      doc.addPage();
      rgb(doc, design.pageBg, "fill");
      doc.rect(0, 0, pageWidth, pageHeight, "F");
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

  // Free photo layers above content; footer/QR stamped afterward so QR stays readable.
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
