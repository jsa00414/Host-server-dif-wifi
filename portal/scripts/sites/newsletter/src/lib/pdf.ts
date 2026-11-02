import { jsPDF } from "jspdf";
import QRCode from "qrcode";
import { getDesign, type NewsletterDesign } from "./designs";
import type { Newsletter, NewsletterSection, SiteConfig } from "./types";
import { slideshowUrl } from "./url";

type RGB = [number, number, number];

function formatIssueDate(issueDate: string) {
  return new Date(issueDate + "T12:00:00").toLocaleDateString("en-US", {
    weekday: "long",
    month: "long",
    day: "numeric",
    year: "numeric",
  });
}

function blockColors(design: NewsletterDesign, index: number): RGB {
  const palette = [
    design.colors.accent,
    design.colors.accent2,
    design.colors.accent3,
    design.colors.headerBg,
  ];
  return palette[index % palette.length];
}

function drawPageBackground(
  doc: jsPDF,
  design: NewsletterDesign,
  pageWidth: number,
  pageHeight: number,
) {
  const c = design.colors;
  doc.setFillColor(...c.pageBg);
  doc.rect(0, 0, pageWidth, pageHeight, "F");

  if (design.layout === "playful") {
    const dots: Array<[number, number, RGB]> = [
      [36, 40, c.accent],
      [90, 70, c.accent2],
      [160, 36, c.accent3],
      [pageWidth - 50, 55, c.accent],
      [pageWidth - 110, 28, c.accent2],
      [48, pageHeight - 120, c.accent3],
      [120, pageHeight - 90, c.accent],
    ];
    for (const [x, y, color] of dots) {
      doc.setFillColor(...color);
      doc.circle(x, y, 7, "F");
    }
  }

  if (design.layout === "stripes") {
    doc.setFillColor(...c.accent);
    doc.rect(0, 0, 18, pageHeight, "F");
    doc.setFillColor(...c.accent2);
    doc.rect(18, 0, 10, pageHeight, "F");
    doc.setFillColor(...c.accent3);
    doc.rect(28, 0, 6, pageHeight, "F");
  }

  if (design.layout === "sidebar") {
    doc.setFillColor(...c.headerBg2);
    doc.rect(0, 0, 120, pageHeight, "F");
    doc.setFillColor(...c.accent);
    doc.rect(120, 0, 10, pageHeight, "F");
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
  const c = design.colors;
  const contentWidth = pageWidth - margin * 2;

  if (design.layout === "sidebar") {
    doc.setTextColor(...c.onHeader);
    doc.setFont("helvetica", "bold");
    doc.setFontSize(11);
    doc.text(config.className, 24, 48, { maxWidth: 84 });
    doc.setFontSize(9);
    doc.setFont("helvetica", "normal");
    doc.text(config.grade, 24, 70, { maxWidth: 84 });
    doc.text(`Room ${config.room}`, 24, 86, { maxWidth: 84 });
    doc.text(config.teacherName, 24, 110, { maxWidth: 84 });

    doc.setFillColor(...c.headerBg);
    doc.roundedRect(150, 36, pageWidth - 174, 92, 14, 14, "F");
    doc.setTextColor(...c.text);
    doc.setFont("helvetica", "bold");
    doc.setFontSize(22);
    doc.text(newsletter.title, 168, 72, { maxWidth: pageWidth - 210 });
    doc.setFont("helvetica", "normal");
    doc.setFontSize(11);
    doc.setTextColor(...c.muted);
    doc.text(
      [newsletter.subtitle, formatIssueDate(newsletter.issueDate)]
        .filter(Boolean)
        .join("  ·  "),
      168,
      98,
      { maxWidth: pageWidth - 210 },
    );
    return 150;
  }

  if (design.layout === "wave" || design.layout === "ribbon") {
    doc.setFillColor(...c.headerBg);
    doc.rect(0, 0, pageWidth, 128, "F");
    doc.setFillColor(...c.headerBg2);
    doc.ellipse(pageWidth * 0.2, 128, pageWidth * 0.35, 28, "F");
    doc.setFillColor(...c.accent);
    doc.ellipse(pageWidth * 0.75, 128, pageWidth * 0.3, 22, "F");
  } else if (design.layout === "magazine") {
    doc.setFillColor(...c.headerBg);
    doc.rect(0, 0, pageWidth * 0.62, 130, "F");
    doc.setFillColor(...c.headerBg2);
    doc.rect(pageWidth * 0.62, 0, pageWidth * 0.38, 130, "F");
    doc.setFillColor(...c.accent);
    doc.rect(0, 130, pageWidth, 10, "F");
  } else if (design.layout === "cards") {
    doc.setFillColor(...c.headerBg);
    doc.rect(0, 0, pageWidth, 48, "F");
    doc.setFillColor(...c.accent);
    doc.rect(0, 48, pageWidth, 18, "F");
    doc.setFillColor(...c.headerBg2);
    doc.rect(0, 66, pageWidth, 48, "F");
  } else if (design.layout === "stripes") {
    doc.setFillColor(...c.headerBg);
    doc.roundedRect(margin, 28, contentWidth, 100, 12, 12, "F");
    doc.setFillColor(...c.accent);
    doc.roundedRect(margin, 116, contentWidth, 10, 4, 4, "F");
  } else if (design.layout === "grid") {
    doc.setFillColor(...c.headerBg);
    doc.roundedRect(margin, 28, contentWidth, 108, 16, 16, "F");
    doc.setFillColor(...c.accent2);
    doc.roundedRect(margin + 12, 40, 64, 84, 10, 10, "F");
  } else if (design.layout === "playful") {
    doc.setFillColor(...c.headerBg);
    doc.roundedRect(margin, 28, contentWidth, 108, 24, 24, "F");
    doc.setFillColor(...c.accent2);
    doc.circle(pageWidth - margin - 28, 48, 18, "F");
    doc.setFillColor(...c.accent);
    doc.circle(pageWidth - margin - 58, 86, 12, "F");
  } else if (design.layout === "blocks") {
    doc.setFillColor(...c.headerBg);
    doc.rect(0, 0, pageWidth, 118, "F");
    const band = contentWidth / 4;
    const colors = [c.accent, c.accent2, c.accent3, c.headerBg2];
    colors.forEach((color, i) => {
      doc.setFillColor(...color);
      doc.rect(margin + i * band, 118, band, 12, "F");
    });
  } else {
    // banner default
    doc.setFillColor(...c.headerBg);
    doc.rect(0, 0, pageWidth, 110, "F");
    doc.setFillColor(...c.accent);
    doc.rect(0, 110, pageWidth, 8, "F");
  }

  const textX =
    design.layout === "grid" ? margin + 92 : margin + (design.layout === "stripes" ? 16 : 0);
  const titleY =
    design.layout === "cards" ? 98 : design.layout === "grid" ? 78 : 64;
  const metaY = titleY + 26;

  doc.setTextColor(...c.onHeader);
  doc.setFont("helvetica", "bold");
  doc.setFontSize(11);
  const labelX = design.layout === "stripes" || design.layout === "grid" || design.layout === "playful"
    ? textX
    : margin;
  doc.text(`${config.className} · ${config.grade}`, labelX, design.layout === "cards" ? 30 : 36, {
    maxWidth: contentWidth - 40,
  });

  doc.setFontSize(22);
  doc.text(newsletter.title, labelX, titleY, {
    maxWidth: contentWidth - (design.layout === "grid" ? 100 : 24),
  });

  doc.setFont("helvetica", "normal");
  doc.setFontSize(11);
  const meta = [
    newsletter.subtitle,
    formatIssueDate(newsletter.issueDate),
    `Teacher: ${config.teacherName}`,
  ]
    .filter(Boolean)
    .join("  ·  ");
  doc.text(meta, labelX, metaY, {
    maxWidth: contentWidth - (design.layout === "grid" ? 100 : 24),
  });

  if (design.layout === "wave" || design.layout === "ribbon") return 168;
  if (design.layout === "magazine") return 160;
  if (design.layout === "cards") return 140;
  if (design.layout === "stripes" || design.layout === "grid" || design.layout === "playful")
    return 158;
  if (design.layout === "blocks") return 150;
  return 148;
}

function drawSection(
  doc: jsPDF,
  design: NewsletterDesign,
  section: NewsletterSection,
  index: number,
  x: number,
  y: number,
  width: number,
): number {
  const c = design.colors;
  const accent = blockColors(design, index);
  const pad = design.layout === "blocks" || design.layout === "cards" || design.layout === "grid" ? 14 : 0;
  const innerX = x + pad;
  const innerW = width - pad * 2;
  const bodyLines = doc.splitTextToSize(section.body || "", innerW);
  const headingHeight = 22;
  const bodyHeight = Math.max(bodyLines.length, 1) * 14;
  const blockHeight =
    headingHeight +
    bodyHeight +
    (pad ? 28 : 24) +
    (design.layout === "magazine" ? 8 : 0);

  if (design.layout === "blocks" || design.layout === "cards" || design.layout === "grid") {
    doc.setFillColor(...c.sectionBg);
    doc.roundedRect(x, y, width, blockHeight, 12, 12, "F");
    doc.setFillColor(...accent);
    doc.roundedRect(x, y, 8, blockHeight, 4, 4, "F");
  } else if (design.layout === "magazine") {
    doc.setFillColor(...accent);
    doc.rect(x, y, width, 4, "F");
  } else if (design.layout === "playful") {
    doc.setFillColor(...accent);
    doc.circle(x + 8, y + 8, 7, "F");
  } else {
    doc.setFillColor(...accent);
    doc.circle(x + 4, y + 4, 4, "F");
  }

  const textStart =
    design.layout === "blocks" || design.layout === "cards" || design.layout === "grid"
      ? innerX + 8
      : design.layout === "playful"
        ? x + 22
        : x + 16;

  doc.setFont("helvetica", "bold");
  doc.setFontSize(14);
  doc.setTextColor(...c.text);
  doc.text(section.heading || "Update", textStart, y + (pad ? 22 : 8), {
    maxWidth: innerW - 8,
  });

  doc.setFont("helvetica", "normal");
  doc.setFontSize(11);
  doc.setTextColor(...c.muted);
  doc.text(bodyLines, textStart, y + (pad ? 42 : headingHeight), {
    maxWidth: innerW - 8,
  });

  return blockHeight + (design.layout === "grid" ? 14 : 12);
}

async function stampQrAndFooter(
  doc: jsPDF,
  design: NewsletterDesign,
  newsletter: Newsletter,
  config: SiteConfig,
  request: Request | undefined,
  pageWidth: number,
  pageHeight: number,
  margin: number,
  contentLeft: number,
) {
  const qrSize = 72;
  const slideLink = slideshowUrl(newsletter.slideshowToken || "preview", request);
  const qrDataUrl = await QRCode.toDataURL(slideLink, {
    errorCorrectionLevel: "M",
    margin: 1,
    width: 240,
    color: {
      dark: design.colors.qrDark,
      light: design.colors.qrLight,
    },
  });

  const pageCount = doc.getNumberOfPages();
  for (let i = 1; i <= pageCount; i += 1) {
    doc.setPage(i);
    const qrX = pageWidth - margin - qrSize;
    const qrY = pageHeight - margin - qrSize - 12;

    doc.setFillColor(255, 255, 255);
    doc.roundedRect(qrX - 6, qrY - 6, qrSize + 12, qrSize + 28, 8, 8, "F");
    doc.setDrawColor(...design.colors.accent);
    doc.setLineWidth(1.5);
    doc.roundedRect(qrX - 6, qrY - 6, qrSize + 12, qrSize + 28, 8, 8, "S");
    doc.addImage(qrDataUrl, "PNG", qrX, qrY, qrSize, qrSize);

    doc.setFont("helvetica", "bold");
    doc.setFontSize(7);
    doc.setTextColor(...design.colors.muted);
    doc.text("Digital slideshow", qrX + qrSize / 2, qrY + qrSize + 12, {
      align: "center",
    });

    doc.setFont("helvetica", "normal");
    doc.setFontSize(9);
    doc.setTextColor(...design.colors.muted);
    doc.text(
      `${config.schoolName} · Room ${config.room} · ${getDesign(newsletter.designId).name}`,
      contentLeft,
      pageHeight - 28,
      { maxWidth: pageWidth - contentLeft - margin - qrSize - 24 },
    );
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
  const margin = design.layout === "stripes" ? 56 : 48;
  const contentLeft = design.layout === "sidebar" ? 150 : margin;
  const contentWidth = pageWidth - contentLeft - margin;
  const bottomSafe = 110;

  drawPageBackground(doc, design, pageWidth, pageHeight);
  let y = drawHeader(doc, design, newsletter, config, pageWidth, margin);

  const sections = newsletter.sections.filter(
    (s) => s.heading.trim() || s.body.trim(),
  );

  if (design.layout === "grid") {
    // 2-column organized cards
    let col = 0;
    let rowY = y;
    let rowMax = 0;
    const gap = 14;
    const colW = (contentWidth - gap) / 2;
    for (let i = 0; i < sections.length; i += 1) {
      const section = sections[i];
      const probe = doc.splitTextToSize(section.body || "", colW - 36);
      const est = 22 + Math.max(probe.length, 1) * 14 + 42;
      if (rowY + est > pageHeight - bottomSafe) {
        doc.addPage();
        drawPageBackground(doc, design, pageWidth, pageHeight);
        rowY = 56;
        col = 0;
        rowMax = 0;
      }
      const x = contentLeft + col * (colW + gap);
      const h = drawSection(doc, design, section, i, x, rowY, colW);
      rowMax = Math.max(rowMax, h);
      col += 1;
      if (col > 1) {
        rowY += rowMax;
        col = 0;
        rowMax = 0;
      }
    }
    if (col === 1) y = rowY + rowMax;
    else y = rowY;
  } else {
    for (let i = 0; i < sections.length; i += 1) {
      const section = sections[i];
      const probeWidth =
        design.layout === "blocks" || design.layout === "cards"
          ? contentWidth - 28
          : contentWidth - 16;
      const probe = doc.splitTextToSize(section.body || "", probeWidth);
      const est =
        22 +
        Math.max(probe.length, 1) * 14 +
        (design.layout === "blocks" || design.layout === "cards" ? 42 : 28);

      if (y + est > pageHeight - bottomSafe) {
        doc.addPage();
        drawPageBackground(doc, design, pageWidth, pageHeight);
        y = 56;
      }
      y += drawSection(doc, design, section, i, contentLeft, y, contentWidth);
    }
  }

  await stampQrAndFooter(
    doc,
    design,
    newsletter,
    config,
    request,
    pageWidth,
    pageHeight,
    margin,
    contentLeft,
  );

  const arrayBuffer = doc.output("arraybuffer");
  return new Uint8Array(arrayBuffer);
}
