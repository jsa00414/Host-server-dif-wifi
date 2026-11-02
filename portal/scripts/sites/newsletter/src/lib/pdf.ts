import { jsPDF } from "jspdf";
import QRCode from "qrcode";
import type { Newsletter, SiteConfig } from "./types";
import { slideshowUrl } from "./url";

export async function buildNewsletterPdf(
  newsletter: Newsletter,
  config: SiteConfig,
  request?: Request,
): Promise<Uint8Array> {
  const doc = new jsPDF({ unit: "pt", format: "letter" });
  const pageWidth = doc.internal.pageSize.getWidth();
  const pageHeight = doc.internal.pageSize.getHeight();
  const margin = 48;
  const contentWidth = pageWidth - margin * 2;
  const qrSize = 72;
  const bottomSafe = 100;
  let y = 56;

  doc.setFillColor(75, 163, 195);
  doc.rect(0, 0, pageWidth, 110, "F");
  doc.setFillColor(245, 215, 110);
  doc.rect(0, 110, pageWidth, 8, "F");

  doc.setTextColor(255, 255, 255);
  doc.setFont("helvetica", "bold");
  doc.setFontSize(11);
  doc.text(`${config.className} · ${config.grade}`, margin, 36);

  doc.setFontSize(22);
  doc.text(newsletter.title, margin, 64, { maxWidth: contentWidth });

  doc.setFont("helvetica", "normal");
  doc.setFontSize(11);
  const meta = [
    newsletter.subtitle,
    new Date(newsletter.issueDate + "T12:00:00").toLocaleDateString("en-US", {
      weekday: "long",
      month: "long",
      day: "numeric",
      year: "numeric",
    }),
    `Teacher: ${config.teacherName}`,
  ]
    .filter(Boolean)
    .join("  ·  ");
  doc.text(meta, margin, 88, { maxWidth: contentWidth });

  y = 148;
  doc.setTextColor(30, 58, 95);

  for (const section of newsletter.sections) {
    if (!section.heading.trim() && !section.body.trim()) continue;

    const headingHeight = 22;
    const bodyLines = doc.splitTextToSize(section.body || "", contentWidth);
    const bodyHeight = bodyLines.length * 14;
    const blockHeight = headingHeight + bodyHeight + 28;

    if (y + blockHeight > pageHeight - bottomSafe) {
      doc.addPage();
      y = 56;
    }

    doc.setFillColor(93, 174, 139);
    doc.circle(margin + 4, y + 4, 4, "F");

    doc.setFont("helvetica", "bold");
    doc.setFontSize(14);
    doc.setTextColor(30, 58, 95);
    doc.text(section.heading || "Update", margin + 16, y + 8);

    y += headingHeight;
    doc.setFont("helvetica", "normal");
    doc.setFontSize(11);
    doc.setTextColor(45, 62, 80);
    doc.text(bodyLines, margin, y);
    y += bodyHeight + 24;
  }

  // QR on every page, bottom-right — opens hidden digital slideshow
  const slideLink = slideshowUrl(newsletter.slideshowToken, request);
  const qrDataUrl = await QRCode.toDataURL(slideLink, {
    errorCorrectionLevel: "M",
    margin: 1,
    width: 240,
    color: { dark: "#1E3A5F", light: "#FFFFFF" },
  });

  const pageCount = doc.getNumberOfPages();
  for (let i = 1; i <= pageCount; i += 1) {
    doc.setPage(i);
    const qrX = pageWidth - margin - qrSize;
    const qrY = pageHeight - margin - qrSize - 12;

    doc.setFillColor(255, 255, 255);
    doc.roundedRect(qrX - 6, qrY - 6, qrSize + 12, qrSize + 28, 6, 6, "F");
    doc.addImage(qrDataUrl, "PNG", qrX, qrY, qrSize, qrSize);

    doc.setFont("helvetica", "normal");
    doc.setFontSize(7);
    doc.setTextColor(120, 140, 160);
    doc.text("Digital slideshow", qrX + qrSize / 2, qrY + qrSize + 12, {
      align: "center",
    });

    doc.setFontSize(9);
    doc.text(
      `${config.schoolName} · Room ${config.room} · Family newsletter`,
      margin,
      pageHeight - 28,
      { maxWidth: pageWidth - margin * 2 - qrSize - 24 },
    );
  }

  const arrayBuffer = doc.output("arraybuffer");
  return new Uint8Array(arrayBuffer);
}
