import { NextResponse } from "next/server";
import { randomBytes } from "crypto";
import {
  deleteNewsletter,
  getConfig,
  getNewsletter,
  saveNewsletter,
  savePdf,
} from "@/lib/storage";
import { DEFAULT_DESIGN_ID } from "@/lib/designs";
import { normalizePageBackground } from "@/lib/backgrounds";
import { normalizeLayers } from "@/lib/layers";
import { materializeNewsletterImages } from "@/lib/materializeImages";
import { buildNewsletterPdf } from "@/lib/pdf";
import { normalizeSections } from "@/lib/sections";

type Params = { params: Promise<{ id: string }> };

export async function GET(_request: Request, { params }: Params) {
  const { id } = await params;
  const newsletter = await getNewsletter(id);
  if (!newsletter) {
    return NextResponse.json({ error: "Not found" }, { status: 404 });
  }
  return NextResponse.json({ newsletter });
}

export async function PUT(request: Request, { params }: Params) {
  const { id } = await params;
  const existing = await getNewsletter(id);
  const config = await getConfig();
  if (!existing || !config) {
    return NextResponse.json({ error: "Not found" }, { status: 404 });
  }

  const body = await request.json();
  const title = String(body.title || "").trim();
  if (!title) {
    return NextResponse.json({ error: "Title is required." }, { status: 400 });
  }

  // Always use the clean classroom design (legacy AI packs removed).
  const designId = DEFAULT_DESIGN_ID;

  const newsletter = {
    ...existing,
    title,
    subtitle: String(body.subtitle || "").trim(),
    bannerLabel: String(
      body.bannerLabel !== undefined ? body.bannerLabel : existing.bannerLabel || "",
    ).trim(),
    footerNote: String(
      body.footerNote !== undefined ? body.footerNote : existing.footerNote || "",
    ).trim(),
    issueDate: String(body.issueDate || existing.issueDate),
    sections: Array.isArray(body.sections)
      ? normalizeSections(body.sections)
      : existing.sections,
    layers: Array.isArray(body.layers)
      ? normalizeLayers(body.layers)
      : existing.layers || [],
    pageBackground:
      body.pageBackground !== undefined
        ? normalizePageBackground(body.pageBackground)
        : existing.pageBackground,
    designId,
    slideshowToken:
      existing.slideshowToken || randomBytes(18).toString("base64url"),
    published: Boolean(body.published),
    updatedAt: new Date().toISOString(),
  };

  await saveNewsletter(newsletter);
  const forPdf = await materializeNewsletterImages(newsletter);
  const pdf = await buildNewsletterPdf(forPdf, config, request);
  await savePdf(newsletter.id, pdf);

  return NextResponse.json({ id: newsletter.id, newsletter });
}

export async function DELETE(_request: Request, { params }: Params) {
  const { id } = await params;
  await deleteNewsletter(id);
  return NextResponse.json({ ok: true });
}
