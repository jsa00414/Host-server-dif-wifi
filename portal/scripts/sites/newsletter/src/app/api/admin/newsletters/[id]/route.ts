import { NextResponse } from "next/server";
import { randomBytes } from "crypto";
import {
  deleteNewsletter,
  getConfig,
  getNewsletter,
  saveNewsletter,
  savePdf,
} from "@/lib/storage";
import { DEFAULT_DESIGN_ID, isDesignId } from "@/lib/designs";
import { buildNewsletterPdf } from "@/lib/pdf";
import type { NewsletterSection } from "@/lib/types";

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

  const sections: NewsletterSection[] = Array.isArray(body.sections)
    ? body.sections.map((s: NewsletterSection) => ({
        id: s.id,
        heading: String(s.heading || "").trim(),
        body: String(s.body || "").trim(),
      }))
    : existing.sections;

  const designId =
    typeof body.designId === "string" && isDesignId(body.designId)
      ? body.designId
      : existing.designId || DEFAULT_DESIGN_ID;

  const newsletter = {
    ...existing,
    title,
    subtitle: String(body.subtitle || "").trim(),
    issueDate: String(body.issueDate || existing.issueDate),
    sections,
    designId,
    slideshowToken:
      existing.slideshowToken || randomBytes(18).toString("base64url"),
    published: Boolean(body.published),
    updatedAt: new Date().toISOString(),
  };

  await saveNewsletter(newsletter);
  const pdf = await buildNewsletterPdf(newsletter, config, request);
  await savePdf(newsletter.id, pdf);

  return NextResponse.json({ id: newsletter.id, newsletter });
}

export async function DELETE(_request: Request, { params }: Params) {
  const { id } = await params;
  await deleteNewsletter(id);
  return NextResponse.json({ ok: true });
}
