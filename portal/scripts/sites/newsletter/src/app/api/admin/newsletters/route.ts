import { NextResponse } from "next/server";
import { randomBytes, randomUUID } from "crypto";
import {
  getConfig,
  listNewsletters,
  saveNewsletter,
  savePdf,
} from "@/lib/storage";
import { buildNewsletterPdf } from "@/lib/pdf";
import { DEFAULT_DESIGN_ID, isDesignId } from "@/lib/designs";
import { normalizeSections } from "@/lib/sections";
import type { Newsletter } from "@/lib/types";

function slideshowToken() {
  return randomBytes(18).toString("base64url");
}

export async function GET() {
  const items = await listNewsletters();
  return NextResponse.json({ newsletters: items });
}

export async function POST(request: Request) {
  const config = await getConfig();
  if (!config) {
    return NextResponse.json({ error: "Not configured" }, { status: 400 });
  }

  const body = await request.json();
  const title = String(body.title || "").trim();
  if (!title) {
    return NextResponse.json({ error: "Title is required." }, { status: 400 });
  }

  const now = new Date().toISOString();
  const designId =
    typeof body.designId === "string" && isDesignId(body.designId)
      ? body.designId
      : DEFAULT_DESIGN_ID;

  const newsletter: Newsletter = {
    id: randomUUID(),
    title,
    subtitle: String(body.subtitle || "").trim(),
    bannerLabel: String(body.bannerLabel || "").trim(),
    footerNote: String(body.footerNote || "").trim(),
    issueDate: String(body.issueDate || now.slice(0, 10)),
    sections: normalizeSections(body.sections),
    designId,
    slideshowToken: slideshowToken(),
    published: body.published === undefined ? true : Boolean(body.published),
    createdAt: now,
    updatedAt: now,
  };

  await saveNewsletter(newsletter);
  const pdf = await buildNewsletterPdf(newsletter, config, request);
  await savePdf(newsletter.id, pdf);

  return NextResponse.json({ id: newsletter.id, newsletter });
}
