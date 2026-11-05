import { NextResponse } from "next/server";
import { randomBytes } from "crypto";
import {
  getConfig,
  getNewsletter,
  readPdf,
  saveNewsletter,
  savePdf,
} from "@/lib/storage";
import { materializeNewsletterImages } from "@/lib/materializeImages";
import { buildNewsletterPdf } from "@/lib/pdf";

type Params = { params: Promise<{ id: string }> };

export async function GET(request: Request, { params }: Params) {
  const { id } = await params;
  let newsletter = await getNewsletter(id);
  const config = await getConfig();
  if (!newsletter || !config || !newsletter.published) {
    return NextResponse.json({ error: "Not found" }, { status: 404 });
  }

  if (!newsletter.slideshowToken) {
    newsletter = {
      ...newsletter,
      slideshowToken: randomBytes(18).toString("base64url"),
    };
    await saveNewsletter(newsletter);
  }

  const forPdf = await materializeNewsletterImages(newsletter);
  const bytes = await buildNewsletterPdf(forPdf, config, request);
  await savePdf(id, bytes);
  const pdf = await readPdf(id);

  return new NextResponse(new Uint8Array(pdf || bytes), {
    headers: {
      "Content-Type": "application/pdf",
      "Content-Disposition": `inline; filename="${newsletter.title.replace(/[^\w\-]+/g, "_")}.pdf"`,
    },
  });
}
