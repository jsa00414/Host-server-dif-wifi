import { NextResponse } from "next/server";
import { randomBytes } from "crypto";
import {
  getConfig,
  getNewsletter,
  readPdf,
  saveNewsletter,
  savePdf,
} from "@/lib/storage";
import { buildNewsletterPdf } from "@/lib/pdf";

type Params = { params: Promise<{ id: string }> };

export async function GET(request: Request, { params }: Params) {
  const { id } = await params;
  let newsletter = await getNewsletter(id);
  const config = await getConfig();
  if (!newsletter || !config) {
    return NextResponse.json({ error: "Not found" }, { status: 404 });
  }

  if (!newsletter.slideshowToken) {
    newsletter = {
      ...newsletter,
      slideshowToken: randomBytes(18).toString("base64url"),
    };
    await saveNewsletter(newsletter);
  }

  // Always rebuild so QR points at current host/token
  const bytes = await buildNewsletterPdf(newsletter, config, request);
  await savePdf(id, bytes);
  const pdf = await readPdf(id);

  return new NextResponse(new Uint8Array(pdf || bytes), {
    headers: {
      "Content-Type": "application/pdf",
      "Content-Disposition": `attachment; filename="${newsletter.title.replace(/[^\w\-]+/g, "_")}.pdf"`,
    },
  });
}
