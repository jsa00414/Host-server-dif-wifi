import { NextResponse } from "next/server";
import { mediaUrl, saveUpload } from "@/lib/uploads";

export async function POST(request: Request) {
  try {
    const form = await request.formData();
    const file = form.get("file");
    if (!(file instanceof File)) {
      return NextResponse.json({ error: "Missing file." }, { status: 400 });
    }
    const bytes = Buffer.from(await file.arrayBuffer());
    const meta = await saveUpload({
      bytes,
      mime: file.type || "application/octet-stream",
      filename: file.name || "photo",
    });
    return NextResponse.json({
      ok: true,
      id: meta.id,
      url: mediaUrl(meta.id),
      filename: meta.filename,
      mime: meta.mime,
    });
  } catch (err) {
    return NextResponse.json(
      { error: err instanceof Error ? err.message : "Upload failed." },
      { status: 400 },
    );
  }
}
