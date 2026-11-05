import { NextResponse } from "next/server";
import { getUpload } from "@/lib/uploads";

type Params = { params: Promise<{ id: string }> };

export async function GET(_request: Request, { params }: Params) {
  const { id } = await params;
  if (!id || id.includes("..") || id.includes("/")) {
    return NextResponse.json({ error: "Not found" }, { status: 404 });
  }
  const upload = await getUpload(id);
  if (!upload) {
    return NextResponse.json({ error: "Not found" }, { status: 404 });
  }
  return new NextResponse(new Uint8Array(upload.bytes), {
    headers: {
      "Content-Type": upload.meta.mime,
      "Cache-Control": "public, max-age=31536000, immutable",
    },
  });
}
