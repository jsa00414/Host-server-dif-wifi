export type PdfImage = {
  dataUrl: string;
  format: "JPEG" | "PNG" | "WEBP";
};

function formatFromMime(mime: string): PdfImage["format"] {
  if (mime.includes("png")) return "PNG";
  if (mime.includes("webp")) return "WEBP";
  return "JPEG";
}

function formatFromDataUrl(dataUrl: string): PdfImage["format"] {
  if (dataUrl.startsWith("data:image/png")) return "PNG";
  if (dataUrl.startsWith("data:image/webp")) return "WEBP";
  return "JPEG";
}

function bytesToBase64(bytes: Uint8Array): string {
  if (typeof Buffer !== "undefined") {
    return Buffer.from(bytes).toString("base64");
  }
  let binary = "";
  const chunk = 0x8000;
  for (let i = 0; i < bytes.length; i += chunk) {
    binary += String.fromCharCode(...bytes.subarray(i, i + chunk));
  }
  return btoa(binary);
}

function absoluteUrl(src: string, baseUrl?: string): string {
  if (/^https?:\/\//i.test(src) || src.startsWith("data:")) return src;
  if (src.startsWith("/")) {
    if (baseUrl) return `${baseUrl.replace(/\/$/, "")}${src}`;
    if (typeof window !== "undefined") return `${window.location.origin}${src}`;
  }
  return src;
}

/**
 * Resolve a media URL or data URL into a jsPDF-compatible data URL.
 * Keep this module browser-safe (no fs / uploads imports) so the editor
 * can build live PDF previews.
 */
export async function resolvePdfImage(
  src: string,
  baseUrl?: string,
): Promise<PdfImage | null> {
  if (!src) return null;

  if (src.startsWith("data:image/")) {
    return { dataUrl: src, format: formatFromDataUrl(src) };
  }

  try {
    const absolute = absoluteUrl(src, baseUrl);
    const res = await fetch(absolute);
    if (!res.ok) return null;
    const mime = res.headers.get("content-type") || "image/jpeg";
    const bytes = new Uint8Array(await res.arrayBuffer());
    const dataUrl = `data:${mime};base64,${bytesToBase64(bytes)}`;
    return { dataUrl, format: formatFromMime(mime) };
  } catch {
    return null;
  }
}
