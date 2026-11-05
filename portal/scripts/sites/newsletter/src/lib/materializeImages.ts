import { getUpload } from "./uploads";
import type { Newsletter, NewsletterLayer, NewsletterSection } from "./types";

async function toDataUrl(src: string): Promise<string> {
  const match = src.match(/\/api\/media\/([A-Za-z0-9_-]+)/);
  if (!match) return src;
  const upload = await getUpload(match[1]);
  if (!upload) return src;
  return `data:${upload.meta.mime};base64,${upload.bytes.toString("base64")}`;
}

/** Rewrite /api/media URLs to data URLs for server-side PDF generation. */
export async function materializeNewsletterImages(
  newsletter: Newsletter,
): Promise<Newsletter> {
  const layers: NewsletterLayer[] = await Promise.all(
    (newsletter.layers || []).map(async (layer) => {
      if (layer.type !== "image") return layer;
      return {
        ...layer,
        src: await toDataUrl(layer.src),
      };
    }),
  );
  const sections: NewsletterSection[] = await Promise.all(
    (newsletter.sections || []).map(async (section) => {
      if (!section.imageSrc) return section;
      return {
        ...section,
        imageSrc: await toDataUrl(section.imageSrc),
      };
    }),
  );
  return { ...newsletter, layers, sections };
}
