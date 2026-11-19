import { promises as fs } from "fs";
import path from "path";
import { randomUUID } from "crypto";
import { UPLOADS_DIR, UPLOADS_META } from "./paths";

export type UploadMeta = {
  id: string;
  filename: string;
  mime: string;
  ext: string;
  createdAt: string;
};

async function ensureUploads() {
  await fs.mkdir(UPLOADS_DIR, { recursive: true });
}

async function readIndex(): Promise<UploadMeta[]> {
  try {
    const raw = await fs.readFile(UPLOADS_META, "utf8");
    return JSON.parse(raw) as UploadMeta[];
  } catch {
    return [];
  }
}

async function writeIndex(items: UploadMeta[]) {
  await ensureUploads();
  await fs.writeFile(UPLOADS_META, JSON.stringify(items, null, 2), "utf8");
}

const ALLOWED: Record<string, string> = {
  "image/jpeg": "jpg",
  "image/jpg": "jpg",
  "image/png": "png",
  "image/webp": "webp",
  "image/gif": "gif",
};

export function mediaUrl(id: string) {
  return `/api/media/${id}`;
}

export async function saveUpload(file: {
  bytes: Buffer;
  mime: string;
  filename: string;
}): Promise<UploadMeta> {
  const ext = ALLOWED[file.mime];
  if (!ext) {
    throw new Error("Only JPG, PNG, WEBP, or GIF images are allowed.");
  }
  if (file.bytes.length > 8 * 1024 * 1024) {
    throw new Error("Image must be under 8MB.");
  }
  await ensureUploads();
  const id = randomUUID();
  const meta: UploadMeta = {
    id,
    filename: file.filename || `photo.${ext}`,
    mime: file.mime,
    ext,
    createdAt: new Date().toISOString(),
  };
  await fs.writeFile(path.join(UPLOADS_DIR, `${id}.${ext}`), file.bytes);
  const index = await readIndex();
  index.unshift(meta);
  await writeIndex(index.slice(0, 500));
  return meta;
}

export async function getUpload(
  id: string,
): Promise<{ meta: UploadMeta; bytes: Buffer } | null> {
  const index = await readIndex();
  const meta = index.find((m) => m.id === id);
  if (!meta) return null;
  try {
    const bytes = await fs.readFile(
      path.join(UPLOADS_DIR, `${meta.id}.${meta.ext}`),
    );
    return { meta, bytes };
  } catch {
    return null;
  }
}
