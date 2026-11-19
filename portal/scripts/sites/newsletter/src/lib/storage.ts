import { promises as fs } from "fs";
import path from "path";
import { CONFIG_PATH, DATA_DIR, NEWSLETTERS_DIR, PDF_DIR } from "./paths";
import type { Newsletter, SiteConfig } from "./types";

async function ensureDirs() {
  await fs.mkdir(DATA_DIR, { recursive: true });
  await fs.mkdir(NEWSLETTERS_DIR, { recursive: true });
  await fs.mkdir(PDF_DIR, { recursive: true });
}

export async function getConfig(): Promise<SiteConfig | null> {
  try {
    await ensureDirs();
    const raw = await fs.readFile(CONFIG_PATH, "utf8");
    return JSON.parse(raw) as SiteConfig;
  } catch {
    return null;
  }
}

export async function saveConfig(config: SiteConfig): Promise<void> {
  await ensureDirs();
  await fs.writeFile(CONFIG_PATH, JSON.stringify(config, null, 2), "utf8");
}

export async function listNewsletters(): Promise<Newsletter[]> {
  await ensureDirs();
  const files = await fs.readdir(NEWSLETTERS_DIR);
  const items: Newsletter[] = [];
  for (const file of files) {
    if (!file.endsWith(".json")) continue;
    const raw = await fs.readFile(path.join(NEWSLETTERS_DIR, file), "utf8");
    items.push(JSON.parse(raw) as Newsletter);
  }
  return items.sort((a, b) => b.issueDate.localeCompare(a.issueDate));
}

export async function getNewsletter(id: string): Promise<Newsletter | null> {
  try {
    const raw = await fs.readFile(
      path.join(NEWSLETTERS_DIR, `${id}.json`),
      "utf8",
    );
    return JSON.parse(raw) as Newsletter;
  } catch {
    return null;
  }
}

export async function getNewsletterBySlideshowToken(
  token: string,
): Promise<Newsletter | null> {
  if (!token) return null;
  const items = await listNewsletters();
  return items.find((n) => n.slideshowToken === token) || null;
}

export async function saveNewsletter(newsletter: Newsletter): Promise<void> {
  await ensureDirs();
  await fs.writeFile(
    path.join(NEWSLETTERS_DIR, `${newsletter.id}.json`),
    JSON.stringify(newsletter, null, 2),
    "utf8",
  );
}

export async function deleteNewsletter(id: string): Promise<void> {
  try {
    await fs.unlink(path.join(NEWSLETTERS_DIR, `${id}.json`));
  } catch {
    /* ignore */
  }
  try {
    await fs.unlink(path.join(PDF_DIR, `${id}.pdf`));
  } catch {
    /* ignore */
  }
}

export async function savePdf(id: string, bytes: Uint8Array): Promise<string> {
  await ensureDirs();
  const filePath = path.join(PDF_DIR, `${id}.pdf`);
  await fs.writeFile(filePath, bytes);
  return filePath;
}

export async function readPdf(id: string): Promise<Buffer | null> {
  try {
    return await fs.readFile(path.join(PDF_DIR, `${id}.pdf`));
  } catch {
    return null;
  }
}
