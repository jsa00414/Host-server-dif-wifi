import path from "path";

export const DATA_DIR = path.join(/*turbopackIgnore: true*/ process.cwd(), "data");
export const CONFIG_PATH = path.join(DATA_DIR, "config.json");
export const NEWSLETTERS_DIR = path.join(DATA_DIR, "newsletters");
export const PDF_DIR = path.join(DATA_DIR, "pdfs");
export const UPLOADS_DIR = path.join(DATA_DIR, "uploads");
export const UPLOADS_META = path.join(UPLOADS_DIR, "index.json");
