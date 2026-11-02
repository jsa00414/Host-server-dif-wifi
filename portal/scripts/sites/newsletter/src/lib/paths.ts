import path from "path";

export const DATA_DIR = path.join(process.cwd(), "data");
export const CONFIG_PATH = path.join(DATA_DIR, "config.json");
export const NEWSLETTERS_DIR = path.join(DATA_DIR, "newsletters");
export const PDF_DIR = path.join(DATA_DIR, "pdfs");
