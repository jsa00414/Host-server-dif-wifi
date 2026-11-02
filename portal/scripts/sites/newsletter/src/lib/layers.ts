import type { NewsletterLayer } from "./types";

function newId() {
  if (typeof crypto !== "undefined" && "randomUUID" in crypto) {
    return crypto.randomUUID();
  }
  return `layer-${Date.now()}-${Math.random().toString(36).slice(2, 8)}`;
}

export function normalizeLayers(raw: unknown): NewsletterLayer[] {
  if (!Array.isArray(raw)) return [];
  return raw
    .map((item, index) => {
      const l = (item || {}) as Partial<NewsletterLayer>;
      const src = String(l.src || "").trim();
      if (!src) return null;
      return {
        id: l.id || newId(),
        type: "image" as const,
        name: String(l.name || `Photo ${index + 1}`).trim() || `Photo ${index + 1}`,
        src,
        x: clampNum(l.x, 8, 0, 90),
        y: clampNum(l.y, 20, 0, 90),
        width: clampNum(l.width, 28, 8, 100),
        height: clampNum(l.height, 22, 8, 100),
        rotation: clampNum(l.rotation, 0, -180, 180),
        opacity: clampNum(l.opacity, 1, 0.1, 1),
        zIndex: Number.isFinite(Number(l.zIndex)) ? Number(l.zIndex) : index + 1,
      };
    })
    .filter(Boolean) as NewsletterLayer[];
}

function clampNum(
  value: unknown,
  fallback: number,
  min: number,
  max: number,
) {
  const n = Number(value);
  if (!Number.isFinite(n)) return fallback;
  return Math.min(max, Math.max(min, n));
}

export function sortLayers(layers: NewsletterLayer[]) {
  return [...layers].sort((a, b) => a.zIndex - b.zIndex);
}

export function nextZIndex(layers: NewsletterLayer[]) {
  if (!layers.length) return 1;
  return Math.max(...layers.map((l) => l.zIndex)) + 1;
}

export function reorderLayer(
  layers: NewsletterLayer[],
  id: string,
  action: "front" | "back" | "forward" | "backward",
): NewsletterLayer[] {
  const sorted = sortLayers(layers);
  const index = sorted.findIndex((l) => l.id === id);
  if (index < 0) return layers;

  const copy = [...sorted];
  const [item] = copy.splice(index, 1);
  if (action === "front") copy.push(item);
  else if (action === "back") copy.unshift(item);
  else if (action === "forward") copy.splice(Math.min(copy.length, index + 1), 0, item);
  else copy.splice(Math.max(0, index - 1), 0, item);

  return copy.map((layer, i) => ({ ...layer, zIndex: i + 1 }));
}
