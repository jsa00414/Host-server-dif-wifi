import type {
  ImageLayer,
  NewsletterLayer,
  ShapeKind,
  ShapeLayer,
} from "./types";

function newId() {
  if (typeof crypto !== "undefined" && "randomUUID" in crypto) {
    return crypto.randomUUID();
  }
  return `layer-${Date.now()}-${Math.random().toString(36).slice(2, 8)}`;
}

const SHAPES = new Set<ShapeKind>([
  "rect",
  "rounded",
  "circle",
  "ellipse",
  "triangle",
  "star",
  "heart",
  "line",
]);

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

function asHex(value: unknown, fallback: string) {
  const s = String(value || "").trim();
  if (/^#([0-9a-f]{3}|[0-9a-f]{6})$/i.test(s)) return s;
  return fallback;
}

function baseFrom(l: Partial<NewsletterLayer>, index: number) {
  return {
    id: l.id || newId(),
    name: String(l.name || `Layer ${index + 1}`).trim() || `Layer ${index + 1}`,
    x: clampNum(l.x, 8, 0, 90),
    y: clampNum(l.y, 20, 0, 90),
    width: clampNum(l.width, 28, 4, 100),
    height: clampNum(l.height, 22, 2, 100),
    rotation: clampNum(l.rotation, 0, -180, 180),
    opacity: clampNum(l.opacity, 1, 0.1, 1),
    zIndex: Number.isFinite(Number(l.zIndex)) ? Number(l.zIndex) : index + 1,
  };
}

export function normalizeLayers(raw: unknown): NewsletterLayer[] {
  if (!Array.isArray(raw)) return [];
  return raw
    .map((item, index) => {
      const l = (item || {}) as Partial<NewsletterLayer> & {
        shape?: string;
        fill?: string;
        stroke?: string;
        strokeWidth?: number;
        src?: string;
      };
      const type = l.type === "shape" ? "shape" : "image";
      if (type === "shape") {
        const shape = (
          SHAPES.has(l.shape as ShapeKind) ? l.shape : "rounded"
        ) as ShapeKind;
        const layer: ShapeLayer = {
          ...baseFrom(l, index),
          type: "shape",
          shape,
          name:
            String(l.name || shapeLabel(shape)).trim() || shapeLabel(shape),
          fill: asHex(l.fill, "#4DABF7"),
          stroke: asHex(l.stroke, "#212529"),
          strokeWidth: clampNum(l.strokeWidth, shape === "line" ? 4 : 0, 0, 12),
          width: clampNum(l.width, shape === "line" ? 36 : 22, 4, 100),
          height: clampNum(l.height, shape === "line" ? 3 : 18, 2, 100),
        };
        return layer;
      }
      const src = String(l.src || "").trim();
      if (!src) return null;
      const layer: ImageLayer = {
        ...baseFrom(l, index),
        type: "image",
        name:
          String(l.name || `Photo ${index + 1}`).trim() || `Photo ${index + 1}`,
        src,
      };
      return layer;
    })
    .filter(Boolean) as NewsletterLayer[];
}

export function shapeLabel(shape: ShapeKind) {
  switch (shape) {
    case "rect":
      return "Rectangle";
    case "rounded":
      return "Rounded";
    case "circle":
      return "Circle";
    case "ellipse":
      return "Oval";
    case "triangle":
      return "Triangle";
    case "star":
      return "Star";
    case "heart":
      return "Heart";
    case "line":
      return "Line";
    default:
      return "Shape";
  }
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
  else if (action === "forward")
    copy.splice(Math.min(copy.length, index + 1), 0, item);
  else copy.splice(Math.max(0, index - 1), 0, item);

  return copy.map((layer, i) => ({ ...layer, zIndex: i + 1 }));
}

export function createShapeLayer(
  shape: ShapeKind,
  layers: NewsletterLayer[],
  fill = "#4DABF7",
): ShapeLayer {
  const count = layers.filter((l) => l.type === "shape").length;
  return {
    id: newId(),
    type: "shape",
    shape,
    name: shapeLabel(shape),
    fill,
    stroke: "#212529",
    strokeWidth: shape === "line" ? 5 : 0,
    x: 14 + (count % 4) * 7,
    y: 30 + (count % 3) * 9,
    width: shape === "line" ? 40 : shape === "circle" || shape === "star" ? 18 : 24,
    height: shape === "line" ? 3 : shape === "circle" || shape === "star" ? 14 : 18,
    rotation: 0,
    opacity: 1,
    zIndex: nextZIndex(layers),
  };
}
