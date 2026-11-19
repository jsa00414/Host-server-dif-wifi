export type SiteConfig = {
  className: string;
  teacherName: string;
  schoolName: string;
  grade: string;
  room: string;
  welcomeMessage: string;
  setupComplete: boolean;
  adminPasswordHash: string;
  adminTotpSecret: string;
  viewerTotpSecret: string;
  createdAt: string;
};

export type SectionTone =
  | "green"
  | "blue"
  | "pink"
  | "orange"
  | "yellow"
  | "lavender"
  | "coral"
  | "mint";

export type SectionVariant = "banner" | "card" | "list" | "learning";

export type SectionWidth = "full" | "half";

export type NewsletterSection = {
  id: string;
  heading: string;
  body: string;
  /** Visual role in the classroom-style layout */
  variant?: SectionVariant;
  /** Pastel block color */
  tone?: SectionTone;
  /**
   * Legacy flow hint (full/half). Free-canvas editors still use this when
   * assigning default frames for older newsletters.
   */
  width?: SectionWidth;
  /** Free-canvas X position as percent of letter page (0–100) */
  x?: number;
  /** Free-canvas Y position as percent of letter page (0–100) */
  y?: number;
  /** Free-canvas box width as percent of letter page (0–100) */
  boxW?: number;
  /** Free-canvas box height as percent of letter page (0–100) */
  boxH?: number;
  /** Stacking order (shared space with photo/shape layers) */
  zIndex?: number;
  /** Optional photo inside the block (media URL or data URL) */
  imageSrc?: string;
};

export type ShapeKind =
  | "rect"
  | "rounded"
  | "circle"
  | "ellipse"
  | "triangle"
  | "star"
  | "heart"
  | "line";

type LayerBase = {
  id: string;
  name: string;
  /** Position/size as percent of letter page (0–100) */
  x: number;
  y: number;
  width: number;
  height: number;
  rotation: number;
  opacity: number;
  /** Higher draws on top */
  zIndex: number;
};

export type ImageLayer = LayerBase & {
  type: "image";
  /** /api/media/<id> or data URL */
  src: string;
};

export type ShapeLayer = LayerBase & {
  type: "shape";
  shape: ShapeKind;
  /** Fill color hex */
  fill: string;
  /** Stroke color hex */
  stroke: string;
  strokeWidth: number;
};

/** Free-positioned canvas layer (photos or shapes), Canva-style. */
export type NewsletterLayer = ImageLayer | ShapeLayer;

/** Optional page background override (falls back to design defaults). */
export type PageBackground = {
  /** Solid page color hex, e.g. #FFF8F0 */
  color?: string;
  /** Pattern id from PAGE_BACKGROUNDS */
  pattern?: string;
};

export type Newsletter = {
  id: string;
  title: string;
  issueDate: string;
  subtitle: string;
  /** Green bar label under the title, e.g. AUGUST CLASS NEWS */
  bannerLabel?: string;
  /** Footer contact line under the green bar */
  footerNote?: string;
  sections: NewsletterSection[];
  /** Photo / shape layers with stacking order */
  layers?: NewsletterLayer[];
  /** Optional background override on top of the template */
  pageBackground?: PageBackground;
  /** Premade colorful PDF design id from NEWSLETTER_DESIGNS. */
  designId: string;
  /** Secret token for the hidden digital slideshow (QR on PDF). */
  slideshowToken: string;
  createdAt: string;
  updatedAt: string;
  published: boolean;
};

export type SessionPayload = {
  role: "viewer" | "admin";
  exp: number;
};
