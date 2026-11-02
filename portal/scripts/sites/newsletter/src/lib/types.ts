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
  /** full-width banner/row or half-width column card */
  width?: SectionWidth;
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
