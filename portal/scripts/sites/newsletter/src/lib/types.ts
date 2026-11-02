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

export type NewsletterSection = {
  id: string;
  heading: string;
  body: string;
};

export type Newsletter = {
  id: string;
  title: string;
  issueDate: string;
  subtitle: string;
  sections: NewsletterSection[];
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
