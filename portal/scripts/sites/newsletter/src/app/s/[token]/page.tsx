export const dynamic = "force-dynamic";

import { notFound } from "next/navigation";
import {
  getConfig,
  getNewsletterBySlideshowToken,
} from "@/lib/storage";
import { Slideshow } from "./Slideshow";

type Props = { params: Promise<{ token: string }> };

export default async function HiddenSlideshowPage({ params }: Props) {
  const { token } = await params;
  const [newsletter, config] = await Promise.all([
    getNewsletterBySlideshowToken(token),
    getConfig(),
  ]);

  // Secret token is the gate — drafts still open from the PDF corner QR.
  if (!newsletter || !config) {
    notFound();
  }

  return (
    <Slideshow
      className={config.className}
      teacherName={config.teacherName}
      schoolName={config.schoolName}
      newsletter={{
        title: newsletter.title,
        subtitle: newsletter.subtitle,
        issueDate: newsletter.issueDate,
        sections: newsletter.sections.map((s) => ({
          heading: s.heading,
          body: s.body,
        })),
      }}
    />
  );
}
