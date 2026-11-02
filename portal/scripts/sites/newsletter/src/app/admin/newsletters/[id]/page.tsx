export const dynamic = "force-dynamic";

import { notFound, redirect } from "next/navigation";
import { NewsletterEditor } from "@/components/NewsletterEditor";
import { getConfig, getNewsletter } from "@/lib/storage";

type Props = { params: Promise<{ id: string }> };

export default async function EditNewsletterPage({ params }: Props) {
  const { id } = await params;
  const [newsletter, config] = await Promise.all([
    getNewsletter(id),
    getConfig(),
  ]);
  if (!config) redirect("/admin/login");
  if (!newsletter) notFound();

  return (
    <NewsletterEditor
      initial={newsletter}
      classInfo={{
        className: config.className,
        teacherName: config.teacherName,
        schoolName: config.schoolName,
        grade: config.grade,
        room: config.room,
      }}
    />
  );
}
