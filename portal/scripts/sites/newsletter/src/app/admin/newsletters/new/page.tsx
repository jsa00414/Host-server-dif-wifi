export const dynamic = "force-dynamic";

import { redirect } from "next/navigation";
import { NewsletterEditor } from "@/components/NewsletterEditor";
import { getConfig } from "@/lib/storage";

export default async function NewNewsletterPage() {
  const config = await getConfig();
  if (!config) redirect("/admin/login");

  return (
    <NewsletterEditor
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
