export const dynamic = "force-dynamic";

import { redirect } from "next/navigation";
import { SiteHeader } from "@/components/SiteHeader";
import { readSession } from "@/lib/auth";
import { getConfig } from "@/lib/storage";

const rhythms = [
  {
    title: "Morning circle",
    body: "We start with greetings, calendar, and a quick share so every voice is heard.",
  },
  {
    title: "Reading workshop",
    body: "Independent reading, partnerships, and small groups help us grow as readers.",
  },
  {
    title: "Math adventures",
    body: "Hands-on games and number talks build confidence with place value and problem solving.",
  },
  {
    title: "Science & makers",
    body: "Questions, sketches, and experiments keep curiosity at the center of our week.",
  },
];

export default async function AboutPage() {
  const config = await getConfig();
  if (!config?.setupComplete) redirect("/admin/login");
  const admin = await readSession("admin");

  return (
    <div className="min-h-screen">
      <SiteHeader className={config.className} showAdmin={Boolean(admin)} />
      <main className="mx-auto max-w-6xl px-5 py-10">
        <section className="animate-fade-up max-w-3xl">
          <p className="text-sm font-extrabold uppercase tracking-[0.2em] text-[var(--sky-deep)]">
            Our class
          </p>
          <h1 className="mt-3 font-[family-name:var(--font-display)] text-5xl font-semibold text-[var(--ink)]">
            Learning with {config.teacherName}
          </h1>
          <p className="mt-4 text-lg text-[var(--ink-soft)]">
            {config.grade} in Room {config.room} at {config.schoolName}. We are
            a kind, curious community that celebrates effort, friendship, and
            big ideas.
          </p>
        </section>

        <section className="mt-14 grid gap-10 md:grid-cols-2">
          {rhythms.map((item, index) => (
            <article
              key={item.title}
              className="animate-fade-up border-t-4 border-[var(--leaf)] pt-5"
              style={{ animationDelay: `${index * 0.08}s` }}
            >
              <h2 className="font-[family-name:var(--font-display)] text-2xl font-semibold">
                {item.title}
              </h2>
              <p className="mt-2 text-[var(--ink-soft)]">{item.body}</p>
            </article>
          ))}
        </section>
      </main>
    </div>
  );
}
