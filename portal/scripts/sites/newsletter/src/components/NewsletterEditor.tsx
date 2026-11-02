"use client";

import { useState } from "react";
import { useRouter } from "next/navigation";
import type { Newsletter, NewsletterSection } from "@/lib/types";

function blankSection(): NewsletterSection {
  return {
    id: crypto.randomUUID(),
    heading: "",
    body: "",
  };
}

export function NewsletterEditor({
  initial,
}: {
  initial?: Newsletter | null;
}) {
  const router = useRouter();
  const [title, setTitle] = useState(initial?.title || "");
  const [subtitle, setSubtitle] = useState(initial?.subtitle || "");
  const [issueDate, setIssueDate] = useState(
    initial?.issueDate || new Date().toISOString().slice(0, 10),
  );
  const [published, setPublished] = useState(initial?.published ?? true);
  const [sections, setSections] = useState<NewsletterSection[]>(
    initial?.sections?.length ? initial.sections : [blankSection()],
  );
  const [error, setError] = useState("");
  const [saving, setSaving] = useState(false);

  function updateSection(id: string, patch: Partial<NewsletterSection>) {
    setSections((prev) =>
      prev.map((s) => (s.id === id ? { ...s, ...patch } : s)),
    );
  }

  async function save(e: React.FormEvent) {
    e.preventDefault();
    setSaving(true);
    setError("");
    const payload = {
      id: initial?.id,
      title,
      subtitle,
      issueDate,
      published,
      sections,
    };
    const res = await fetch(
      initial?.id ? `/api/admin/newsletters/${initial.id}` : "/api/admin/newsletters",
      {
        method: initial?.id ? "PUT" : "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(payload),
      },
    );
    const data = await res.json().catch(() => ({}));
    setSaving(false);
    if (!res.ok) {
      setError(data.error || "Could not save newsletter.");
      return;
    }
    router.push(`/admin/newsletters/${data.id}`);
    router.refresh();
  }

  return (
    <form onSubmit={save} className="space-y-6">
      <div className="grid gap-4 md:grid-cols-2">
        <div className="md:col-span-2">
          <label className="mb-2 block text-sm font-bold">Title</label>
          <input
            className="input-field"
            value={title}
            onChange={(e) => setTitle(e.target.value)}
            placeholder="March Family Newsletter"
            required
          />
        </div>
        <div>
          <label className="mb-2 block text-sm font-bold">Subtitle</label>
          <input
            className="input-field"
            value={subtitle}
            onChange={(e) => setSubtitle(e.target.value)}
            placeholder="Reading week & spring science"
          />
        </div>
        <div>
          <label className="mb-2 block text-sm font-bold">Issue date</label>
          <input
            type="date"
            className="input-field"
            value={issueDate}
            onChange={(e) => setIssueDate(e.target.value)}
            required
          />
        </div>
      </div>

      <label className="flex items-center gap-3 text-sm font-bold">
        <input
          type="checkbox"
          checked={published}
          onChange={(e) => setPublished(e.target.checked)}
          className="h-4 w-4 accent-[var(--sky-deep)]"
        />
        Published for families
      </label>

      <div className="space-y-4">
        <div className="flex items-center justify-between">
          <h2 className="font-[family-name:var(--font-display)] text-xl font-semibold">
            Sections
          </h2>
          <button
            type="button"
            className="btn-secondary"
            onClick={() => setSections((s) => [...s, blankSection()])}
          >
            Add section
          </button>
        </div>
        {sections.map((section, index) => (
          <div key={section.id} className="paper-card space-y-3 rounded-2xl p-5">
            <div className="flex items-center justify-between gap-3">
              <p className="text-sm font-bold text-[var(--ink-soft)]">
                Section {index + 1}
              </p>
              {sections.length > 1 ? (
                <button
                  type="button"
                  className="text-sm font-bold text-[var(--coral)]"
                  onClick={() =>
                    setSections((prev) => prev.filter((s) => s.id !== section.id))
                  }
                >
                  Remove
                </button>
              ) : null}
            </div>
            <input
              className="input-field"
              placeholder="Heading"
              value={section.heading}
              onChange={(e) =>
                updateSection(section.id, { heading: e.target.value })
              }
              required
            />
            <textarea
              className="input-field min-h-28"
              placeholder="What should families know?"
              value={section.body}
              onChange={(e) =>
                updateSection(section.id, { body: e.target.value })
              }
              required
            />
          </div>
        ))}
      </div>

      {error ? (
        <p className="rounded-xl bg-red-50 px-4 py-3 text-sm font-semibold text-red-700">
          {error}
        </p>
      ) : null}

      <button type="submit" className="btn-primary" disabled={saving}>
        {saving ? "Saving…" : initial ? "Update newsletter" : "Create newsletter"}
      </button>
    </form>
  );
}
