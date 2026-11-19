"use client";

import { useEffect, useState } from "react";

type SlideSection = { heading: string; body: string };

export function Slideshow({
  className,
  teacherName,
  schoolName,
  newsletter,
}: {
  className: string;
  teacherName: string;
  schoolName: string;
  newsletter: {
    title: string;
    subtitle: string;
    issueDate: string;
    sections: SlideSection[];
  };
}) {
  const slides = [
    {
      kind: "title" as const,
      heading: newsletter.title,
      body:
        newsletter.subtitle ||
        `${className} · ${new Date(newsletter.issueDate + "T12:00:00").toLocaleDateString("en-US", { month: "long", day: "numeric", year: "numeric" })}`,
    },
    ...newsletter.sections
      .filter((s) => s.heading || s.body)
      .map((s) => ({
        kind: "section" as const,
        heading: s.heading,
        body: s.body,
      })),
    {
      kind: "end" as const,
      heading: "Thanks for reading",
      body: `With care, ${teacherName} · ${schoolName}`,
    },
  ];

  const [index, setIndex] = useState(0);
  const slide = slides[index];

  function next() {
    setIndex((i) => Math.min(i + 1, slides.length - 1));
  }
  function prev() {
    setIndex((i) => Math.max(i - 1, 0));
  }

  useEffect(() => {
    function onKey(e: KeyboardEvent) {
      if (e.key === "ArrowRight" || e.key === " ") {
        e.preventDefault();
        setIndex((i) => Math.min(i + 1, slides.length - 1));
      }
      if (e.key === "ArrowLeft") {
        e.preventDefault();
        setIndex((i) => Math.max(i - 1, 0));
      }
    }
    window.addEventListener("keydown", onKey);
    return () => window.removeEventListener("keydown", onKey);
  }, [slides.length]);

  return (
    <main
      className="relative flex min-h-screen cursor-pointer flex-col overflow-hidden text-white"
      onClick={next}
      role="presentation"
    >
      <div className="hero-plane absolute inset-0" />
      <div className="animate-float absolute -left-10 top-16 h-52 w-52 rounded-full bg-[var(--sun)]/30 blur-3xl" />
      <div className="absolute bottom-10 right-10 h-64 w-64 rounded-full bg-white/10 blur-3xl" />

      <div className="relative z-10 flex flex-1 flex-col justify-center px-6 py-16 sm:px-16">
        <p className="animate-fade-up text-sm font-extrabold uppercase tracking-[0.24em] text-white/70">
          {className} · Digital newsletter
        </p>
        <h1
          key={`${index}-h`}
          className="animate-fade-up mt-5 max-w-4xl font-[family-name:var(--font-display)] text-4xl font-semibold leading-tight sm:text-6xl"
        >
          {slide.heading}
        </h1>
        <span className="animate-underline mt-5 block h-1.5 w-24 rounded-full bg-[var(--sun)]" />
        <p
          key={`${index}-b`}
          className="animate-fade-up-delay mt-8 max-w-3xl whitespace-pre-wrap text-lg leading-relaxed text-white/90 sm:text-2xl"
        >
          {slide.body}
        </p>
      </div>

      <div className="relative z-10 flex items-center justify-between gap-4 px-6 pb-8 sm:px-16">
        <button
          type="button"
          className="rounded-xl bg-white/15 px-4 py-2 text-sm font-bold backdrop-blur transition hover:bg-white/25"
          onClick={(e) => {
            e.stopPropagation();
            prev();
          }}
        >
          Back
        </button>
        <div className="flex items-center gap-2">
          {slides.map((_, i) => (
            <span
              key={i}
              className={`h-2.5 rounded-full transition-all ${
                i === index ? "w-8 bg-[var(--sun)]" : "w-2.5 bg-white/40"
              }`}
            />
          ))}
        </div>
        <button
          type="button"
          className="rounded-xl bg-white/15 px-4 py-2 text-sm font-bold backdrop-blur transition hover:bg-white/25"
          onClick={(e) => {
            e.stopPropagation();
            next();
          }}
        >
          {index === slides.length - 1 ? "Done" : "Next"}
        </button>
      </div>
    </main>
  );
}
