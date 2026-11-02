import Link from "next/link";

const links = [
  { href: "/home", label: "Home" },
  { href: "/about", label: "Our Class" },
  { href: "/newsletters", label: "Newsletters" },
];

export function SiteHeader({
  className,
  showAdmin,
}: {
  className: string;
  showAdmin?: boolean;
}) {
  return (
    <header className="mx-auto flex w-full max-w-6xl items-center justify-between gap-4 px-5 py-5">
      <Link href="/home" className="group">
        <p className="font-[family-name:var(--font-display)] text-2xl font-semibold tracking-tight text-[var(--ink)] transition group-hover:text-[var(--sky-deep)]">
          {className}
        </p>
        <span className="block h-1 w-16 origin-left scale-x-100 rounded-full bg-[var(--sun)] transition group-hover:w-24" />
      </Link>
      <nav className="flex flex-wrap items-center gap-2 sm:gap-3">
        {links.map((link) => (
          <Link
            key={link.href}
            href={link.href}
            className="rounded-lg px-3 py-2 text-sm font-bold text-[var(--ink-soft)] transition hover:bg-white/70 hover:text-[var(--ink)]"
          >
            {link.label}
          </Link>
        ))}
        {showAdmin ? (
          <Link
            href="/admin"
            className="rounded-lg bg-[var(--ink)] px-3 py-2 text-sm font-bold text-white"
          >
            Admin
          </Link>
        ) : null}
        <form action="/api/auth/logout" method="post">
          <button
            type="submit"
            className="rounded-lg px-3 py-2 text-sm font-bold text-[var(--coral)] transition hover:bg-white/70"
          >
            Sign out
          </button>
        </form>
      </nav>
    </header>
  );
}
