export const dynamic = "force-dynamic";

import Link from "next/link";
import { AccessPanel } from "./AccessPanel";

export default function AccessPage() {
  return (
    <div className="min-h-screen">
      <header className="mx-auto flex max-w-6xl items-center justify-between px-5 py-6">
        <div>
          <Link href="/admin" className="text-sm font-bold text-[var(--sky-deep)]">
            ← Admin home
          </Link>
          <h1 className="mt-2 font-[family-name:var(--font-display)] text-3xl font-semibold">
            Family 2FA access
          </h1>
        </div>
      </header>
      <main className="mx-auto max-w-6xl px-5 pb-16">
        <AccessPanel />
      </main>
    </div>
  );
}
