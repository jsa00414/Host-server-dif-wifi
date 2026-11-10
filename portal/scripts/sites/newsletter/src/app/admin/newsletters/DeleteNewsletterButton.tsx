"use client";

import { useRouter } from "next/navigation";
import { useState } from "react";

export function DeleteNewsletterButton({ id }: { id: string }) {
  const router = useRouter();
  const [busy, setBusy] = useState(false);

  async function onDelete() {
    if (!window.confirm("Delete this newsletter and its PDF?")) return;
    setBusy(true);
    await fetch(`/api/admin/newsletters/${id}`, { method: "DELETE" });
    setBusy(false);
    router.refresh();
  }

  return (
    <button
      type="button"
      onClick={onDelete}
      disabled={busy}
      className="rounded-xl border border-red-200 bg-red-50 px-5 py-3 font-semibold text-red-700 transition hover:bg-red-100 disabled:opacity-60"
    >
      {busy ? "Deleting…" : "Delete"}
    </button>
  );
}
