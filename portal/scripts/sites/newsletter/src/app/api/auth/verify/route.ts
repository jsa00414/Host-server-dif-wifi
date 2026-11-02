import { NextResponse } from "next/server";
import { createSessionToken, setSessionCookie } from "@/lib/auth";
import { getConfig } from "@/lib/storage";
import { verifyTotp } from "@/lib/totp";

export async function POST(request: Request) {
  const config = await getConfig();
  if (!config?.setupComplete) {
    return NextResponse.json(
      { error: "Site is not set up yet.", redirect: "/admin/login" },
      { status: 400 },
    );
  }

  const { code } = (await request.json()) as { code?: string };
  if (!code || !verifyTotp(config.viewerTotpSecret, code)) {
    return NextResponse.json(
      { error: "That code is not valid. Check your authenticator app." },
      { status: 401 },
    );
  }

  const token = await createSessionToken("viewer");
  await setSessionCookie("viewer", token);
  return NextResponse.json({ ok: true });
}
