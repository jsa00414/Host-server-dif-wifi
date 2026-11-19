import { NextResponse } from "next/server";
import bcrypt from "bcryptjs";
import { createSessionToken, setSessionCookie } from "@/lib/auth";
import { getConfig, saveConfig } from "@/lib/storage";
import {
  buildOtpAuthUri,
  createTotpSecret,
  totpQrDataUrl,
} from "@/lib/totp";
import type { SiteConfig } from "@/lib/types";

export async function GET() {
  const config = await getConfig();
  return NextResponse.json({
    needsCreate: !config?.setupComplete,
    className: config?.className || null,
  });
}

export async function POST(request: Request) {
  const body = await request.json();
  const mode = body.mode === "create" ? "create" : "login";
  const existing = await getConfig();

  if (mode === "create") {
    if (existing?.setupComplete) {
      return NextResponse.json(
        { error: "Admin already exists. Sign in instead." },
        { status: 400 },
      );
    }

    const {
      className,
      teacherName,
      schoolName,
      grade,
      room,
      welcomeMessage,
      password,
    } = body as Record<string, string>;

    if (!className || !teacherName || !password || password.length < 8) {
      return NextResponse.json(
        {
          error:
            "Class name, teacher name, and a password of at least 8 characters are required.",
        },
        { status: 400 },
      );
    }

    const config: SiteConfig = {
      className: className.trim(),
      teacherName: teacherName.trim(),
      schoolName: (schoolName || "Our Elementary School").trim(),
      grade: (grade || "2nd Grade").trim(),
      room: (room || "2B").trim(),
      welcomeMessage: (
        welcomeMessage ||
        "Welcome, families! This is our private class website for updates and newsletters."
      ).trim(),
      setupComplete: true,
      adminPasswordHash: await bcrypt.hash(password, 12),
      // Kept for schema compatibility; admin sign-in is password-only.
      adminTotpSecret: createTotpSecret(),
      viewerTotpSecret: createTotpSecret(),
      createdAt: new Date().toISOString(),
    };

    await saveConfig(config);

    const viewerUri = buildOtpAuthUri({
      secret: config.viewerTotpSecret,
      label: `${config.className} Families`,
      issuer: config.schoolName,
    });

    return NextResponse.json({
      ok: true,
      created: true,
      viewer: {
        secret: config.viewerTotpSecret,
        uri: viewerUri,
        qrDataUrl: await totpQrDataUrl(viewerUri),
      },
    });
  }

  if (!existing?.setupComplete) {
    return NextResponse.json(
      { error: "Create your admin login first.", needsCreate: true },
      { status: 400 },
    );
  }

  const { password } = body as { password?: string };
  const passwordOk =
    !!password && (await bcrypt.compare(password, existing.adminPasswordHash));

  if (!passwordOk) {
    return NextResponse.json(
      { error: "Password is incorrect." },
      { status: 401 },
    );
  }

  const token = await createSessionToken("admin", 8);
  await setSessionCookie("admin", token);
  return NextResponse.json({ ok: true });
}
