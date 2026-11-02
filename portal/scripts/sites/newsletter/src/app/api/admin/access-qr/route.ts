import { NextResponse } from "next/server";
import { getConfig, saveConfig } from "@/lib/storage";
import {
  buildOtpAuthUri,
  createTotpSecret,
  totpQrDataUrl,
} from "@/lib/totp";

export async function GET() {
  const config = await getConfig();
  if (!config) {
    return NextResponse.json({ error: "Not configured" }, { status: 400 });
  }

  const viewerUri = buildOtpAuthUri({
    secret: config.viewerTotpSecret,
    label: `${config.className} Families`,
    issuer: config.schoolName,
  });
  const adminUri = buildOtpAuthUri({
    secret: config.adminTotpSecret,
    label: `${config.className} Admin`,
    issuer: config.schoolName,
  });

  return NextResponse.json({
    viewer: {
      secret: config.viewerTotpSecret,
      uri: viewerUri,
      qrDataUrl: await totpQrDataUrl(viewerUri),
    },
    admin: {
      secret: config.adminTotpSecret,
      uri: adminUri,
      qrDataUrl: await totpQrDataUrl(adminUri),
    },
  });
}

export async function POST(request: Request) {
  const config = await getConfig();
  if (!config) {
    return NextResponse.json({ error: "Not configured" }, { status: 400 });
  }

  const { target } = (await request.json()) as { target?: string };
  if (target === "viewer") {
    config.viewerTotpSecret = createTotpSecret();
  } else if (target === "admin") {
    config.adminTotpSecret = createTotpSecret();
  } else {
    return NextResponse.json({ error: "Invalid target" }, { status: 400 });
  }

  await saveConfig(config);
  return NextResponse.json({ ok: true });
}
