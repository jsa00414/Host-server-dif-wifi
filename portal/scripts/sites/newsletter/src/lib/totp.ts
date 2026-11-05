import { generateSecret, generateSync, generateURI, verifySync } from "otplib";
import QRCode from "qrcode";

export function createTotpSecret(): string {
  return generateSecret();
}

export function buildOtpAuthUri(options: {
  secret: string;
  label: string;
  issuer: string;
}): string {
  return generateURI({
    issuer: options.issuer,
    label: options.label,
    secret: options.secret,
  });
}

export function verifyTotp(secret: string, token: string): boolean {
  const cleaned = token.replace(/\s+/g, "");
  if (!/^\d{6}$/.test(cleaned)) return false;
  const result = verifySync({ secret, token: cleaned });
  return Boolean(result.valid);
}

export function currentTotp(secret: string): string {
  return generateSync({ secret });
}

export async function totpQrDataUrl(uri: string): Promise<string> {
  return QRCode.toDataURL(uri, {
    errorCorrectionLevel: "M",
    margin: 2,
    width: 280,
    color: { dark: "#1E3A5F", light: "#FFFFFF" },
  });
}
