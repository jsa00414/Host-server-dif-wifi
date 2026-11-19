import { SignJWT, jwtVerify } from "jose";
import { cookies } from "next/headers";
import type { SessionPayload } from "./types";

const VIEWER_COOKIE = "class_viewer_session";
const ADMIN_COOKIE = "class_admin_session";

function secretKey() {
  const secret =
    process.env.SESSION_SECRET ||
    "sunshine-second-grade-dev-secret-change-me";
  return new TextEncoder().encode(secret);
}

export async function createSessionToken(
  role: SessionPayload["role"],
  hours = 12,
): Promise<string> {
  const exp = Math.floor(Date.now() / 1000) + hours * 60 * 60;
  return new SignJWT({ role })
    .setProtectedHeader({ alg: "HS256" })
    .setExpirationTime(exp)
    .setIssuedAt()
    .sign(secretKey());
}

export async function readSession(
  kind: "viewer" | "admin",
): Promise<SessionPayload | null> {
  const jar = await cookies();
  const name = kind === "admin" ? ADMIN_COOKIE : VIEWER_COOKIE;
  const token = jar.get(name)?.value;
  if (!token) return null;
  try {
    const { payload } = await jwtVerify(token, secretKey());
    if (payload.role !== kind) return null;
    return {
      role: payload.role as SessionPayload["role"],
      exp: typeof payload.exp === "number" ? payload.exp : 0,
    };
  } catch {
    return null;
  }
}

export async function setSessionCookie(
  kind: "viewer" | "admin",
  token: string,
) {
  const jar = await cookies();
  const name = kind === "admin" ? ADMIN_COOKIE : VIEWER_COOKIE;
  jar.set(name, token, {
    httpOnly: true,
    sameSite: "lax",
    // Allow HTTP local demos; set COOKIE_SECURE=true behind HTTPS.
    secure: process.env.COOKIE_SECURE === "true",
    path: "/",
    maxAge: 60 * 60 * 12,
  });
}

export async function clearSessionCookie(kind: "viewer" | "admin") {
  const jar = await cookies();
  const name = kind === "admin" ? ADMIN_COOKIE : VIEWER_COOKIE;
  jar.delete(name);
}

export { VIEWER_COOKIE, ADMIN_COOKIE };
