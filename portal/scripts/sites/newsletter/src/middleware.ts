import { NextResponse, type NextRequest } from "next/server";
import { jwtVerify } from "jose";

const VIEWER_COOKIE = "class_viewer_session";
const ADMIN_COOKIE = "class_admin_session";

const PUBLIC_PATHS = [
  "/gate",
  "/admin/login",
  "/api/auth/verify",
  "/api/admin/login",
  "/s",
];

function secretKey() {
  const secret =
    process.env.SESSION_SECRET ||
    "sunshine-second-grade-dev-secret-change-me";
  return new TextEncoder().encode(secret);
}

async function hasValidToken(
  token: string | undefined,
  role: "viewer" | "admin",
) {
  if (!token) return false;
  try {
    const { payload } = await jwtVerify(token, secretKey());
    return payload.role === role;
  } catch {
    return false;
  }
}

export async function middleware(request: NextRequest) {
  const { pathname } = request.nextUrl;

  if (
    pathname.startsWith("/_next") ||
    pathname.startsWith("/favicon") ||
    pathname.includes(".")
  ) {
    return NextResponse.next();
  }

  const isPublic = PUBLIC_PATHS.some(
    (p) => pathname === p || pathname.startsWith(`${p}/`),
  );

  const viewerOk = await hasValidToken(
    request.cookies.get(VIEWER_COOKIE)?.value,
    "viewer",
  );
  const adminOk = await hasValidToken(
    request.cookies.get(ADMIN_COOKIE)?.value,
    "admin",
  );

  if (pathname === "/") {
    if (viewerOk || adminOk) {
      return NextResponse.redirect(new URL("/home", request.url));
    }
    return NextResponse.redirect(new URL("/gate", request.url));
  }

  if (pathname.startsWith("/admin")) {
    if (pathname === "/admin/login") {
      if (adminOk) {
        return NextResponse.redirect(new URL("/admin", request.url));
      }
      return NextResponse.next();
    }
    if (!adminOk) {
      return NextResponse.redirect(new URL("/admin/login", request.url));
    }
    return NextResponse.next();
  }

  if (pathname.startsWith("/api/admin") && pathname !== "/api/admin/login") {
    if (!adminOk) {
      return NextResponse.json({ error: "Unauthorized" }, { status: 401 });
    }
    return NextResponse.next();
  }

  if (isPublic) {
    return NextResponse.next();
  }

  if (!viewerOk && !adminOk) {
    if (pathname.startsWith("/api/")) {
      return NextResponse.json({ error: "Unauthorized" }, { status: 401 });
    }
    return NextResponse.redirect(new URL("/gate", request.url));
  }

  return NextResponse.next();
}

export const config = {
  matcher: ["/((?!_next/static|_next/image).*)"],
};
