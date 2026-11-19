import { NextResponse } from "next/server";
import { clearSessionCookie } from "@/lib/auth";

export async function POST(request: Request) {
  await clearSessionCookie("admin");
  return NextResponse.redirect(new URL("/admin/login", request.url), 303);
}
