import { NextResponse } from "next/server";
import { clearSessionCookie } from "@/lib/auth";

export async function POST(request: Request) {
  await clearSessionCookie("viewer");
  return NextResponse.redirect(new URL("/gate", request.url), 303);
}
