export function getAppBaseUrl(request?: Request): string {
  const fromEnv =
    process.env.NEXT_PUBLIC_APP_URL || process.env.APP_URL || "";
  if (fromEnv) return fromEnv.replace(/\/$/, "");

  if (request) {
    const host =
      request.headers.get("x-forwarded-host") ||
      request.headers.get("host") ||
      "localhost:3000";
    const proto =
      request.headers.get("x-forwarded-proto") ||
      (host.includes("localhost") ? "http" : "https");
    return `${proto}://${host}`;
  }

  return "http://localhost:3000";
}

export function slideshowPath(token: string): string {
  return `/s/${token}`;
}

export function slideshowUrl(token: string, request?: Request): string {
  return `${getAppBaseUrl(request)}${slideshowPath(token)}`;
}
