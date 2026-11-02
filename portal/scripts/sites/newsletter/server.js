#!/usr/bin/env node
"use strict";

const http = require("http");
const fs = require("fs");
const path = require("path");

const PORT = Number(process.env.PORT) || 3017;
const ROOT = path.join(__dirname, "public");

const TYPES = {
  ".html": "text/html; charset=utf-8",
  ".css": "text/css; charset=utf-8",
  ".js": "text/javascript; charset=utf-8",
  ".json": "application/json; charset=utf-8",
  ".png": "image/png",
  ".jpg": "image/jpeg",
  ".jpeg": "image/jpeg",
  ".webp": "image/webp",
  ".svg": "image/svg+xml",
  ".ico": "image/x-icon",
  ".txt": "text/plain; charset=utf-8",
  ".xml": "application/xml; charset=utf-8",
};

function send(res, status, type, body) {
  res.writeHead(status, {
    "Content-Type": type,
    "Cache-Control": status === 200 ? "public, max-age=60" : "no-store",
    "X-Content-Type-Options": "nosniff",
  });
  res.end(body);
}

function safeJoin(urlPath) {
  const decoded = decodeURIComponent((urlPath || "/").split("?")[0]);
  const clean = decoded === "/" ? "/index.html" : decoded;
  const resolved = path.resolve(path.join(ROOT, clean));
  if (!resolved.startsWith(path.resolve(ROOT) + path.sep) && resolved !== path.resolve(ROOT)) {
    return null;
  }
  return resolved;
}

const server = http.createServer((req, res) => {
  if (req.method !== "GET" && req.method !== "HEAD") {
    send(res, 405, "text/plain; charset=utf-8", "Method Not Allowed");
    return;
  }
  let filePath = safeJoin(req.url || "/");
  if (!filePath) {
    send(res, 400, "text/plain; charset=utf-8", "Bad Request");
    return;
  }
  fs.stat(filePath, (err, st) => {
    if (!err && st.isDirectory()) {
      filePath = path.join(filePath, "index.html");
    }
    fs.readFile(filePath, (readErr, data) => {
      if (readErr) {
        const fallback = path.join(ROOT, "index.html");
        fs.readFile(fallback, (fbErr, fbData) => {
          if (fbErr) {
            send(res, 404, "text/plain; charset=utf-8", "Not Found");
            return;
          }
          if (req.method === "HEAD") {
            send(res, 200, "text/html; charset=utf-8", "");
            return;
          }
          send(res, 200, "text/html; charset=utf-8", fbData);
        });
        return;
      }
      const type = TYPES[path.extname(filePath).toLowerCase()] || "application/octet-stream";
      if (req.method === "HEAD") {
        send(res, 200, type, "");
        return;
      }
      send(res, 200, type, data);
    });
  });
});

server.listen(PORT, "0.0.0.0", () => {
  console.log(`newsletter listening on :${PORT}`);
});
