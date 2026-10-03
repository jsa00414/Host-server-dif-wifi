/**
 * ServerManager circle crypto — Ed25519 IP↔key binding (Web Crypto).
 * Each circle IP gets a unique keypair stored only on this device.
 */
(function (global) {
  "use strict";

  const STORE_KEYS = "sm.circle.keys.v1";
  const ALG = { name: "Ed25519" };

  function b64urlFromBuf(buf) {
    const bytes = buf instanceof ArrayBuffer ? new Uint8Array(buf) : buf;
    let s = "";
    for (let i = 0; i < bytes.length; i++) s += String.fromCharCode(bytes[i]);
    return btoa(s).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/g, "");
  }

  function bufFromB64url(s) {
    const pad = "=".repeat((4 - (s.length % 4)) % 4);
    const b64 = (s + pad).replace(/-/g, "+").replace(/_/g, "/");
    const bin = atob(b64);
    const out = new Uint8Array(bin.length);
    for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
    return out;
  }

  function loadStore() {
    try {
      return JSON.parse(localStorage.getItem(STORE_KEYS) || "{}") || {};
    } catch (_) {
      return {};
    }
  }

  function saveStore(data) {
    localStorage.setItem(STORE_KEYS, JSON.stringify(data));
  }

  async function exportRawPublic(key) {
    const raw = await crypto.subtle.exportKey("raw", key);
    return b64urlFromBuf(raw);
  }

  async function exportJwk(key) {
    return crypto.subtle.exportKey("jwk", key);
  }

  async function importPrivateJwk(jwk) {
    return crypto.subtle.importKey("jwk", jwk, ALG, true, ["sign"]);
  }

  async function importPublicRaw(b64) {
    const raw = bufFromB64url(b64);
    return crypto.subtle.importKey("raw", raw, ALG, true, ["verify"]);
  }

  function keyIdFromPub(pubB64) {
    // Short stable id (first 16 hex of SHA-256) — computed sync-ish via subtle async wrapper.
    return pubB64.slice(0, 16);
  }

  async function keyIdAsync(pubB64) {
    const dig = await crypto.subtle.digest("SHA-256", bufFromB64url(pubB64));
    return Array.from(new Uint8Array(dig))
      .slice(0, 8)
      .map((b) => b.toString(16).padStart(2, "0"))
      .join("");
  }

  async function ensureKeyForIp(ip) {
    const ipN = String(ip || "").trim();
    if (!ipN) throw new Error("IP required for circle key");
    if (!global.crypto || !crypto.subtle) {
      throw new Error("Web Crypto Ed25519 unavailable in this browser");
    }
    const store = loadStore();
    if (store[ipN] && store[ipN].privateJwk && store[ipN].publicKey) {
      return store[ipN];
    }
    const pair = await crypto.subtle.generateKey(ALG, true, ["sign", "verify"]);
    const publicKey = await exportRawPublic(pair.publicKey);
    const privateJwk = await exportJwk(pair.privateKey);
    const publicJwk = await exportJwk(pair.publicKey);
    const keyId = await keyIdAsync(publicKey);
    const row = {
      ip: ipN,
      publicKey,
      publicJwk,
      privateJwk,
      keyId,
      createdAt: Date.now(),
    };
    store[ipN] = row;
    saveStore(store);
    return row;
  }

  async function getKeyForIp(ip) {
    const store = loadStore();
    return store[String(ip || "").trim()] || null;
  }

  function proofMessage({ ts, nonce, ip, method, path, bodySha256 }) {
    return [
      "SM-CIRCLE-V1",
      String(ts),
      String(nonce),
      String(ip || ""),
      String(method || "GET").toUpperCase(),
      String(path || "/"),
      String(bodySha256 || ""),
    ].join("\n");
  }

  async function sha256Hex(text) {
    const data = new TextEncoder().encode(text || "");
    const dig = await crypto.subtle.digest("SHA-256", data);
    return Array.from(new Uint8Array(dig))
      .map((b) => b.toString(16).padStart(2, "0"))
      .join("");
  }

  async function signForIp(ip, { method, path, bodyText }) {
    const row = await ensureKeyForIp(ip);
    const priv = await importPrivateJwk(row.privateJwk);
    const ts = Math.floor(Date.now() / 1000);
    const nonce = b64urlFromBuf(crypto.getRandomValues(new Uint8Array(16)));
    const bodySha256 = await sha256Hex(bodyText || "");
    const msg = proofMessage({
      ts,
      nonce,
      ip,
      method,
      path,
      bodySha256,
    });
    const sig = await crypto.subtle.sign(ALG, priv, new TextEncoder().encode(msg));
    return {
      publicKey: row.publicKey,
      keyId: row.keyId,
      ts,
      nonce,
      signature: b64urlFromBuf(sig),
      message: msg,
    };
  }

  async function circleHeaders(ip, { method, path, bodyText } = {}) {
    const proof = await signForIp(ip, {
      method: method || "GET",
      path: path || "/",
      bodyText: bodyText || "",
    });
    return {
      "X-SM-Circle-Pub": proof.publicKey,
      "X-SM-Circle-Kid": proof.keyId,
      "X-SM-Circle-Ts": String(proof.ts),
      "X-SM-Circle-Nonce": proof.nonce,
      "X-SM-Circle-Sig": proof.signature,
      "X-SM-Circle-Ip": ip,
    };
  }

  global.SmCircleCrypto = {
    ensureKeyForIp,
    getKeyForIp,
    signForIp,
    circleHeaders,
    keyIdFromPub,
    loadStore,
    proofMessage,
    sha256Hex,
  };
})(typeof window !== "undefined" ? window : globalThis);
