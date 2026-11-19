"use strict";

require("dotenv").config();

const crypto = require("crypto");
const path = require("path");
const express = require("express");
const session = require("express-session");
const {
  verifyLogin,
  listMailboxes,
  listMessages,
  getMessage,
  getAttachment,
  setFlags,
  moveMessage,
  deleteMessage,
  sendMail,
  userFacingMailError,
} = require("./lib/mail");
const {
  isAdminEmail,
  listAccounts,
  addAccount,
  deleteAccount,
  listAliases,
  addAlias,
  deleteAlias,
  getOverview,
} = require("./lib/admin");

const PORT = Number(process.env.PORT) || 3000;
const PUBLIC_DIR = path.join(__dirname, "public");
const TRUST_PROXY = process.env.TRUST_PROXY !== "false";

const app = express();
if (TRUST_PROXY) app.set("trust proxy", 1);

app.use(express.json({ limit: "2mb" }));
app.use(express.urlencoded({ extended: false }));

app.use(
  session({
    name: "truemailsid",
    secret: process.env.SESSION_SECRET || crypto.randomBytes(32).toString("hex"),
    resave: false,
    saveUninitialized: false,
    proxy: TRUST_PROXY,
    cookie: {
      httpOnly: true,
      // "auto" uses HTTPS when behind Caddy (trust proxy); avoids lost sessions
      secure: process.env.NODE_ENV === "production" ? "auto" : false,
      sameSite: "lax",
      maxAge: 12 * 60 * 60 * 1000,
      path: "/",
    },
  })
);

function requireAuth(req, res, next) {
  if (!req.session?.mailUser || !req.session?.mailPass) {
    return res.status(401).json({ error: "Sign in required." });
  }
  next();
}

function requireAdmin(req, res, next) {
  if (!req.session?.mailUser || !req.session?.mailPass) {
    return res.status(401).json({ error: "Sign in required." });
  }
  if (!isAdminEmail(req.session.mailUser)) {
    return res.status(403).json({ error: "Admin access required." });
  }
  next();
}

app.get("/api/health", (_req, res) => {
  res.json({
    ok: true,
    service: "truemail",
    brand: process.env.MAIL_BRAND || "True Mail",
  });
});

app.get("/", (req, res) => {
  // Always land on the mail app (login or inbox)
  res.redirect(302, "/mail");
});

app.get("/mail", (_req, res) => {
  res.sendFile(path.join(PUBLIC_DIR, "mail.html"));
});

app.get("/api/auth/session", (req, res) => {
  const loggedIn = Boolean(req.session?.mailUser && req.session?.mailPass);
  const email = loggedIn ? req.session.mailUser : null;
  res.json({
    loggedIn,
    email,
    isAdmin: loggedIn ? isAdminEmail(email) : false,
    brand: process.env.MAIL_BRAND || "True Mail",
  });
});

app.post("/api/auth/login", async (req, res) => {
  try {
    const email = String(req.body?.email || "")
      .trim()
      .toLowerCase();
    const password = String(req.body?.password || "");
    if (!email || !password) {
      return res.status(400).json({ error: "Email and password are required." });
    }

    const domain = (process.env.MAIL_DOMAIN || "").trim().toLowerCase();
    if (domain && !email.endsWith("@" + domain)) {
      return res.status(403).json({ error: `Only @${domain} accounts can sign in here.` });
    }

    await verifyLogin(email, password);
    req.session.mailUser = email;
    req.session.mailPass = password;
    await new Promise((resolve, reject) => {
      req.session.save((err) => (err ? reject(err) : resolve()));
    });
    res.json({ ok: true, email, isAdmin: isAdminEmail(email) });
  } catch (err) {
    console.error("[auth/login]", err.message || err);
    res.status(401).json({ error: userFacingMailError(err) });
  }
});

app.get("/api/admin/overview", requireAdmin, async (_req, res) => {
  try {
    const overview = await getOverview();
    res.json({ overview });
  } catch (err) {
    console.error("[admin/overview]", err.message || err);
    res.status(err.status || 502).json({ error: err.message || "Admin overview failed." });
  }
});

app.get("/api/admin/accounts", requireAdmin, async (_req, res) => {
  try {
    const accounts = await listAccounts();
    res.json({ accounts });
  } catch (err) {
    console.error("[admin/accounts]", err.message || err);
    res.status(err.status || 502).json({ error: err.message || "Could not list accounts." });
  }
});

app.post("/api/admin/accounts", requireAdmin, async (req, res) => {
  try {
    const result = await addAccount(req.body?.email, req.body?.password);
    res.json({ ok: true, ...result });
  } catch (err) {
    console.error("[admin/accounts/add]", err.message || err);
    res.status(err.status || 502).json({ error: err.message || "Could not create mailbox." });
  }
});

app.delete("/api/admin/accounts/:email", requireAdmin, async (req, res) => {
  try {
    const email = decodeURIComponent(req.params.email || "");
    const result = await deleteAccount(email);
    res.json({ ok: true, ...result });
  } catch (err) {
    console.error("[admin/accounts/del]", err.message || err);
    res.status(err.status || 502).json({ error: err.message || "Could not delete mailbox." });
  }
});

app.get("/api/admin/aliases", requireAdmin, async (_req, res) => {
  try {
    const aliases = await listAliases();
    res.json({ aliases });
  } catch (err) {
    console.error("[admin/aliases]", err.message || err);
    res.status(err.status || 502).json({ error: err.message || "Could not list forwards." });
  }
});

app.post("/api/admin/aliases", requireAdmin, async (req, res) => {
  try {
    const result = await addAlias(req.body?.from, req.body?.to, {
      keepCopy: Boolean(req.body?.keepCopy),
    });
    res.json({ ok: true, ...result });
  } catch (err) {
    console.error("[admin/aliases/add]", err.message || err);
    res.status(err.status || 502).json({ error: err.message || "Could not create forward." });
  }
});

app.delete("/api/admin/aliases/:from", requireAdmin, async (req, res) => {
  try {
    const from = decodeURIComponent(req.params.from || "");
    const to = req.query?.to ? decodeURIComponent(String(req.query.to)) : undefined;
    const result = await deleteAlias(from, to);
    res.json({ ok: true, ...result });
  } catch (err) {
    console.error("[admin/aliases/del]", err.message || err);
    res.status(err.status || 502).json({ error: err.message || "Could not delete forward." });
  }
});

app.post("/api/auth/logout", (req, res) => {
  req.session.destroy((err) => {
    if (err) console.error("[auth/logout]", err);
    res.clearCookie("truemailsid");
    res.json({ ok: true });
  });
});

app.get("/api/mailboxes", requireAuth, async (req, res) => {
  try {
    const mailboxes = await listMailboxes(req.session.mailUser, req.session.mailPass);
    res.json({ mailboxes });
  } catch (err) {
    console.error("[mailboxes]", err.message || err);
    res.status(502).json({ error: userFacingMailError(err) });
  }
});

app.get("/api/messages", requireAuth, async (req, res) => {
  try {
    const data = await listMessages(req.session.mailUser, req.session.mailPass, {
      mailbox: req.query.mailbox,
      limit: req.query.limit,
      page: req.query.page,
    });
    res.json(data);
  } catch (err) {
    console.error("[messages]", err.message || err);
    res.status(502).json({ error: userFacingMailError(err) });
  }
});

app.get("/api/messages/:uid", requireAuth, async (req, res) => {
  try {
    const message = await getMessage(
      req.session.mailUser,
      req.session.mailPass,
      req.params.uid,
      req.query.mailbox
    );
    res.json({ message });
  } catch (err) {
    console.error("[message]", err.message || err);
    res.status(err.status || 502).json({ error: userFacingMailError(err) });
  }
});

function contentDispositionHeader(disposition, filename) {
  const safeName = String(filename || "attachment")
    .replace(/[\r\n"]/g, "_")
    .slice(0, 180);
  const encoded = encodeURIComponent(safeName);
  const mode = disposition === "attachment" ? "attachment" : "inline";
  return `${mode}; filename="${safeName}"; filename*=UTF-8''${encoded}`;
}

function canOpenInline(contentType) {
  const ct = String(contentType || "").toLowerCase().split(";")[0].trim();
  if (!ct) return false;
  if (ct.startsWith("image/")) return true;
  if (ct.startsWith("audio/") || ct.startsWith("video/")) return true;
  if (ct === "application/pdf") return true;
  if (ct.startsWith("text/")) return true;
  return false;
}

app.get("/api/messages/:uid/attachments/:index", requireAuth, async (req, res) => {
  try {
    const file = await getAttachment(
      req.session.mailUser,
      req.session.mailPass,
      req.params.uid,
      req.params.index,
      req.query.mailbox
    );
    const wantDownload =
      String(req.query.disposition || "").toLowerCase() === "attachment" ||
      String(req.query.download || "") === "1";
    const disposition =
      wantDownload || !canOpenInline(file.contentType) ? "attachment" : "inline";
    res.setHeader("Content-Type", file.contentType || "application/octet-stream");
    res.setHeader("Content-Length", String(file.content.length));
    res.setHeader("Content-Disposition", contentDispositionHeader(disposition, file.filename));
    res.setHeader("X-Content-Type-Options", "nosniff");
    res.setHeader("Cache-Control", "private, max-age=120");
    return res.send(file.content);
  } catch (err) {
    console.error("[attachment]", err.message || err);
    res.status(err.status || 502).json({ error: userFacingMailError(err) });
  }
});

app.post("/api/messages/send", requireAuth, async (req, res) => {
  try {
    const result = await sendMail(req.session.mailUser, req.session.mailPass, req.body || {});
    res.json({ ok: true, ...result });
  } catch (err) {
    console.error("[send]", err.message || err);
    res.status(err.status || 502).json({ error: userFacingMailError(err) });
  }
});

app.post("/api/messages/:uid/flags", requireAuth, async (req, res) => {
  try {
    const add = Array.isArray(req.body?.add) ? req.body.add : [];
    const remove = Array.isArray(req.body?.remove) ? req.body.remove : [];
    await setFlags(req.session.mailUser, req.session.mailPass, req.params.uid, req.body?.mailbox || "INBOX", {
      add,
      remove,
    });
    res.json({ ok: true });
  } catch (err) {
    console.error("[flags]", err.message || err);
    res.status(502).json({ error: userFacingMailError(err) });
  }
});

app.post("/api/messages/:uid/move", requireAuth, async (req, res) => {
  try {
    const to = req.body?.to;
    if (!to) return res.status(400).json({ error: "Destination mailbox required." });
    await moveMessage(
      req.session.mailUser,
      req.session.mailPass,
      req.params.uid,
      req.body?.from || "INBOX",
      to
    );
    res.json({ ok: true });
  } catch (err) {
    console.error("[move]", err.message || err);
    res.status(502).json({ error: userFacingMailError(err) });
  }
});

app.delete("/api/messages/:uid", requireAuth, async (req, res) => {
  try {
    await deleteMessage(
      req.session.mailUser,
      req.session.mailPass,
      req.params.uid,
      req.query.mailbox || req.body?.mailbox || "INBOX"
    );
    res.json({ ok: true });
  } catch (err) {
    console.error("[delete]", err.message || err);
    res.status(502).json({ error: userFacingMailError(err) });
  }
});

app.use(express.static(PUBLIC_DIR, { index: false }));

app.get(/^(?!\/api).*/, (_req, res) => {
  res.sendFile(path.join(PUBLIC_DIR, "mail.html"));
});

app.listen(PORT, "0.0.0.0", () => {
  console.log(`[truemail] listening on :${PORT}`);
});
