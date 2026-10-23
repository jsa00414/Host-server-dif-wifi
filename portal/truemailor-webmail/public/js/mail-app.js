(function () {
  function setAppHeight() {
    const h = window.visualViewport ? window.visualViewport.height : window.innerHeight;
    document.documentElement.style.setProperty("--app-height", `${Math.round(h)}px`);
  }
  setAppHeight();
  window.addEventListener("resize", setAppHeight);
  window.addEventListener("orientationchange", setAppHeight);
  if (window.visualViewport) {
    window.visualViewport.addEventListener("resize", setAppHeight);
    window.visualViewport.addEventListener("scroll", setAppHeight);
  }
  document.addEventListener(
    "touchmove",
    (ev) => {
      if (ev.touches.length > 1) return;
      const scrollable = ev.target.closest(
        ".message-list, .read-scroll, .gmail-nav, .admin-main, .gmail-login, .compose-form textarea, .compose-form"
      );
      if (!scrollable) {
        ev.preventDefault();
        return;
      }
      // Prevent chaining scroll to the document when pane is at edge
      const el = scrollable;
      const atTop = el.scrollTop <= 0;
      const atBottom = el.scrollTop + el.clientHeight >= el.scrollHeight - 1;
      const touching = ev.target;
      // allow default inside scrollable; browser handles it
    },
    { passive: false }
  );

  const state = {
    email: null,
    mailbox: "INBOX",
    mailboxes: [],
    messages: [],
    selectedUid: null,
    selected: null,
    query: "",
    isAdmin: false,
  };

  const els = {
    app: document.getElementById("app"),
    folderNav: document.getElementById("folderNav"),
    signedAs: document.getElementById("signedAs"),
    listTitle: document.getElementById("listTitle"),
    messageList: document.getElementById("messageList"),
    listLoading: document.getElementById("listLoading"),
    listEmpty: document.getElementById("listEmpty"),
    readEmpty: document.getElementById("readEmpty"),
    readView: document.getElementById("readView"),
    readSubject: document.getElementById("readSubject"),
    readFrom: document.getElementById("readFrom"),
    readTo: document.getElementById("readTo"),
    readDate: document.getElementById("readDate"),
    readBody: document.getElementById("readBody"),
    readAttachments: document.getElementById("readAttachments"),
    composeModal: document.getElementById("composeModal"),
    composeForm: document.getElementById("composeForm"),
    composeError: document.getElementById("composeError"),
    toast: document.getElementById("toast"),
    sidebar: document.getElementById("sidebar"),
    sidebarBackdrop: document.getElementById("sidebarBackdrop"),
    searchInput: document.getElementById("searchInput"),
    starBtn: document.getElementById("starBtn"),
  };

  let toastTimer = null;

  function toast(msg) {
    if (!els.toast) return;
    els.toast.textContent = msg;
    els.toast.hidden = false;
    clearTimeout(toastTimer);
    toastTimer = setTimeout(() => {
      els.toast.hidden = true;
    }, 2600);
  }

  function closeAccountMenus() {
    document.querySelectorAll(".account-menu").forEach((menu) => {
      const btn = menu.querySelector(".account-menu-btn");
      const panel = menu.querySelector(".account-menu-panel");
      if (btn) btn.setAttribute("aria-expanded", "false");
      if (panel) panel.hidden = true;
    });
  }

  function wireAccountMenu(menuId, btnId, panelId) {
    const btn = document.getElementById(btnId);
    const panel = document.getElementById(panelId);
    if (!btn || !panel) return;
    btn.addEventListener("click", (ev) => {
      ev.stopPropagation();
      const open = panel.hidden;
      closeAccountMenus();
      if (open) {
        panel.hidden = false;
        btn.setAttribute("aria-expanded", "true");
      }
    });
    panel.addEventListener("click", (ev) => ev.stopPropagation());
  }

  wireAccountMenu("mailAccountMenu", "mailAccountMenuBtn", "mailAccountMenuPanel");
  wireAccountMenu("adminAccountMenu", "adminAccountMenuBtn", "adminAccountMenuPanel");
  document.addEventListener("click", () => closeAccountMenus());
  document.addEventListener("keydown", (ev) => {
    if (ev.key === "Escape") closeAccountMenus();
  });

  function setAccountIdentity(email) {
    const letter = (email || "A").trim().charAt(0).toUpperCase() || "A";
    ["signedAs", "adminSignedAs"].forEach((id) => {
      const el = document.getElementById(id);
      if (el) el.textContent = email || "";
    });
    ["accountAvatar", "adminAccountAvatar"].forEach((id) => {
      const el = document.getElementById(id);
      if (el) el.textContent = letter;
    });
  }

  function escapeHtml(s) {
    return String(s)
      .replace(/&/g, "&amp;")
      .replace(/</g, "&lt;")
      .replace(/>/g, "&gt;")
      .replace(/"/g, "&quot;");
  }

  async function api(path, opts = {}) {
    const controller = new AbortController();
    const timeoutMs = opts.timeoutMs || 45000;
    const timer = setTimeout(() => controller.abort(), timeoutMs);
    const onOuterAbort = () => controller.abort();
    if (opts.signal) {
      if (opts.signal.aborted) controller.abort();
      else opts.signal.addEventListener("abort", onOuterAbort, { once: true });
    }
    try {
      const { timeoutMs: _t, signal: _s, ...rest } = opts;
      const res = await fetch(path, {
        credentials: "same-origin",
        headers: { "Content-Type": "application/json", ...(rest.headers || {}) },
        signal: controller.signal,
        ...rest,
      });
      const text = await res.text();
      let data = {};
      try {
        data = text ? JSON.parse(text) : {};
      } catch (_) {
        throw new Error("Unexpected server response.");
      }
      if (!res.ok) throw new Error(data.error || "Request failed.");
      return data;
    } catch (e) {
      if (e && e.name === "AbortError") {
        const err = new Error("Request timed out. Try again.");
        err.name = "AbortError";
        throw err;
      }
      throw e;
    } finally {
      clearTimeout(timer);
      if (opts.signal) opts.signal.removeEventListener("abort", onOuterAbort);
    }
  }

  function folderLabel(box) {
    if (box.specialUse === "\\Inbox" || box.path === "INBOX") return "Inbox";
    if (box.specialUse === "\\Sent") return "Sent";
    if (box.specialUse === "\\Drafts") return "Drafts";
    if (box.specialUse === "\\Trash") return "Trash";
    if (box.specialUse === "\\Junk") return "Spam";
    if (box.specialUse === "\\Archive") return "Archive";
    return box.name || box.path;
  }

  function findSpecial(use) {
    return state.mailboxes.find((b) => b.specialUse === use)?.path;
  }

  function folderIcon(box) {
    const use = box.specialUse || "";
    const path = box.path || "";
    if (use === "\\Inbox" || path === "INBOX") {
      return '<svg class="folder-icon" viewBox="0 0 24 24"><path fill="currentColor" d="M19 3H4.99C3.88 3 3 3.9 3 5l.01 14c0 1.1.88 2 1.99 2H19c1.1 0 2-.9 2-2V5c0-1.1-.9-2-2-2zm0 12h-4c0 1.66-1.35 3-3 3s-3-1.34-3-3H4.99V5H19v10z"/></svg>';
    }
    if (use === "\\Sent") {
      return '<svg class="folder-icon" viewBox="0 0 24 24"><path fill="currentColor" d="M2.01 21 23 12 2.01 3 2 10l15 2-15 2z"/></svg>';
    }
    if (use === "\\Drafts") {
      return '<svg class="folder-icon" viewBox="0 0 24 24"><path fill="currentColor" d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8l-6-6zm2 16H8v-2h8v2zm0-4H8v-2h8v2zm-3-5V3.5L18.5 9H13z"/></svg>';
    }
    if (use === "\\Trash") {
      return '<svg class="folder-icon" viewBox="0 0 24 24"><path fill="currentColor" d="M6 19a2 2 0 0 0 2 2h8a2 2 0 0 0 2-2V7H6v12zM19 4h-3.5l-1-1h-5l-1 1H5v2h14V4z"/></svg>';
    }
    if (use === "\\Junk") {
      return '<svg class="folder-icon" viewBox="0 0 24 24"><path fill="currentColor" d="M12 2C6.48 2 2 6.48 2 12s4.48 10 10 10 10-4.48 10-10S17.52 2 12 2zm1 15h-2v-2h2v2zm0-4h-2V7h2v6z"/></svg>';
    }
    if (use === "\\Archive") {
      return '<svg class="folder-icon" viewBox="0 0 24 24"><path fill="currentColor" d="M20.54 5.23 19.15 3.55A1.5 1.5 0 0 0 17.96 3H6.04c-.47 0-.92.22-1.19.55L3.46 5.23c-.24.3-.36.67-.36 1.05V19a2 2 0 0 0 2 2h14a2 2 0 0 0 2-2V6.28c0-.38-.12-.75-.36-1.05zM12 17.5 6.5 12H10v-2h4v2h3.5L12 17.5zM5.12 5l.81-1h12l.94 1H5.12z"/></svg>';
    }
    return '<svg class="folder-icon" viewBox="0 0 24 24"><path fill="currentColor" d="M10 4H4c-1.1 0-2 .9-2 2v12c0 1.1.9 2 2 2h16c1.1 0 2-.9 2-2V8c0-1.1-.9-2-2-2h-8l-2-2z"/></svg>';
  }

  function renderFolders() {
    const order = ["\\Inbox", "\\Sent", "\\Drafts", "\\Archive", "\\Junk", "\\Trash"];
    const sorted = [...state.mailboxes].sort((a, b) => {
      const ai = order.indexOf(a.specialUse || "");
      const bi = order.indexOf(b.specialUse || "");
      if (a.path === "INBOX") return -1;
      if (b.path === "INBOX") return 1;
      if (ai !== -1 || bi !== -1) return (ai === -1 ? 99 : ai) - (bi === -1 ? 99 : bi);
      return folderLabel(a).localeCompare(folderLabel(b));
    });

    els.folderNav.innerHTML = sorted
      .map((b) => {
        const active = b.path === state.mailbox ? " active" : "";
        return `<button type="button" class="folder-btn${active}" data-path="${escapeHtml(b.path)}">${folderIcon(b)}<span>${escapeHtml(folderLabel(b))}</span></button>`;
      })
      .join("");

    els.folderNav.querySelectorAll(".folder-btn").forEach((btn) => {
      btn.addEventListener("click", () => {
        selectMailbox(btn.getAttribute("data-path"));
        closeSidebar();
      });
    });
  }

  function formatWhen(iso) {
    if (!iso) return "";
    const d = new Date(iso);
    const now = new Date();
    const sameDay = d.toDateString() === now.toDateString();
    return sameDay
      ? d.toLocaleTimeString(undefined, { hour: "numeric", minute: "2-digit" })
      : d.toLocaleDateString(undefined, { month: "short", day: "numeric" });
  }

  function filteredMessages() {
    const q = state.query.trim().toLowerCase();
    if (!q) return state.messages;
    return state.messages.filter((m) => {
      return (
        (m.subject || "").toLowerCase().includes(q) ||
        (m.from || "").toLowerCase().includes(q) ||
        (m.to || "").toLowerCase().includes(q)
      );
    });
  }

  function initialsFrom(from) {
    const raw = String(from || "").trim();
    const name = (raw.match(/^([^<]+)/) || [])[1]?.trim() || raw;
    const parts = name.replace(/["']/g, "").split(/\s+/).filter(Boolean);
    if (!parts.length) return "?";
    if (parts.length === 1) return parts[0].slice(0, 2).toUpperCase();
    return (parts[0][0] + parts[parts.length - 1][0]).toUpperCase();
  }

  function formatBytes(n) {
    const size = Number(n) || 0;
    if (size < 1024) return `${size} B`;
    if (size < 1024 * 1024) return `${(size / 1024).toFixed(size < 10 * 1024 ? 1 : 0)} KB`;
    return `${(size / (1024 * 1024)).toFixed(size < 10 * 1024 * 1024 ? 1 : 0)} MB`;
  }

  function attachmentUrl(uid, index, opts) {
    const q = new URLSearchParams();
    q.set("mailbox", state.mailbox || "INBOX");
    if (opts && opts.download) q.set("disposition", "attachment");
    return `/api/messages/${encodeURIComponent(uid)}/attachments/${encodeURIComponent(index)}?${q}`;
  }

  function renderAttachments(message) {
    const list = message.attachments || [];
    if (!list.length) {
      els.readAttachments.hidden = true;
      els.readAttachments.innerHTML = "";
      return;
    }
    els.readAttachments.hidden = false;
    els.readAttachments.innerHTML =
      `<div class="attach-heading">Attachments (${list.length})</div>` +
      `<ul class="attach-list">` +
      list
        .map((a) => {
          const openHref = attachmentUrl(message.uid, a.index, { download: false });
          const dlHref = attachmentUrl(message.uid, a.index, { download: true });
          const size = a.size ? `<span class="attach-size">${escapeHtml(formatBytes(a.size))}</span>` : "";
          return (
            `<li class="attach-item">` +
            `<a class="attach-open" href="${escapeHtml(openHref)}" target="_blank" rel="noopener noreferrer" title="Open ${escapeHtml(a.filename || "attachment")}">` +
            `<span class="attach-icon" aria-hidden="true"><svg viewBox="0 0 24 24" width="16" height="16"><path fill="currentColor" d="M16.5 6.5v9.25a4.75 4.75 0 1 1-9.5 0V6.25a3.25 3.25 0 0 1 6.5 0v8.75a1.75 1.75 0 1 1-3.5 0V7.5h1.5v7.5a.25.25 0 0 0 .5 0V6.25a1.75 1.75 0 1 0-3.5 0v9.5a3.25 3.25 0 0 0 6.5 0V6.5h1.5z"/></svg></span>` +
            `<span class="attach-name">${escapeHtml(a.filename || `attachment-${a.index + 1}`)}</span>` +
            `</a>` +
            size +
            `<a class="attach-download" href="${escapeHtml(dlHref)}" download="${escapeHtml(a.filename || "attachment")}">Download</a>` +
            `</li>`
          );
        })
        .join("") +
      `</ul>`;
  }

  function renderMessageRow(m) {
    const active = m.uid === state.selectedUid ? " active" : "";
    const unread = m.seen ? "" : " unread";
    const flagged = m.flagged ? " flagged" : "";
    const from = m.from || "";
    const fromShort = ((from.match(/^([^<]+)/) || [])[1] || from).replace(/["']/g, "").trim();
    const clip = m.hasAttachments
      ? `<span class="msg-attach" title="Has attachments" aria-label="Has attachments"><svg viewBox="0 0 24 24" width="14" height="14" aria-hidden="true"><path fill="currentColor" d="M16.5 6.5v9.25a4.75 4.75 0 1 1-9.5 0V6.25a3.25 3.25 0 0 1 6.5 0v8.75a1.75 1.75 0 1 1-3.5 0V7.5h1.5v7.5a.25.25 0 0 0 .5 0V6.25a1.75 1.75 0 1 0-3.5 0v9.5a3.25 3.25 0 0 0 6.5 0V6.5h1.5z"/></svg></span>`
      : "";
    return (
      `<button type="button" class="msg-row${active}${unread}${flagged}" data-uid="${m.uid}" role="listitem">` +
      `<span class="msg-star" aria-hidden="true">${m.flagged ? "★" : "☆"}</span>` +
      `<span class="msg-from">${escapeHtml(fromShort || from)}</span>` +
      `<span class="msg-subject-line"><span class="msg-subject">${escapeHtml(m.subject || "(no subject)")}</span>${clip}</span>` +
      `<span class="msg-date">${escapeHtml(formatWhen(m.date))}</span>` +
      `</button>`
    );
  }

  function renderList() {
    const messages = filteredMessages();
    els.listEmpty.hidden = messages.length > 0;
    if (els.listEmpty && messages.length === 0) {
      els.listEmpty.textContent = "No messages here.";
    }
    els.messageList.innerHTML = messages.map(renderMessageRow).join("");

    els.messageList.querySelectorAll(".msg-row").forEach((row) => {
      row.addEventListener("click", () => openMessage(Number(row.getAttribute("data-uid"))));
    });
  }

  function clearRead() {
    state.selectedUid = null;
    state.selected = null;
    els.readView.hidden = true;
    els.readEmpty.hidden = false;
    els.app.classList.remove("show-read");
  }

  function showRead(message) {
    state.selected = message;
    state.selectedUid = message.uid;
    els.readEmpty.hidden = true;
    els.readView.hidden = false;
    els.readSubject.textContent = message.subject || "(no subject)";
    els.readFrom.textContent = message.from || "";
    els.readTo.textContent = message.to ? `To: ${message.to}` : "";
    els.readDate.textContent = message.date ? new Date(message.date).toLocaleString() : "";
    if (els.starBtn) {
      els.starBtn.title = message.flagged ? "Unstar" : "Star";
      els.starBtn.setAttribute("aria-label", message.flagged ? "Unstar" : "Star");
      els.starBtn.style.color = message.flagged ? "#f4b400" : "";
    }
    const avatar = document.getElementById("readAvatar");
    if (avatar) avatar.textContent = initialsFrom(message.from);

    if (message.html) {
      const doc = `<!DOCTYPE html><html><head><meta charset="utf-8"><base target="_blank" rel="noopener"><style>body{font-family:Roboto,Helvetica Neue,Arial,sans-serif;color:#202124;margin:0;line-height:1.5;font-size:14px;word-break:break-word;}img{max-width:100%;height:auto;}a{color:#1a73e8;}</style></head><body>${message.html}</body></html>`;
      els.readBody.innerHTML = `<iframe title="Message" sandbox="allow-same-origin allow-popups allow-popups-to-escape-sandbox" style="width:100%;min-height:60vh;border:0;background:transparent;"></iframe>`;
      const iframe = els.readBody.querySelector("iframe");
      iframe.srcdoc = doc;
    } else {
      els.readBody.innerHTML = `<pre>${escapeHtml(message.text || "")}</pre>`;
    }

    renderAttachments(message);

    els.app.classList.add("show-read");
    renderList();
  }

  async function loadMailboxes() {
    const data = await api("/api/mailboxes");
    state.mailboxes = data.mailboxes || [];
    if (!state.mailboxes.find((b) => b.path === state.mailbox)) {
      state.mailbox = state.mailboxes[0]?.path || "INBOX";
    }
    renderFolders();
  }

  async function loadMessages() {
    els.listLoading.hidden = false;
    els.listEmpty.hidden = true;
    try {
      const data = await api(
        `/api/messages?mailbox=${encodeURIComponent(state.mailbox)}&limit=75`
      );
      state.messages = data.messages || [];
      const label =
        state.mailboxes.find((b) => b.path === state.mailbox) || { path: state.mailbox, name: state.mailbox };
      els.listTitle.textContent = folderLabel(label);
      renderList();
    } finally {
      els.listLoading.hidden = true;
    }
  }

  async function selectMailbox(path) {
    state.mailbox = path;
    clearRead();
    renderFolders();
    await loadMessages();
  }

  async function openMessage(uid) {
    try {
      const data = await api(`/api/messages/${uid}?mailbox=${encodeURIComponent(state.mailbox)}`);
      const msg = data.message;
      const row = state.messages.find((m) => m.uid === uid);
      if (row) row.seen = true;
      showRead(msg);
    } catch (e) {
      toast(e.message || "Could not open message.");
    }
  }

  let sendAbort = null;

  function openCompose(prefill = {}) {
    if (els.composeError) {
      els.composeError.hidden = true;
      els.composeError.textContent = "";
    }
    document.getElementById("composeTo").value = prefill.to || "";
    document.getElementById("composeCc").value = prefill.cc || "";
    document.getElementById("composeSubject").value = prefill.subject || "";
    document.getElementById("composeBody").value = prefill.text || "";
    els.composeModal.classList.add("is-open");
    els.composeModal.setAttribute("aria-hidden", "false");
    const sendBtn = document.getElementById("sendBtn");
    if (sendBtn) {
      sendBtn.disabled = false;
      sendBtn.textContent = "Send";
    }
    setTimeout(() => document.getElementById("composeTo")?.focus(), 50);
  }

  function closeCompose(ev) {
    if (ev) {
      ev.preventDefault();
      ev.stopPropagation();
    }
    if (sendAbort) {
      try {
        sendAbort.abort();
      } catch (_) {
        /* ignore */
      }
      sendAbort = null;
    }
    els.composeModal.classList.remove("is-open");
    els.composeModal.setAttribute("aria-hidden", "true");
    try {
      els.composeForm?.reset();
    } catch (_) {
      /* ignore */
    }
    const sendBtn = document.getElementById("sendBtn");
    if (sendBtn) {
      sendBtn.disabled = false;
      sendBtn.textContent = "Send";
    }
  }

  function openSidebar() {
    els.sidebar.classList.add("open");
    els.sidebarBackdrop.hidden = false;
  }

  function closeSidebar() {
    els.sidebar.classList.remove("open");
    els.sidebarBackdrop.hidden = true;
  }

  function showBootError(msg) {
    const boot = document.getElementById("bootScreen");
    const status = document.getElementById("bootStatus");
    const err = document.getElementById("bootError");
    const retry = document.getElementById("bootRetry");
    hideLogin();
    if (boot) boot.classList.add("is-open");
    if (els.app) els.app.classList.remove("is-open");
    if (status) status.textContent = "Could not open inbox.";
    if (err) {
      err.hidden = false;
      err.textContent = msg || "Unknown error.";
    }
    if (retry) retry.hidden = false;
  }

  function hideBoot() {
    document.getElementById("bootScreen")?.classList.remove("is-open");
  }

  function showLogin() {
    hideBoot();
    hideAdmin();
    if (els.app) els.app.classList.remove("is-open");
    const login = document.getElementById("loginScreen");
    if (login) login.hidden = false;
    document.body.classList.add("auth-page");
    document.body.classList.remove("app-page");
  }

  function hideLogin() {
    const login = document.getElementById("loginScreen");
    if (login) login.hidden = true;
    document.body.classList.remove("auth-page");
    document.body.classList.add("app-page");
  }

  function hideAdmin() {
    const admin = document.getElementById("adminApp");
    if (admin) {
      admin.hidden = true;
      admin.classList.remove("is-open");
    }
  }

  function showAdmin() {
    hideBoot();
    hideLogin();
    if (els.app) els.app.classList.remove("is-open");
    const admin = document.getElementById("adminApp");
    if (admin) {
      admin.hidden = false;
      admin.classList.add("is-open");
    }
  }

  function showApp() {
    hideBoot();
    hideLogin();
    hideAdmin();
    if (els.app) els.app.classList.add("is-open");
  }

  function renderAdminAccounts(accounts, adminList) {
    const list = document.getElementById("adminAccountList");
    if (!list) return;
    const admins = new Set((adminList || []).map((e) => String(e).toLowerCase()));
    if (!accounts.length) {
      list.innerHTML = '<p class="pane-status">No mailboxes yet.</p>';
      return;
    }
    list.innerHTML = accounts
      .map((email) => {
        const isAdm = admins.has(String(email).toLowerCase());
        return (
          `<div class="admin-account-row">` +
          `<div><strong>${escapeHtml(email)}</strong>${isAdm ? '<span class="admin-tag">ADMIN</span>' : ""}</div>` +
          `<button type="button" class="btn-danger-text" data-del="${escapeHtml(email)}" ${isAdm ? "disabled" : ""}>Delete</button>` +
          `</div>`
        );
      })
      .join("");
    list.querySelectorAll("[data-del]").forEach((btn) => {
      btn.addEventListener("click", async () => {
        const email = btn.getAttribute("data-del");
        if (!email || !confirm(`Delete mailbox ${email}?`)) return;
        try {
          await api(`/api/admin/accounts/${encodeURIComponent(email)}`, { method: "DELETE" });
          toast("Mailbox deleted");
          await loadAdminDashboard();
        } catch (e) {
          toast(e.message || "Delete failed");
        }
      });
    });
  }

  function renderAdminForwards(aliases) {
    const list = document.getElementById("adminForwardList");
    if (!list) return;
    if (!aliases.length) {
      list.innerHTML = '<p class="pane-status">No forwards yet.</p>';
      return;
    }
    list.innerHTML = aliases
      .map((row) => {
        const destinations = (row.to || []).filter((addr) => addr !== row.from);
        const destText = destinations.length ? destinations.join(", ") : (row.to || []).join(", ");
        const keep = row.keepCopy ? '<span class="admin-tag">KEEP COPY</span>' : "";
        return (
          `<div class="admin-account-row">` +
          `<div>` +
          `<strong>${escapeHtml(row.from)}</strong>${keep}` +
          `<div class="admin-forward-dest">→ ${escapeHtml(destText)}</div>` +
          `</div>` +
          `<button type="button" class="btn-danger-text" data-fwd="${escapeHtml(row.from)}">Delete</button>` +
          `</div>`
        );
      })
      .join("");
    list.querySelectorAll("[data-fwd]").forEach((btn) => {
      btn.addEventListener("click", async () => {
        const from = btn.getAttribute("data-fwd");
        if (!from || !confirm(`Delete forward for ${from}?`)) return;
        try {
          await api(`/api/admin/aliases/${encodeURIComponent(from)}`, { method: "DELETE" });
          toast("Forward deleted");
          await loadAdminDashboard();
        } catch (e) {
          toast(e.message || "Delete failed");
        }
      });
    });
  }

  async function loadAdminDashboard() {
    const overviewRes = await api("/api/admin/overview");
    const o = overviewRes.overview || {};
    const setText = (id, val) => {
      const el = document.getElementById(id);
      if (el) el.textContent = val || "—";
    };
    setText("adminDomain", o.domain);
    setText("adminHostname", o.hostname);
    setText("adminAccountCount", String(o.accountCount ?? (o.accounts || []).length));
    setAccountIdentity(state.email || "");
    const outboundEl = document.getElementById("adminOutboundStatus");
    const outboundCard = document.getElementById("adminOutboundCard");
    if (outboundEl) {
      const ob = o.outboundSmtp || {};
      if (ob.ok) {
        outboundEl.textContent = `Open — delivery to remote servers works (${ob.host}:${ob.port}).`;
        outboundCard?.classList.add("is-ok");
        outboundCard?.classList.remove("is-bad");
      } else {
        outboundEl.textContent =
          ob.hint ||
          `Blocked — cannot reach ${ob.host || "remote MX"}:${ob.port || 25}. Call IONOS to unblock outbound port 25.`;
        outboundCard?.classList.add("is-bad");
        outboundCard?.classList.remove("is-ok");
      }
    }
    renderAdminAccounts(o.accounts || [], o.adminEmails || []);
    renderAdminForwards(o.aliases || []);
  }

  async function enterAdmin(email) {
    state.email = email || state.email;
    state.isAdmin = true;
    showAdmin();
    try {
      await loadAdminDashboard();
    } catch (e) {
      toast(e.message || "Could not load admin dashboard.");
    }
  }

  async function enterInbox(email) {
    state.email = email || state.email;
    state.mailbox = "INBOX";
    setAccountIdentity(state.email || "");
    const adminDashBtn = document.getElementById("adminDashBtn");
    if (adminDashBtn) adminDashBtn.hidden = !state.isAdmin;
    if (els.listTitle) els.listTitle.textContent = "Inbox";
    showApp();
    if (els.listLoading) els.listLoading.hidden = false;
    if (els.listEmpty) els.listEmpty.hidden = true;
    if (els.messageList) els.messageList.innerHTML = "";
    try {
      await loadMailboxes();
    } catch (e) {
      toast(e.message || "Could not load folders.");
    }
    try {
      await loadMessages();
    } catch (e) {
      if (els.listLoading) els.listLoading.hidden = true;
      if (els.listEmpty) {
        els.listEmpty.hidden = false;
        els.listEmpty.textContent = e.message || "Could not load messages.";
      }
      toast(e.message || "Could not load inbox.");
    }
  }

  async function enterAfterAuth(email, isAdmin) {
    state.isAdmin = Boolean(isAdmin);
    if (isAdmin) await enterAdmin(email);
    else await enterInbox(email);
  }

  async function boot() {
    const status = document.getElementById("bootStatus");
    try {
      if (status) status.textContent = "Loading…";
      const session = await api("/api/auth/session", { timeoutMs: 15000 });
      if (!session.loggedIn) {
        showLogin();
        return;
      }
      await enterAfterAuth(session.email, session.isAdmin);
    } catch (e) {
      showBootError(e.message || "Could not reach True Mail.");
    }
  }

  document.getElementById("bootRetry")?.addEventListener("click", () => {
    const err = document.getElementById("bootError");
    const retry = document.getElementById("bootRetry");
    const status = document.getElementById("bootStatus");
    if (err) err.hidden = true;
    if (retry) retry.hidden = true;
    if (status) status.textContent = "Opening inbox…";
    document.getElementById("bootScreen")?.classList.add("is-open");
    boot();
  });

  document.getElementById("loginForm")?.addEventListener("submit", async (ev) => {
    ev.preventDefault();
    const errorEl = document.getElementById("loginError");
    const btn = document.getElementById("loginBtn");
    const email = document.getElementById("email")?.value?.trim() || "";
    const password = document.getElementById("password")?.value || "";
    if (errorEl) {
      errorEl.hidden = true;
      errorEl.textContent = "";
    }
    if (!email || !password) {
      if (errorEl) {
        errorEl.hidden = false;
        errorEl.textContent = "Enter email and password.";
      }
      return;
    }
    if (btn) {
      btn.disabled = true;
      btn.textContent = "Signing in…";
    }
    try {
      const data = await api("/api/auth/login", {
        method: "POST",
        timeoutMs: 30000,
        body: JSON.stringify({ email, password }),
      });
      if (btn) btn.textContent = "Opening…";
      document.getElementById("password").value = "";
      hideLogin();
      document.getElementById("bootScreen")?.classList.add("is-open");
      const status = document.getElementById("bootStatus");
      if (status) status.textContent = data.isAdmin ? "Opening admin dashboard…" : "Opening inbox…";
      await enterAfterAuth(data.email || email, data.isAdmin);
    } catch (e) {
      if (errorEl) {
        errorEl.hidden = false;
        errorEl.textContent = e.message || "Sign in failed.";
      }
    } finally {
      if (btn) {
        btn.disabled = false;
        btn.textContent = "Sign in";
      }
    }
  });

  document.getElementById("composeBtn")?.addEventListener("click", () => openCompose());
  document.getElementById("closeComposeBtn")?.addEventListener("click", closeCompose);
  document.getElementById("discardComposeBtn")?.addEventListener("click", closeCompose);
  els.composeModal?.addEventListener("click", (ev) => {
    if (ev.target === els.composeModal) closeCompose(ev);
  });
  document.getElementById("openSidebarBtn")?.addEventListener("click", openSidebar);
  document.getElementById("backToListBtn")?.addEventListener("click", () => clearRead());
  els.sidebarBackdrop?.addEventListener("click", closeSidebar);

  document.getElementById("refreshBtn")?.addEventListener("click", async () => {
    try {
      await loadMessages();
      toast("Inbox refreshed");
    } catch (e) {
      toast(e.message);
    }
  });

  document.getElementById("logoutBtn")?.addEventListener("click", async () => {
    closeAccountMenus();
    try {
      await api("/api/auth/logout", { method: "POST" });
    } catch (_) {
      /* ignore */
    }
    state.email = null;
    state.messages = [];
    state.mailboxes = [];
    state.selected = null;
    state.selectedUid = null;
    if (els.messageList) els.messageList.innerHTML = "";
    if (els.folderNav) els.folderNav.innerHTML = "";
    closeCompose();
    clearRead();
    showLogin();
  });

  els.searchInput?.addEventListener("input", () => {
    state.query = els.searchInput.value || "";
    renderList();
  });

  els.composeForm?.addEventListener("submit", async (ev) => {
    ev.preventDefault();
    if (els.composeError) {
      els.composeError.hidden = true;
      els.composeError.textContent = "";
    }
    const sendBtn = document.getElementById("sendBtn");
    if (sendBtn) {
      sendBtn.disabled = true;
      sendBtn.textContent = "Sending…";
    }
    sendAbort = new AbortController();
    const thisAbort = sendAbort;
    try {
      await api("/api/messages/send", {
        method: "POST",
        timeoutMs: 60000,
        signal: thisAbort.signal,
        body: JSON.stringify({
          to: document.getElementById("composeTo").value,
          cc: document.getElementById("composeCc").value,
          subject: document.getElementById("composeSubject").value,
          text: document.getElementById("composeBody").value,
        }),
      });
      sendAbort = null;
      closeCompose();
      toast("Message sent");
      const sent = findSpecial("\\Sent");
      if (sent && state.mailbox === sent) await loadMessages();
    } catch (e) {
      const discarded =
        e &&
        e.name === "AbortError" &&
        (!els.composeModal?.classList.contains("is-open") || sendAbort !== thisAbort);
      if (discarded) return;
      if (els.composeError) {
        els.composeError.hidden = false;
        els.composeError.textContent = e.message || "Send failed.";
      }
      toast(e.message || "Send failed.");
    } finally {
      if (sendAbort === thisAbort) sendAbort = null;
      if (sendBtn && els.composeModal?.classList.contains("is-open")) {
        sendBtn.disabled = false;
        sendBtn.textContent = "Send";
      }
    }
  });

  document.getElementById("replyBtn")?.addEventListener("click", () => {
    if (!state.selected) return;
    const from = state.selected.from || "";
    const addr = (from.match(/<([^>]+)>/) || [])[1] || from;
    const subj = state.selected.subject || "";
    openCompose({
      to: addr,
      subject: /^re:/i.test(subj) ? subj : `Re: ${subj}`,
      text: `\n\nOn ${state.selected.date || ""}, ${from} wrote:\n${state.selected.text || ""}`,
    });
  });

  document.getElementById("starBtn")?.addEventListener("click", async () => {
    if (!state.selected) return;
    const flagged = Boolean(state.selected.flagged);
    try {
      await api(`/api/messages/${state.selected.uid}/flags`, {
        method: "POST",
        body: JSON.stringify({
          mailbox: state.mailbox,
          add: flagged ? [] : ["\\Flagged"],
          remove: flagged ? ["\\Flagged"] : [],
        }),
      });
      state.selected.flagged = !flagged;
      const row = state.messages.find((m) => m.uid === state.selected.uid);
      if (row) row.flagged = !flagged;
      if (els.starBtn) {
        els.starBtn.title = state.selected.flagged ? "Unstar" : "Star";
        els.starBtn.style.color = state.selected.flagged ? "#f4b400" : "";
      }
      renderList();
    } catch (e) {
      toast(e.message);
    }
  });

  document.getElementById("archiveBtn")?.addEventListener("click", async () => {
    if (!state.selected) return;
    const archive = findSpecial("\\Archive") || "Archive";
    try {
      await api(`/api/messages/${state.selected.uid}/move`, {
        method: "POST",
        body: JSON.stringify({ from: state.mailbox, to: archive }),
      });
      state.messages = state.messages.filter((m) => m.uid !== state.selected.uid);
      clearRead();
      renderList();
      toast("Archived");
    } catch (e) {
      toast(e.message);
    }
  });

  document.getElementById("deleteBtn")?.addEventListener("click", async () => {
    if (!state.selected) return;
    try {
      await api(`/api/messages/${state.selected.uid}?mailbox=${encodeURIComponent(state.mailbox)}`, {
        method: "DELETE",
      });
      state.messages = state.messages.filter((m) => m.uid !== state.selected.uid);
      clearRead();
      renderList();
      toast("Deleted");
    } catch (e) {
      toast(e.message);
    }
  });

  // Back gesture on mobile: leaving read view
  window.addEventListener("keydown", (ev) => {
    if (ev.key === "Escape") {
      if (els.composeModal.classList.contains("is-open")) closeCompose(ev);
      else if (els.app.classList.contains("show-read")) clearRead();
    }
  });

  document.getElementById("adminOpenInboxBtn")?.addEventListener("click", async () => {
    hideAdmin();
    document.getElementById("bootScreen")?.classList.add("is-open");
    const status = document.getElementById("bootStatus");
    if (status) status.textContent = "Opening inbox…";
    try {
      await enterInbox(state.email);
    } catch (e) {
      showBootError(e.message || "Could not open inbox.");
    }
  });

  document.getElementById("adminDashBtn")?.addEventListener("click", async () => {
    closeAccountMenus();
    try {
      await enterAdmin(state.email);
    } catch (e) {
      toast(e.message || "Could not open admin.");
    }
  });

  document.getElementById("adminLogoutBtn")?.addEventListener("click", async () => {
    closeAccountMenus();
    try {
      await api("/api/auth/logout", { method: "POST" });
    } catch (_) {
      /* ignore */
    }
    state.email = null;
    state.isAdmin = false;
    hideAdmin();
    showLogin();
  });

  document.getElementById("adminRefreshAccounts")?.addEventListener("click", async () => {
    try {
      await loadAdminDashboard();
      toast("Accounts refreshed");
    } catch (e) {
      toast(e.message || "Refresh failed");
    }
  });

  document.getElementById("adminRefreshAliases")?.addEventListener("click", async () => {
    try {
      await loadAdminDashboard();
      toast("Forwards refreshed");
    } catch (e) {
      toast(e.message || "Refresh failed");
    }
  });

  document.getElementById("adminCreateForm")?.addEventListener("submit", async (ev) => {
    ev.preventDefault();
    const err = document.getElementById("adminFormError");
    const ok = document.getElementById("adminFormOk");
    if (err) {
      err.hidden = true;
      err.textContent = "";
    }
    if (ok) ok.hidden = true;
    const email = document.getElementById("adminNewEmail")?.value?.trim() || "";
    const password = document.getElementById("adminNewPass")?.value || "";
    try {
      await api("/api/admin/accounts", {
        method: "POST",
        body: JSON.stringify({ email, password }),
      });
      document.getElementById("adminCreateForm")?.reset();
      if (ok) {
        ok.hidden = false;
        ok.textContent = `Created ${email}`;
      }
      toast("Mailbox created");
      await loadAdminDashboard();
    } catch (e) {
      if (err) {
        err.hidden = false;
        err.textContent = e.message || "Create failed";
      }
    }
  });

  document.getElementById("adminForwardForm")?.addEventListener("submit", async (ev) => {
    ev.preventDefault();
    const err = document.getElementById("adminForwardError");
    const ok = document.getElementById("adminForwardOk");
    if (err) {
      err.hidden = true;
      err.textContent = "";
    }
    if (ok) ok.hidden = true;
    const from = document.getElementById("adminForwardFrom")?.value?.trim() || "";
    const to = document.getElementById("adminForwardTo")?.value?.trim() || "";
    const keepCopy = Boolean(document.getElementById("adminForwardKeepCopy")?.checked);
    try {
      await api("/api/admin/aliases", {
        method: "POST",
        body: JSON.stringify({ from, to, keepCopy }),
      });
      document.getElementById("adminForwardForm")?.reset();
      const keep = document.getElementById("adminForwardKeepCopy");
      if (keep) keep.checked = false;
      if (ok) {
        ok.hidden = false;
        ok.textContent = `Forward created: ${from} → ${to}`;
      }
      toast("Forward created");
      await loadAdminDashboard();
    } catch (e) {
      if (err) {
        err.hidden = false;
        err.textContent = e.message || "Could not create forward";
      }
    }
  });

  boot();
})();
