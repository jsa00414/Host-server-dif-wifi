/**
 * Per-device Surfshark / Tailscale exit UI for Authenticator (keys.*).
 * Expects markup ids: netControlIp, netMeta, netDeviceRow, netDevicePick,
 * netDeviceManual, netUseDeviceBtn, netChoices, netSsServer, netBtnTs,
 * netBtnSs, netBtnDirect. Optional toast via opts.toast(msg, err?).
 */
(function (global) {
  "use strict";

  const LAST_IP_KEY = "sm.network.deviceIp.v1";
  const TOTP_STORE_KEY = "sm.auth.totp.v1";
  const TOTP_PERIOD = 30;
  const TOTP_DIGITS = 6;
  const LAN_RE = /^192\.168\.8\.(?:[2-9]|\d{2}|1\d{2}|2[0-4]\d|25[0-4])$/;
  // OpenVPN CCD clients (not server .1 / Flint .2)
  const OVPN_RE = /^10\.9\.0\.(?:[3-9]|[1-9]\d|1\d{2}|2[0-4]\d|25[0-4])$/;

  function $(id) {
    return document.getElementById(id);
  }

  function isHomeLanIp(ip) {
    return LAN_RE.test(String(ip || "").trim());
  }

  function isExitDeviceIp(ip) {
    const s = String(ip || "").trim();
    return LAN_RE.test(s) || OVPN_RE.test(s);
  }

  function loadTotpAccount() {
    try {
      const raw = localStorage.getItem(TOTP_STORE_KEY);
      if (!raw) return null;
      const data = JSON.parse(raw);
      const secret = String(data?.secret || "").replace(/\s+/g, "").toUpperCase();
      return secret ? { secret } : null;
    } catch (_) {
      return null;
    }
  }

  function b32Decode(secret) {
    const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
    let bits = "";
    const cleaned = String(secret || "").replace(/=+$/, "").toUpperCase();
    for (const ch of cleaned) {
      const val = alphabet.indexOf(ch);
      if (val < 0) continue;
      bits += val.toString(2).padStart(5, "0");
    }
    const bytes = [];
    for (let i = 0; i + 8 <= bits.length; i += 8) {
      bytes.push(parseInt(bits.slice(i, i + 8), 2));
    }
    return new Uint8Array(bytes);
  }

  async function hmacSha1(keyBytes, msgBytes) {
    const key = await crypto.subtle.importKey(
      "raw",
      keyBytes,
      { name: "HMAC", hash: "SHA-1" },
      false,
      ["sign"]
    );
    return new Uint8Array(await crypto.subtle.sign("HMAC", key, msgBytes));
  }

  async function totpAt(secret, forTime = Date.now() / 1000) {
    const counter = Math.floor(forTime / TOTP_PERIOD);
    const msg = new Uint8Array(8);
    let n = counter;
    for (let i = 7; i >= 0; i--) {
      msg[i] = n & 0xff;
      n = Math.floor(n / 256);
    }
    const digest = await hmacSha1(b32Decode(secret), msg);
    const offset = digest[digest.length - 1] & 0x0f;
    const codeInt =
      ((digest[offset] & 0x7f) << 24) |
      ((digest[offset + 1] & 0xff) << 16) |
      ((digest[offset + 2] & 0xff) << 8) |
      (digest[offset + 3] & 0xff);
    return String(codeInt % 10 ** TOTP_DIGITS).padStart(TOTP_DIGITS, "0");
  }

  function circleStoreIps() {
    try {
      const store = (global.SmCircleCrypto && SmCircleCrypto.loadStore()) || {};
      return Object.keys(store)
        .filter(isExitDeviceIp)
        .sort((a, b) => {
          const ca = Number(store[a]?.createdAt || 0);
          const cb = Number(store[b]?.createdAt || 0);
          return cb - ca;
        });
    } catch (_) {
      return [];
    }
  }

  function circleStoreLanIps() {
    return circleStoreIps().filter(isHomeLanIp);
  }

  /**
   * Prefer an exact key for the claim IP; otherwise reuse any local key so
   * OpenVPN 10.9.0.x can prove with the home Wi‑Fi key that shares the same
   * server-side pubkey binding.
   */
  async function resolveKeyRowForClaim(claimIp) {
    if (!global.SmCircleCrypto?.getKeyForIp) return null;
    const direct = await SmCircleCrypto.getKeyForIp(claimIp);
    if (direct?.privateJwk && direct?.publicKey) return direct;
    try {
      const store = SmCircleCrypto.loadStore() || {};
      const rows = Object.entries(store)
        .filter(([, row]) => row?.privateJwk && row?.publicKey)
        .sort((a, b) => {
          const aLan = isHomeLanIp(a[0]) ? 1 : 0;
          const bLan = isHomeLanIp(b[0]) ? 1 : 0;
          if (aLan !== bLan) return bLan - aLan;
          return Number(b[1]?.createdAt || 0) - Number(a[1]?.createdAt || 0);
        });
      return rows[0]?.[1] || null;
    } catch (_) {
      return null;
    }
  }

  function extractLanFromText(text) {
    const found = [];
    const re = /\b(192\.168\.8\.(?:[2-9]|\d{2}|1\d{2}|2[0-4]\d|25[0-4]))\b/g;
    let m;
    while ((m = re.exec(String(text || "")))) {
      if (!found.includes(m[1])) found.push(m[1]);
    }
    return found;
  }

  async function detectHomeLanIpViaWebRtc() {
    return await new Promise((resolve) => {
      let done = false;
      let pc;
      const finish = (ip) => {
        if (done) return;
        done = true;
        try {
          pc && pc.close();
        } catch (_) {}
        resolve(ip || "");
      };
      const timer = setTimeout(() => finish(""), 1800);
      try {
        pc = new RTCPeerConnection({ iceServers: [] });
        pc.createDataChannel("x");
        pc.onicecandidate = (ev) => {
          const cand = ev.candidate && ev.candidate.candidate;
          if (!cand) return;
          const ips = extractLanFromText(cand);
          if (ips.length) {
            clearTimeout(timer);
            finish(ips[0]);
          }
        };
        pc.createOffer()
          .then((o) => pc.setLocalDescription(o))
          .catch(() => {
            clearTimeout(timer);
            finish("");
          });
      } catch (_) {
        clearTimeout(timer);
        finish("");
      }
    });
  }

  function create(opts) {
    const toast = typeof opts?.toast === "function" ? opts.toast : () => {};
    const onBusy = typeof opts?.onBusy === "function" ? opts.onBusy : () => {};
    const els = {
      controlIp: $("netControlIp"),
      meta: $("netMeta"),
      deviceRow: $("netDeviceRow"),
      devicePick: $("netDevicePick"),
      deviceManual: $("netDeviceManual"),
      useDeviceBtn: $("netUseDeviceBtn"),
      choices: $("netChoices"),
      ssServer: $("netSsServer"),
      btnTs: $("netBtnTs"),
      btnSs: $("netBtnSs"),
      btnDirect: $("netBtnDirect"),
    };
    if (!els.controlIp || !els.choices) {
      return { refresh: async () => {}, open: async () => {} };
    }

    let state = null;
    let lanIp = "";
    let wired = false;
    let picking = false; // ignore select rebuild side-effects
    let userPicked = false;

    function rememberIp(ip) {
      if (!isExitDeviceIp(ip)) return;
      try {
        localStorage.setItem(LAST_IP_KEY, ip);
      } catch (_) {}
    }

    function rememberedIp() {
      try {
        const ip = localStorage.getItem(LAST_IP_KEY) || "";
        return isExitDeviceIp(ip) ? ip : "";
      } catch (_) {
        return "";
      }
    }

    async function currentTotpCode() {
      const account = loadTotpAccount();
      if (!account?.secret) return "";
      return totpAt(account.secret);
    }

    function candidateEntries() {
      const byIp = new Map();
      const add = (ip, label) => {
        if (!isExitDeviceIp(ip)) return;
        const prev = byIp.get(ip);
        byIp.set(ip, {
          ip,
          label: (label && label !== ip ? label : null) || prev?.label || ip,
        });
      };
      const member = !!(state?.circle_member || state?.circle_ok);
      if (member) {
        for (const row of state?.candidate_ips || []) {
          add(row.ip, row.label || row.ip);
        }
      }
      for (const ip of circleStoreIps()) add(ip, ip);
      return [...byIp.values()].sort((a, b) =>
        String(a.label).localeCompare(String(b.label))
      );
    }

    function fillDevicePicker(selected) {
      const opts = candidateEntries();
      const member = !!(state?.circle_member || state?.circle_ok);
      if (els.deviceRow) els.deviceRow.hidden = !(member || opts.length || selected);
      if (!els.devicePick) return;
      picking = true;
      try {
        if (!opts.length) {
          els.devicePick.innerHTML = member
            ? `<option value="">No circle devices yet</option>`
            : `<option value="">Authenticator required…</option>`;
        } else {
          els.devicePick.innerHTML =
            `<option value="">Select this device’s IP…</option>` +
            opts
              .map((row) => {
                const text =
                  row.label && row.label !== row.ip
                    ? `${row.label} — ${row.ip}`
                    : row.ip;
                return `<option value="${row.ip}" ${
                  row.ip === selected ? "selected" : ""
                }>${text}</option>`;
              })
              .join("");
        }
        if (selected && isExitDeviceIp(selected)) {
          els.devicePick.value = selected;
        }
      } finally {
        // iOS can fire change when options are replaced; ignore one tick.
        setTimeout(() => {
          picking = false;
        }, 0);
      }
      if (els.deviceManual && selected && isExitDeviceIp(selected)) {
        els.deviceManual.value = selected;
      }
      if (els.useDeviceBtn) els.useDeviceBtn.disabled = !(member || opts.length);
    }

    function renderUi() {
      if (!state) return;
      const ip =
        (state.circle_ok && state.control_ip) ||
        (userPicked && lanIp) ||
        state.control_ip ||
        "";
      const needsCircle = !!(
        state.needs_circle &&
        !state.circle_member &&
        !state.circle_ok
      );
      els.controlIp.textContent = ip
        || (needsCircle ? "circle required" : "pick this device");
      const bits = [];
      if (needsCircle) {
        bits.push("Unlock Authenticator on this phone first");
      } else {
        if (state.via_flint) bits.push("via Flint VPN");
        if (state.client_ip && state.client_ip !== ip) {
          bits.push(`connection ${state.client_ip}`);
        }
        if (state.lan_ip && state.lan_ip !== ip) bits.push(`LAN ${state.lan_ip}`);
        if (state.provider_label && state.circle_ok) {
          bits.push(`now: ${state.provider_label}`);
        }
        if (state.global_exit) bits.push(`default: ${state.global_exit}`);
        if (state.needs_device_ip && !state.circle_ok) {
          bits.push("pick this device’s home Wi‑Fi or OpenVPN IP");
        }
      }
      if (els.meta) els.meta.textContent = bits.join(" · ") || "Ready";
      fillDevicePicker(ip || lanIp);

      const prov = String(state.provider || "direct");
      els.btnTs?.classList.toggle("active", prov === "tailscale");
      els.btnTs?.classList.toggle("ts", prov === "tailscale");
      els.btnSs?.classList.toggle("active", prov === "surfshark");
      els.btnDirect?.classList.toggle(
        "active",
        prov === "direct" || prov === "clear" || !prov
      );

      const servers = state.surfshark_servers || [];
      if (els.ssServer) {
        if (servers.length) {
          els.ssServer.hidden = false;
          const cur = state.surfshark_server || servers[0].id;
          els.ssServer.innerHTML = servers
            .map(
              (s) =>
                `<option value="${s.id}" ${s.id === cur ? "selected" : ""}>${
                  s.label || s.id
                }</option>`
            )
            .join("");
        } else {
          els.ssServer.hidden = true;
        }
      }

      const canAct = !!(state.circle_ok && state.control_ip);
      els.choices.classList.toggle("busy", !canAct);
    }

    async function exitHeaders(extra, bodyText) {
      const headers = { Accept: "application/json", ...(extra || {}) };
      if (lanIp) headers["X-SM-Lan-Ip"] = lanIp;
      try {
        const code = await currentTotpCode();
        if (code) headers["X-SM-Totp"] = code;
      } catch (_) {}
      try {
        if (lanIp && global.SmCircleCrypto) {
          const row = await resolveKeyRowForClaim(lanIp);
          if (row?.publicKey && row?.privateJwk) {
            const method = headers["Content-Type"] ? "POST" : "GET";
            const proof = SmCircleCrypto.circleHeadersWithRow
              ? await SmCircleCrypto.circleHeadersWithRow(lanIp, row, {
                  method,
                  path: "/api/network/exit",
                  bodyText: bodyText || "",
                })
              : await SmCircleCrypto.circleHeaders(lanIp, {
                  method,
                  path: "/api/network/exit",
                  bodyText: bodyText || "",
                });
            Object.assign(headers, proof);
          }
        }
      } catch (_) {}
      return headers;
    }

    async function refresh() {
      const headers = await exitHeaders();
      const res = await fetch("/api/network/exit", { headers, cache: "no-store" });
      const data = await res.json().catch(() => ({}));
      if (!res.ok || data.ok === false) {
        throw new Error(data.error || `HTTP ${res.status}`);
      }
      state = data;
      if (data.control_ip && isExitDeviceIp(data.control_ip) && data.circle_ok) {
        lanIp = data.control_ip;
        rememberIp(lanIp);
      }
      renderUi();
      return state;
    }

    async function applyChosenDeviceIp(ip) {
      if (!isExitDeviceIp(ip)) {
        toast("Choose a circle device IP (192.168.8.x or OpenVPN 10.9.0.x)", true);
        return;
      }
      const keyRow = await resolveKeyRowForClaim(ip);
      const hasLocalKey = !!(keyRow?.privateJwk && keyRow?.publicKey);
      const hasTotp = !!loadTotpAccount()?.secret;
      if (!hasLocalKey && !hasTotp) {
        toast("Unlock Authenticator first", true);
        return;
      }
      userPicked = true;
      lanIp = ip;
      rememberIp(ip);
      if (els.devicePick) els.devicePick.value = ip;
      if (els.deviceManual) els.deviceManual.value = ip;
      await refresh();
      if (state?.circle_ok && state?.control_ip === ip) {
        toast(`Controlling ${ip}`);
      } else if (state?.needs_circle && !state?.circle_member) {
        toast(state.error || "Circle proof failed", true);
      } else if (state?.circle_member && !state?.circle_ok) {
        toast(state.error || "Could not prove that IP — unlock and retry", true);
      } else if (!state?.circle_ok) {
        toast(state?.error || "Could not control that IP", true);
      }
    }

    async function setProvider(provider) {
      if (!lanIp && !state?.control_ip) {
        toast("Pick this device’s Wi‑Fi or OpenVPN IP first", true);
        return;
      }
      els.choices.classList.add("busy");
      onBusy(true);
      try {
        const body = {
          provider,
          lan_ip: lanIp || state.control_ip || undefined,
        };
        if (provider === "surfshark" && els.ssServer?.value) {
          body.server = els.ssServer.value;
        }
        if (provider === "tailscale" && state?.tailscale_exit_ip) {
          body.exit_ip = state.tailscale_exit_ip;
        }
        const bodyText = JSON.stringify(body);
        const headers = await exitHeaders(
          { "Content-Type": "application/json" },
          bodyText
        );
        if (!headers["X-SM-Circle-Sig"] && !headers["X-SM-Totp"]) {
          throw new Error("Unlock Authenticator, then retry");
        }
        const res = await fetch("/api/network/exit", {
          method: "POST",
          headers,
          body: bodyText,
        });
        const data = await res.json().catch(() => ({}));
        if (!res.ok || data.ok === false) {
          throw new Error(data.error || `HTTP ${res.status}`);
        }
        state = data;
        if (data.control_ip && isExitDeviceIp(data.control_ip)) {
          lanIp = data.control_ip;
          rememberIp(lanIp);
          userPicked = true;
        }
        renderUi();
        toast(data.message || `Set ${provider}`);
      } catch (err) {
        toast(String(err?.message || err), true);
      } finally {
        els.choices.classList.remove("busy");
        onBusy(false);
        renderUi();
      }
    }

    function wireOnce() {
      if (wired) return;
      wired = true;
      if (els.devicePick) {
        els.devicePick.onchange = async () => {
          if (picking) return;
          const ip = els.devicePick.value;
          if (!isExitDeviceIp(ip)) return;
          if (els.deviceManual) els.deviceManual.value = ip;
          try {
            await applyChosenDeviceIp(ip);
          } catch (err) {
            toast(String(err?.message || err), true);
          }
        };
      }
      if (els.useDeviceBtn) {
        els.useDeviceBtn.onclick = async () => {
          const typed = String(els.deviceManual?.value || "").trim();
          const picked = String(els.devicePick?.value || "").trim();
          try {
            await applyChosenDeviceIp(typed || picked);
          } catch (err) {
            toast(String(err?.message || err), true);
          }
        };
      }
      if (els.btnTs) els.btnTs.onclick = () => setProvider("tailscale");
      if (els.btnSs) els.btnSs.onclick = () => setProvider("surfshark");
      if (els.btnDirect) els.btnDirect.onclick = () => setProvider("direct");
    }

    async function open() {
      wireOnce();
      state = {
        hosts: { keys: "keys.vpstruelord.com" },
        needs_circle: true,
        circle_ok: false,
        circle_member: false,
        candidate_ips: [],
      };
      renderUi();
      try {
        // Keep an explicit user pick across Exit tab revisits.
        if (userPicked && isExitDeviceIp(lanIp)) {
          await refresh();
          if (!state?.circle_ok) await applyChosenDeviceIp(lanIp);
          return;
        }
        await refresh();
        const allowed = new Set(
          (state?.candidate_ips || []).map((r) => r.ip).filter(isExitDeviceIp)
        );
        for (const ip of circleStoreIps()) allowed.add(ip);
        const webrtc = await detectHomeLanIpViaWebRtc();
        let best = "";
        if (isHomeLanIp(webrtc) && (!allowed.size || allowed.has(webrtc))) {
          best = webrtc;
        } else if (rememberedIp() && (!allowed.size || allowed.has(rememberedIp()))) {
          best = rememberedIp();
        } else if (state?.client_ip && allowed.has(state.client_ip)) {
          best = state.client_ip;
        } else {
          const local = circleStoreIps().filter(
            (ip) => !allowed.size || allowed.has(ip)
          );
          if (local.length) best = local[0];
          else if (allowed.size === 1) best = [...allowed][0];
        }
        if (best) {
          await applyChosenDeviceIp(best);
        } else if (state?.circle_member && !state?.circle_ok) {
          toast("Pick this device’s home Wi‑Fi or OpenVPN IP", false);
        }
      } catch (err) {
        if (els.controlIp) els.controlIp.textContent = "unavailable";
        if (els.meta) els.meta.textContent = String(err?.message || err);
        toast(String(err?.message || err), true);
      }
    }

    return { refresh, open, render: renderUi };
  }

  global.SmNetworkExit = { create, isHomeLanIp, isExitDeviceIp };
})(typeof window !== "undefined" ? window : globalThis);
