#!/usr/bin/env python3
"""
Caddy Domain Manager — VPN-only web UI for managing reverse-proxy sites.
Accessible only from WireGuard-connected devices via Caddy IP restrictions.
"""

import json
import os
import re
import subprocess
from datetime import datetime, timezone
from pathlib import Path

from flask import Flask, jsonify, render_template_string, request, abort

app = Flask(__name__)

DOMAINS_DIR = Path(os.environ.get("DOMAINS_DIR", "/domains"))
CADDY_CONTAINER = os.environ.get("CADDY_CONTAINER", "caddy")
ADMIN_TOKEN = os.environ.get("ADMIN_TOKEN", "")
VPN_SUBNET = os.environ.get("VPN_SUBNET", "10.8.0.0/24")
DATA_DIR = Path("/data")
INDEX_FILE = DATA_DIR / "domains.json"

DOMAIN_PATTERN = re.compile(
    r"^[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?)*$"
)


def ensure_dirs():
    DOMAINS_DIR.mkdir(parents=True, exist_ok=True)
    DATA_DIR.mkdir(parents=True, exist_ok=True)
    if not INDEX_FILE.exists():
        INDEX_FILE.write_text("[]")


def load_domains():
    ensure_dirs()
    if INDEX_FILE.exists():
        return json.loads(INDEX_FILE.read_text())
    return []


def save_domains(domains):
    ensure_dirs()
    INDEX_FILE.write_text(json.dumps(domains, indent=2))


def caddy_file_for(domain: str, upstream: str, tls_mode: str = "auto") -> str:
    tls_line = ""
    if tls_mode == "internal":
        tls_line = "\n\ttls internal"
    elif tls_mode == "off":
        tls_line = "\n\ttls off"

    return f"""# Managed by Domain Manager — {domain}
{domain} {{
\treverse_proxy {upstream}{tls_line}
}}
"""


def reload_caddy():
    result = subprocess.run(
        ["docker", "exec", CADDY_CONTAINER, "caddy", "reload", "--config", "/etc/caddy/Caddyfile"],
        capture_output=True,
        text=True,
    )
    if result.returncode != 0:
        raise RuntimeError(result.stderr or result.stdout or "Caddy reload failed")


def require_auth():
    if not ADMIN_TOKEN:
        return
    token = request.headers.get("X-Admin-Token") or request.args.get("token")
    if token != ADMIN_TOKEN:
        abort(401, description="Invalid admin token")


HTML = """<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>Caddy Domain Manager</title>
  <style>
    :root {
      --bg: #0f1419;
      --surface: #1a2332;
      --border: #2d3a4f;
      --text: #e7ecf3;
      --muted: #8b9cb3;
      --accent: #3b82f6;
      --accent-hover: #2563eb;
      --danger: #ef4444;
      --success: #22c55e;
    }
    * { box-sizing: border-box; margin: 0; padding: 0; }
    body {
      font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
      background: var(--bg);
      color: var(--text);
      min-height: 100vh;
      line-height: 1.5;
    }
    header {
      background: var(--surface);
      border-bottom: 1px solid var(--border);
      padding: 1.25rem 2rem;
    }
    header h1 { font-size: 1.35rem; font-weight: 600; }
    header p { color: var(--muted); font-size: 0.875rem; margin-top: 0.25rem; }
    main { max-width: 960px; margin: 0 auto; padding: 2rem; }
    .card {
      background: var(--surface);
      border: 1px solid var(--border);
      border-radius: 12px;
      padding: 1.5rem;
      margin-bottom: 1.5rem;
    }
    .card h2 { font-size: 1.1rem; margin-bottom: 1rem; }
    label { display: block; font-size: 0.875rem; color: var(--muted); margin-bottom: 0.35rem; }
    input, select {
      width: 100%;
      padding: 0.65rem 0.85rem;
      background: var(--bg);
      border: 1px solid var(--border);
      border-radius: 8px;
      color: var(--text);
      font-size: 0.95rem;
      margin-bottom: 1rem;
    }
    input:focus, select:focus { outline: 2px solid var(--accent); border-color: transparent; }
    .row { display: grid; grid-template-columns: 1fr 1fr; gap: 1rem; }
    @media (max-width: 640px) { .row { grid-template-columns: 1fr; } }
    button {
      background: var(--accent);
      color: white;
      border: none;
      border-radius: 8px;
      padding: 0.7rem 1.25rem;
      font-size: 0.95rem;
      font-weight: 500;
      cursor: pointer;
    }
    button:hover { background: var(--accent-hover); }
    button.danger { background: var(--danger); }
    button.danger:hover { background: #dc2626; }
    button.small { padding: 0.4rem 0.75rem; font-size: 0.8rem; }
    .domain-list { list-style: none; }
    .domain-item {
      display: flex;
      align-items: center;
      justify-content: space-between;
      padding: 0.85rem 0;
      border-bottom: 1px solid var(--border);
    }
    .domain-item:last-child { border-bottom: none; }
    .domain-info strong { display: block; }
    .domain-info span { font-size: 0.8rem; color: var(--muted); }
    .badge {
      display: inline-block;
      font-size: 0.7rem;
      padding: 0.15rem 0.5rem;
      border-radius: 999px;
      background: rgba(34, 197, 94, 0.15);
      color: var(--success);
      margin-left: 0.5rem;
    }
    .alert {
      padding: 0.75rem 1rem;
      border-radius: 8px;
      margin-bottom: 1rem;
      font-size: 0.875rem;
    }
    .alert-info { background: rgba(59, 130, 246, 0.12); color: #93c5fd; }
    .alert-error { background: rgba(239, 68, 68, 0.12); color: #fca5a5; }
    .empty { color: var(--muted); text-align: center; padding: 2rem; }
    #status { display: none; }
  </style>
</head>
<body>
  <header>
    <h1>Caddy Domain Manager</h1>
    <p>Manage reverse-proxy domains from your WireGuard-connected device · VPN subnet: {{ vpn_subnet }}</p>
  </header>
  <main>
    <div id="status"></div>

    <div class="card">
      <h2>Add Domain</h2>
      <div class="alert alert-info">
        Point your domain's DNS A record to this VPS, then add a reverse-proxy entry below.
        Changes reload Caddy automatically.
      </div>
      <form id="addForm">
        <div class="row">
          <div>
            <label for="domain">Domain name</label>
            <input id="domain" name="domain" placeholder="app.example.com" required>
          </div>
          <div>
            <label for="upstream">Upstream target</label>
            <input id="upstream" name="upstream" placeholder="192.168.1.10:8080" required>
          </div>
        </div>
        <div class="row">
          <div>
            <label for="tls_mode">TLS mode</label>
            <select id="tls_mode" name="tls_mode">
              <option value="auto">Automatic (Let's Encrypt)</option>
              <option value="internal">Internal CA</option>
              <option value="off">Off (HTTP only)</option>
            </select>
          </div>
          <div style="display:flex;align-items:flex-end;">
            <button type="submit">Deploy Domain</button>
          </div>
        </div>
      </form>
    </div>

    <div class="card">
      <h2>Deployed Domains</h2>
      <ul class="domain-list" id="domainList">
        <li class="empty">Loading...</li>
      </ul>
    </div>
  </main>

  <script>
    const token = new URLSearchParams(window.location.search).get('token') || localStorage.getItem('adminToken') || '';
    if (token) localStorage.setItem('adminToken', token);

    function headers() {
      const h = { 'Content-Type': 'application/json' };
      if (token) h['X-Admin-Token'] = token;
      return h;
    }

    function showStatus(msg, isError) {
      const el = document.getElementById('status');
      el.className = 'alert ' + (isError ? 'alert-error' : 'alert-info');
      el.textContent = msg;
      el.style.display = 'block';
      setTimeout(() => { el.style.display = 'none'; }, 5000);
    }

    async function loadDomains() {
      const res = await fetch('/api/domains', { headers: headers() });
      const data = await res.json();
      const list = document.getElementById('domainList');
      if (!data.length) {
        list.innerHTML = '<li class="empty">No domains deployed yet.</li>';
        return;
      }
      list.innerHTML = data.map(d => `
        <li class="domain-item">
          <div class="domain-info">
            <strong>${d.domain} <span class="badge">${d.tls_mode}</span></strong>
            <span>→ ${d.upstream} · ${d.created_at}</span>
          </div>
          <button class="danger small" onclick="removeDomain('${d.domain}')">Remove</button>
        </li>
      `).join('');
    }

    document.getElementById('addForm').addEventListener('submit', async (e) => {
      e.preventDefault();
      const body = {
        domain: document.getElementById('domain').value.trim(),
        upstream: document.getElementById('upstream').value.trim(),
        tls_mode: document.getElementById('tls_mode').value
      };
      const res = await fetch('/api/domains', { method: 'POST', headers: headers(), body: JSON.stringify(body) });
      const data = await res.json();
      if (!res.ok) { showStatus(data.error || 'Failed to add domain', true); return; }
      showStatus('Domain deployed and Caddy reloaded.');
      document.getElementById('addForm').reset();
      loadDomains();
    });

    async function removeDomain(domain) {
      if (!confirm('Remove ' + domain + '?')) return;
      const res = await fetch('/api/domains/' + encodeURIComponent(domain), { method: 'DELETE', headers: headers() });
      const data = await res.json();
      if (!res.ok) { showStatus(data.error || 'Failed to remove domain', true); return; }
      showStatus('Domain removed and Caddy reloaded.');
      loadDomains();
    }

    loadDomains();
  </script>
</body>
</html>"""


@app.route("/")
def index():
    return render_template_string(HTML, vpn_subnet=VPN_SUBNET)


@app.route("/api/domains", methods=["GET"])
def list_domains():
    require_auth()
    return jsonify(load_domains())


@app.route("/api/domains", methods=["POST"])
def add_domain():
    require_auth()
    data = request.get_json(force=True)
    domain = (data.get("domain") or "").strip().lower()
    upstream = (data.get("upstream") or "").strip()
    tls_mode = data.get("tls_mode", "auto")

    if not domain or not DOMAIN_PATTERN.match(domain):
        return jsonify({"error": "Invalid domain name"}), 400
    if not upstream:
        return jsonify({"error": "Upstream target is required"}), 400
    if tls_mode not in ("auto", "internal", "off"):
        return jsonify({"error": "Invalid TLS mode"}), 400

    domains = load_domains()
    if any(d["domain"] == domain for d in domains):
        return jsonify({"error": "Domain already exists"}), 409

    caddy_path = DOMAINS_DIR / f"{domain.replace('.', '_')}.caddy"
    caddy_path.write_text(caddy_file_for(domain, upstream, tls_mode))

    entry = {
        "domain": domain,
        "upstream": upstream,
        "tls_mode": tls_mode,
        "created_at": datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC"),
    }
    domains.append(entry)
    save_domains(domains)

    try:
        reload_caddy()
    except RuntimeError as exc:
        caddy_path.unlink(missing_ok=True)
        domains = [d for d in domains if d["domain"] != domain]
        save_domains(domains)
        return jsonify({"error": str(exc)}), 500

    return jsonify(entry), 201


@app.route("/api/domains/<domain>", methods=["DELETE"])
def remove_domain(domain):
    require_auth()
    domain = domain.strip().lower()
    domains = load_domains()
    if not any(d["domain"] == domain for d in domains):
        return jsonify({"error": "Domain not found"}), 404

    caddy_path = DOMAINS_DIR / f"{domain.replace('.', '_')}.caddy"
    caddy_path.unlink(missing_ok=True)

    domains = [d for d in domains if d["domain"] != domain]
    save_domains(domains)

    try:
        reload_caddy()
    except RuntimeError as exc:
        return jsonify({"error": str(exc)}), 500

    return jsonify({"ok": True})


@app.route("/health")
def health():
    return jsonify({"status": "ok"})


if __name__ == "__main__":
    ensure_dirs()
    app.run(host="0.0.0.0", port=8080)
