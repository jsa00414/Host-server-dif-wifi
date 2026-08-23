#!/usr/bin/env python3
"""VPS WireGuard Setup — Windows GUI installer."""

from __future__ import annotations

import sys
import threading
import tkinter as tk
import webbrowser
from tkinter import filedialog, messagebox, scrolledtext, ttk

from deployer import DeployConfig, deploy, test_ssh_connection

APP_TITLE = "VPS WireGuard Setup"
APP_VERSION = "1.0.0"
WG_EASY_VERSION = "15.3.0"
WG_EASY_LICENSE = "AGPL-3.0-only"
WG_EASY_COPYRIGHT = "© 2021-2026 Emile Nijssen"


class SetupApp(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title(f"{APP_TITLE} v{APP_VERSION}")
        self.geometry("720x780")
        self.minsize(640, 680)
        self.configure(bg="#0f1419")

        style = ttk.Style(self)
        style.theme_use("clam")
        style.configure("TNotebook", background="#0f1419", borderwidth=0)
        style.configure("TNotebook.Tab", padding=[14, 8], font=("Segoe UI", 10))
        style.configure("TFrame", background="#0f1419")
        style.configure("TLabel", background="#0f1419", foreground="#e7ecf3", font=("Segoe UI", 10))
        style.configure("Header.TLabel", font=("Segoe UI", 16, "bold"), foreground="#ffffff")
        style.configure("Sub.TLabel", foreground="#8b9cb3", font=("Segoe UI", 9))
        style.configure("TEntry", fieldbackground="#1a2332", foreground="#e7ecf3")
        style.configure("TButton", font=("Segoe UI", 10, "bold"), padding=8)
        style.configure("Deploy.TButton", font=("Segoe UI", 11, "bold"), padding=12)

        self._build_ui()

    def _field(self, parent, label: str, default: str = "", show: str | None = None) -> ttk.Entry:
        ttk.Label(parent, text=label).pack(anchor="w", pady=(8, 2))
        entry = ttk.Entry(parent, width=60, show=show)
        entry.insert(0, default)
        entry.pack(fill="x")
        return entry

    def _build_ui(self):
        header = ttk.Frame(self, padding=16)
        header.pack(fill="x")
        ttk.Label(header, text=APP_TITLE, style="Header.TLabel").pack(anchor="w")
        ttk.Label(
            header,
            text=(
                f"Deploy WireGuard Easy v{WG_EASY_VERSION} + Caddy to your VPS\n"
                f"WireGuard Easy {WG_EASY_COPYRIGHT} — licensed under {WG_EASY_LICENSE}"
            ),
            style="Sub.TLabel",
        ).pack(anchor="w", pady=(4, 0))

        notebook = ttk.Notebook(self, padding=8)
        notebook.pack(fill="both", expand=True, padx=12, pady=(0, 8))

        # --- VPS tab ---
        vps_tab = ttk.Frame(notebook, padding=12)
        notebook.add(vps_tab, text="  VPS Server  ")

        self.vps_host = self._field(vps_tab, "VPS IP address or hostname *", "")
        self.vps_port = self._field(vps_tab, "SSH port", "22")
        self.ssh_user = self._field(vps_tab, "SSH username *", "root")

        ttk.Label(vps_tab, text="SSH password (leave blank if using key)").pack(anchor="w", pady=(8, 2))
        self.ssh_password = ttk.Entry(vps_tab, width=60, show="•")
        self.ssh_password.pack(fill="x")

        key_row = ttk.Frame(vps_tab)
        key_row.pack(fill="x", pady=(8, 0))
        ttk.Label(key_row, text="SSH private key file (.pem / id_rsa)").pack(anchor="w")
        key_inner = ttk.Frame(key_row)
        key_inner.pack(fill="x", pady=(2, 0))
        self.ssh_key = ttk.Entry(key_inner)
        self.ssh_key.pack(side="left", fill="x", expand=True)
        ttk.Button(key_inner, text="Browse…", command=self._browse_key).pack(side="left", padx=(8, 0))

        ttk.Button(vps_tab, text="Test SSH Connection", command=self._test_ssh).pack(pady=(16, 0), anchor="w")

        # --- WireGuard tab ---
        wg_tab = ttk.Frame(notebook, padding=12)
        notebook.add(wg_tab, text="  WireGuard Easy  ")

        ttk.Label(
            wg_tab,
            text=(
                f"The UI will run WireGuard Easy v{WG_EASY_VERSION} on the port you choose below.\n"
                "After deployment, complete the first-time setup wizard in your browser."
            ),
            style="Sub.TLabel",
            wraplength=640,
        ).pack(anchor="w", pady=(0, 8))

        self.wg_ui_port = self._field(wg_tab, "WireGuard Easy UI port (TCP) *", "51821")
        self.wg_tunnel_port = self._field(wg_tab, "WireGuard tunnel port (UDP) *", "51820")
        self.wg_domain = self._field(
            wg_tab,
            "Public domain for WireGuard UI (optional — Caddy HTTPS)",
            "wg.example.com",
        )
        self.caddy_email = self._field(wg_tab, "Let's Encrypt email (for HTTPS)", "admin@example.com")

        # --- Domain Manager tab ---
        dm_tab = ttk.Frame(notebook, padding=12)
        notebook.add(dm_tab, text="  Caddy Domains  ")

        ttk.Label(
            dm_tab,
            text=(
                "The Caddy Domain Manager is accessible only from WireGuard-connected devices.\n"
                "Connect to your VPN first, then open the Domain Manager URL to deploy domains."
            ),
            style="Sub.TLabel",
            wraplength=640,
        ).pack(anchor="w", pady=(0, 8))

        self.domain_manager_host = self._field(
            dm_tab,
            "Domain Manager hostname *",
            "domains.example.com",
        )
        self.vpn_subnet = self._field(
            dm_tab,
            "WireGuard client subnet (for access control)",
            "10.8.0.0/24",
        )

        # --- Log + Deploy ---
        bottom = ttk.Frame(self, padding=(12, 0, 12, 12))
        bottom.pack(fill="both", expand=True)

        self.log_box = scrolledtext.ScrolledText(
            bottom,
            height=12,
            bg="#1a2332",
            fg="#e7ecf3",
            insertbackground="#e7ecf3",
            font=("Consolas", 9),
            wrap="word",
        )
        self.log_box.pack(fill="both", expand=True, pady=(0, 8))

        btn_row = ttk.Frame(bottom)
        btn_row.pack(fill="x")
        self.deploy_btn = ttk.Button(btn_row, text="Deploy to VPS", style="Deploy.TButton", command=self._start_deploy)
        self.deploy_btn.pack(side="left")
        ttk.Button(btn_row, text="Clear Log", command=lambda: self.log_box.delete("1.0", "end")).pack(side="left", padx=8)

    def _browse_key(self):
        path = filedialog.askopenfilename(
            title="Select SSH private key",
            filetypes=[("Key files", "*.pem *.ppk id_rsa id_ed25519 *"), ("All files", "*.*")],
        )
        if path:
            self.ssh_key.delete(0, "end")
            self.ssh_key.insert(0, path)

    def _log(self, msg: str):
        self.log_box.insert("end", msg + "\n")
        self.log_box.see("end")
        self.update_idletasks()

    def _get_config(self) -> DeployConfig | None:
        host = self.vps_host.get().strip()
        user = self.ssh_user.get().strip()
        if not host or not user:
            messagebox.showerror("Validation", "VPS host and SSH username are required.")
            return None

        try:
            port = int(self.vps_port.get().strip() or "22")
            wg_ui = int(self.wg_ui_port.get().strip())
            wg_tunnel = int(self.wg_tunnel_port.get().strip())
        except ValueError:
            messagebox.showerror("Validation", "Ports must be numeric.")
            return None

        password = self.ssh_password.get() or None
        key_path = self.ssh_key.get().strip() or None
        if not password and not key_path:
            messagebox.showerror("Validation", "Provide an SSH password or private key file.")
            return None

        return DeployConfig(
            vps_host=host,
            vps_port=port,
            ssh_user=user,
            ssh_password=password,
            ssh_key_path=key_path,
            wg_tunnel_port=wg_tunnel,
            wg_ui_port=wg_ui,
            wg_domain=self.wg_domain.get().strip(),
            caddy_email=self.caddy_email.get().strip(),
            domain_manager_host=self.domain_manager_host.get().strip(),
            vpn_subnet=self.vpn_subnet.get().strip() or "10.8.0.0/24",
        )

    def _test_ssh(self):
        cfg = self._get_config()
        if not cfg:
            return
        self._log("Testing SSH connection...")
        ok, msg = test_ssh_connection(cfg)
        self._log(msg)
        if ok:
            messagebox.showinfo("SSH Test", msg)
        else:
            messagebox.showerror("SSH Test Failed", msg)

    def _start_deploy(self):
        cfg = self._get_config()
        if not cfg:
            return

        if not messagebox.askyesno(
            "Confirm Deploy",
            f"Deploy WireGuard Easy v{WG_EASY_VERSION} + Caddy to {cfg.vps_host}?\n\n"
            f"UI port: {cfg.wg_ui_port}\n"
            f"Tunnel port: {cfg.wg_tunnel_port}",
        ):
            return

        self.deploy_btn.configure(state="disabled")
        self._log("=" * 50)
        self._log(f"Starting deployment to {cfg.vps_host}...")

        def run():
            try:
                result = deploy(cfg, self._log)
                self.after(0, lambda: self._deploy_success(result))
            except Exception as exc:
                self.after(0, lambda: self._deploy_error(str(exc)))

        threading.Thread(target=run, daemon=True).start()

    def _deploy_success(self, result: dict):
        self.deploy_btn.configure(state="normal")
        self._log("=" * 50)
        self._log("DEPLOYMENT SUCCESSFUL")
        self._log(f"WireGuard Easy UI:  {result['wg_easy_url']}")
        if result.get("wg_domain_url"):
            self._log(f"WireGuard UI (TLS): {result['wg_domain_url']}")
        self._log(f"Domain Manager:     {result['domain_manager_url']}")
        self._log(f"Admin token:        {result['admin_token']}")
        self._log("")
        self._log("Next steps:")
        self._log("1. Open WireGuard Easy UI and complete the setup wizard")
        self._log("2. Create VPN client profiles and connect a device")
        self._log("3. Open Domain Manager URL (VPN required) to deploy Caddy domains")

        if messagebox.askyesno(
            "Deployment Complete",
            f"WireGuard Easy is running at:\n{result['wg_easy_url']}\n\n"
            "Open the setup wizard in your browser now?",
        ):
            webbrowser.open(result["wg_easy_url"])

    def _deploy_error(self, msg: str):
        self.deploy_btn.configure(state="normal")
        self._log(f"ERROR: {msg}")
        messagebox.showerror("Deployment Failed", msg)


def main():
    app = SetupApp()
    app.mainloop()


if __name__ == "__main__":
    main()
