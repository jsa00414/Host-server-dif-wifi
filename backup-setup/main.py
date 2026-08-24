#!/usr/bin/env python3
"""ServerManager Backup Setup — Windows GUI installer."""

from __future__ import annotations

import threading
import tkinter as tk
import webbrowser
from tkinter import filedialog, messagebox, scrolledtext, ttk

from deployer import BackupConfig, ensure_github_repo, install_backup, test_ssh_connection

APP_TITLE = "ServerManager Backup Setup"
APP_VERSION = "1.0.0"
DEFAULT_REPO = "ServerManagerBackup"


class SetupApp(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title(f"{APP_TITLE} v{APP_VERSION}")
        self.geometry("720x780")
        self.minsize(640, 700)
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
        style.configure("TCheckbutton", background="#0f1419", foreground="#e7ecf3")

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
            text="Connect to your VPS and install automatic config backups to GitHub.",
            style="Sub.TLabel",
        ).pack(anchor="w", pady=(4, 0))

        notebook = ttk.Notebook(self, padding=8)
        notebook.pack(fill="both", expand=True, padx=12, pady=(0, 8))

        # --- VPS ---
        vps = ttk.Frame(notebook, padding=12)
        notebook.add(vps, text="  VPS Server  ")
        self.vps_host = self._field(vps, "VPS IP or hostname *", "74.208.54.132")
        self.vps_port = self._field(vps, "SSH port", "22")
        self.ssh_user = self._field(vps, "SSH username *", "root")

        ttk.Label(vps, text="SSH password (leave blank if using key)").pack(anchor="w", pady=(8, 2))
        self.ssh_password = ttk.Entry(vps, width=60, show="•")
        self.ssh_password.pack(fill="x")

        key_row = ttk.Frame(vps)
        key_row.pack(fill="x", pady=(8, 0))
        ttk.Label(key_row, text="SSH private key file (.pem / id_rsa)").pack(anchor="w")
        key_inner = ttk.Frame(key_row)
        key_inner.pack(fill="x", pady=(2, 0))
        self.ssh_key = ttk.Entry(key_inner)
        self.ssh_key.pack(side="left", fill="x", expand=True)
        ttk.Button(key_inner, text="Browse…", command=self._browse_key).pack(side="left", padx=(8, 0))

        ttk.Button(vps, text="Test SSH Connection", command=self._test_ssh).pack(pady=(16, 0), anchor="w")

        # --- GitHub ---
        gh = ttk.Frame(notebook, padding=12)
        notebook.add(gh, text="  GitHub Backup  ")
        ttk.Label(
            gh,
            text=(
                "Use a GitHub Personal Access Token with repo access.\n"
                "Default repo: jsa00414/ServerManagerBackup (created private if missing)."
            ),
            style="Sub.TLabel",
            wraplength=640,
        ).pack(anchor="w", pady=(0, 8))

        self.gh_owner = self._field(gh, "GitHub username / org *", "jsa00414")
        self.gh_repo = self._field(gh, "Repository name *", DEFAULT_REPO)
        self.gh_branch = self._field(gh, "Branch", "main")
        ttk.Label(gh, text="GitHub Personal Access Token *").pack(anchor="w", pady=(8, 2))
        self.gh_token = ttk.Entry(gh, width=60, show="•")
        self.gh_token.pack(fill="x")
        self.backup_hour = self._field(gh, "Daily backup hour (UTC 0–23)", "3")

        self.create_repo = tk.BooleanVar(value=True)
        ttk.Checkbutton(
            gh,
            text="Create private repo automatically if it does not exist",
            variable=self.create_repo,
        ).pack(anchor="w", pady=(12, 0))

        link_row = ttk.Frame(gh)
        link_row.pack(fill="x", pady=(12, 0))
        ttk.Button(
            link_row,
            text="Open token settings",
            command=lambda: webbrowser.open("https://github.com/settings/tokens"),
        ).pack(side="left")
        ttk.Button(
            link_row,
            text="Open backup repo",
            command=self._open_repo,
        ).pack(side="left", padx=(8, 0))
        ttk.Button(gh, text="Test GitHub Access", command=self._test_github).pack(pady=(16, 0), anchor="w")

        # --- Log + deploy ---
        bottom = ttk.Frame(self, padding=12)
        bottom.pack(fill="both", expand=False)
        ttk.Button(bottom, text="Install Backup on VPS", command=self._install).pack(anchor="w")
        self.log = scrolledtext.ScrolledText(
            bottom,
            height=14,
            bg="#0a0e14",
            fg="#c8d4e4",
            insertbackground="#c8d4e4",
            font=("Consolas", 9),
        )
        self.log.pack(fill="both", expand=True, pady=(10, 0))

    def _browse_key(self):
        path = filedialog.askopenfilename(
            title="Select SSH private key",
            filetypes=[("Key files", "*.pem *.key *"), ("All files", "*.*")],
        )
        if path:
            self.ssh_key.delete(0, tk.END)
            self.ssh_key.insert(0, path)

    def _open_repo(self):
        owner = self.gh_owner.get().strip() or "jsa00414"
        repo = self.gh_repo.get().strip() or DEFAULT_REPO
        webbrowser.open(f"https://github.com/{owner}/{repo}")

    def _cfg(self) -> BackupConfig:
        hour_raw = self.backup_hour.get().strip() or "3"
        try:
            hour = int(hour_raw)
        except ValueError as exc:
            raise ValueError("Backup hour must be an integer 0–23") from exc
        if hour < 0 or hour > 23:
            raise ValueError("Backup hour must be 0–23")
        return BackupConfig(
            vps_host=self.vps_host.get().strip(),
            vps_port=int(self.vps_port.get().strip() or "22"),
            ssh_user=self.ssh_user.get().strip(),
            ssh_password=self.ssh_password.get() or None,
            ssh_key_path=self.ssh_key.get().strip() or None,
            github_token=self.gh_token.get().strip(),
            github_owner=self.gh_owner.get().strip(),
            github_repo=self.gh_repo.get().strip() or DEFAULT_REPO,
            github_branch=self.gh_branch.get().strip() or "main",
            backup_hour=hour,
            create_repo_if_missing=bool(self.create_repo.get()),
        )

    def _log(self, msg: str):
        self.log.insert(tk.END, msg + "\n")
        self.log.see(tk.END)

    def _run_bg(self, title: str, fn):
        self.log.delete("1.0", tk.END)
        self._log(f"=== {title} ===")

        def worker():
            try:
                fn()
                self.after(0, lambda: messagebox.showinfo(APP_TITLE, f"{title} succeeded."))
            except Exception as exc:
                err = str(exc)
                self.after(0, lambda: self._log(f"ERROR: {err}"))
                self.after(0, lambda: messagebox.showerror(APP_TITLE, err))

        threading.Thread(target=worker, daemon=True).start()

    def _test_ssh(self):
        def go():
            cfg = self._cfg()
            if not cfg.vps_host or not cfg.ssh_user:
                raise ValueError("VPS host and SSH username are required.")
            test_ssh_connection(cfg, lambda m: self.after(0, lambda: self._log(m)))

        self._run_bg("Test SSH", go)

    def _test_github(self):
        def go():
            cfg = self._cfg()
            if not cfg.github_token or not cfg.github_owner:
                raise ValueError("GitHub token and username are required.")
            ensure_github_repo(cfg, lambda m: self.after(0, lambda: self._log(m)))

        self._run_bg("Test GitHub", go)

    def _install(self):
        def go():
            cfg = self._cfg()
            if not cfg.vps_host or not cfg.ssh_user:
                raise ValueError("VPS host and SSH username are required.")
            if not cfg.github_token or not cfg.github_owner:
                raise ValueError("GitHub token and username are required.")
            if not cfg.ssh_password and not cfg.ssh_key_path:
                raise ValueError("Provide SSH password or private key.")
            install_backup(cfg, lambda m: self.after(0, lambda: self._log(m)))

        if not messagebox.askyesno(
            APP_TITLE,
            "Install the backup agent on this VPS?\n\n"
            "It will push ServerManager configs to your private GitHub repo daily.",
        ):
            return
        self._run_bg("Install backup", go)


def main():
    app = SetupApp()
    app.mainloop()


if __name__ == "__main__":
    main()
