(function () {
  const form = document.getElementById("loginForm");
  const errorEl = document.getElementById("loginError");
  const btn = document.getElementById("loginBtn");

  function setError(msg) {
    if (!errorEl) return;
    if (!msg) {
      errorEl.hidden = true;
      errorEl.textContent = "";
    } else {
      errorEl.hidden = false;
      errorEl.textContent = msg;
    }
  }

  async function checkSession() {
    try {
      const res = await fetch("/api/auth/session", { credentials: "same-origin" });
      const data = await res.json();
      if (data.loggedIn) {
        window.location.replace("/mail");
      }
    } catch (_) {
      /* stay on login */
    }
  }

  form?.addEventListener("submit", async (ev) => {
    ev.preventDefault();
    setError("");
    const email = document.getElementById("email")?.value?.trim() || "";
    const password = document.getElementById("password")?.value || "";
    if (!email || !password) {
      setError("Enter email and password.");
      return;
    }
    if (btn) {
      btn.disabled = true;
      btn.textContent = "Signing in…";
    }
    try {
      const res = await fetch("/api/auth/login", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        credentials: "same-origin",
        body: JSON.stringify({ email, password }),
      });
      const data = await res.json().catch(() => ({}));
      if (!res.ok) {
        setError(data.error || "Sign in failed.");
        return;
      }
      window.location.replace("/mail");
    } catch (_) {
      setError("Could not reach True Mail.");
    } finally {
      if (btn) {
        btn.disabled = false;
        btn.textContent = "Continue";
      }
    }
  });

  checkSession();
})();
