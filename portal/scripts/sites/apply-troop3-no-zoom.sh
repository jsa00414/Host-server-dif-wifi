#!/usr/bin/env bash
# Apply viewport / zoom fixes so the Troop 3 site stays fully in frame
# on mobile and desktop (no pinch/browser zoom-in).
set -euo pipefail

ROOT="${1:-/opt/sites/troop3}"

python3 - "$ROOT" <<'PY'
from pathlib import Path
import re
import sys

root = Path(sys.argv[1])

# 1) Lock viewport scale — keep site fully in frame, no user zoom-in
index = root / "index.html"
text = index.read_text(encoding="utf-8")
viewport = (
    'content="width=device-width, initial-scale=1, maximum-scale=1, '
    'minimum-scale=1, user-scalable=no, viewport-fit=cover"'
)
text2, n = re.subn(
    r'content="width=device-width[^"]*"',
    viewport,
    text,
    count=1,
)
if n == 0:
    raise SystemExit(f"viewport meta not found in {index}")
index.write_text(text2, encoding="utf-8")
print(f"updated viewport in {index}")

# 2) CSS: block pinch/double-tap zoom + iOS text auto-zoom on inputs
css = root / "src" / "index.css"
css_text = css.read_text(encoding="utf-8")
marker = "/* TROOP3-NO-ZOOM */"
block = """/* TROOP3-NO-ZOOM */
html {
  -webkit-text-size-adjust: 100%;
  text-size-adjust: 100%;
  touch-action: manipulation;
}

html,
body {
  overscroll-behavior-x: none;
}

input,
textarea,
select,
button {
  font-size: 16px;
  touch-action: manipulation;
}

"""
if marker in css_text:
    css_text = re.sub(
        r"/\* TROOP3-NO-ZOOM \*/.*?(?=\n:root|\Z)",
        "",
        css_text,
        count=1,
        flags=re.S,
    )
css.write_text(block + css_text.lstrip(), encoding="utf-8")
print(f"updated {css}")

# 3) Admin editor preview: never scale above 1 (keep full site in frame)
editor = root / "src" / "pages" / "admin" / "AdminEditor.tsx"
if editor.is_file():
    et = editor.read_text(encoding="utf-8")
    if "never zoom in past 1" in et:
        print(f"already patched {editor}")
    else:
        old = """      const nextScale =
        device === "phone"
          ? Math.min(1, (canvas.clientWidth - 48) / frame.width)
          : canvas.clientWidth / frame.width;
      setScale(nextScale > 0 ? nextScale : 1);"""
        new = """      // Fit the full preview in the canvas — never zoom in past 1.
      const available =
        device === "phone" ? canvas.clientWidth - 48 : canvas.clientWidth;
      const nextScale = Math.min(1, available / frame.width);
      setScale(nextScale > 0 ? nextScale : 1);"""
        if old not in et:
            raise SystemExit(f"scale block not found in {editor}")
        editor.write_text(et.replace(old, new), encoding="utf-8")
        print(f"updated {editor}")
PY
