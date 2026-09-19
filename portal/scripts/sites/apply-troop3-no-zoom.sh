#!/usr/bin/env bash
# Apply viewport / zoom fixes so the Troop 3 site stays fully in frame
# on mobile and desktop (blocks pinch, Ctrl-wheel, and keyboard zoom).
set -euo pipefail

ROOT="${1:-/opt/sites/troop3}"

python3 - "$ROOT" <<'PY'
from pathlib import Path
import re
import sys

root = Path(sys.argv[1])

# 1) Lock viewport scale
index = root / "index.html"
text = index.read_text(encoding="utf-8")
viewport = (
    'content="width=device-width, initial-scale=1, maximum-scale=1, '
    'minimum-scale=1, user-scalable=no, viewport-fit=cover"'
)
text, n = re.subn(r'content="width=device-width[^"]*"', viewport, text, count=1)
if n == 0:
    raise SystemExit(f"viewport meta not found in {index}")

# Early head script — runs before React so desktop Ctrl-zoom is blocked ASAP
early = """
    <script>
      /* TROOP3-NO-ZOOM-EARLY */
      (function () {
        function block(e) {
          if (e.ctrlKey || e.metaKey) e.preventDefault();
        }
        function blockKeys(e) {
          if (!(e.ctrlKey || e.metaKey)) return;
          var k = e.key;
          if (k === "+" || k === "-" || k === "=" || k === "_" || k === "0") {
            e.preventDefault();
          }
        }
        function blockGesture(e) { e.preventDefault(); }
        window.addEventListener("wheel", block, { passive: false, capture: true });
        window.addEventListener("mousewheel", block, { passive: false, capture: true });
        window.addEventListener("DOMMouseScroll", block, { passive: false, capture: true });
        window.addEventListener("keydown", blockKeys, { capture: true });
        document.addEventListener("gesturestart", blockGesture, { passive: false, capture: true });
        document.addEventListener("gesturechange", blockGesture, { passive: false, capture: true });
        document.addEventListener("gestureend", blockGesture, { passive: false, capture: true });
      })();
    </script>
"""
if "TROOP3-NO-ZOOM-EARLY" not in text:
    if "</head>" not in text:
        raise SystemExit(f"no </head> in {index}")
    text = text.replace("</head>", early + "\n  </head>", 1)
index.write_text(text, encoding="utf-8")
print(f"updated {index}")

# 2) CSS
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
  touch-action: pan-x pan-y;
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

# 3) Runtime zoom lock module + import from main.tsx
no_zoom = root / "src" / "noZoom.ts"
no_zoom.write_text(
    """/** Block browser zoom so the full Troop 3 site stays in frame. */
function isZoomChord(e: KeyboardEvent): boolean {
  if (!(e.ctrlKey || e.metaKey)) return false;
  return e.key === "+" || e.key === "-" || e.key === "=" || e.key === "_" || e.key === "0";
}

function blockWheel(e: WheelEvent) {
  if (e.ctrlKey || e.metaKey) e.preventDefault();
}

function blockKey(e: KeyboardEvent) {
  if (isZoomChord(e)) e.preventDefault();
}

function blockGesture(e: Event) {
  e.preventDefault();
}

/** Counteract mobile pinch scale via visualViewport when possible. */
function syncVisualViewport() {
  const vv = window.visualViewport;
  if (!vv) return;
  const scale = vv.scale || 1;
  const root = document.documentElement;
  if (Math.abs(scale - 1) < 0.01) {
    root.style.removeProperty("transform");
    root.style.removeProperty("transform-origin");
    root.style.removeProperty("width");
    root.style.removeProperty("height");
    return;
  }
  const inv = 1 / scale;
  root.style.transformOrigin = "0 0";
  root.style.transform = `scale(${inv})`;
  root.style.width = `${scale * 100}%`;
  root.style.height = `${scale * 100}%`;
}

export function installNoZoom(): void {
  const wheelOpts: AddEventListenerOptions = { passive: false, capture: true };
  window.addEventListener("wheel", blockWheel, wheelOpts);
  window.addEventListener("mousewheel", blockWheel as EventListener, wheelOpts);
  window.addEventListener("keydown", blockKey, true);
  document.addEventListener("gesturestart", blockGesture, { passive: false, capture: true });
  document.addEventListener("gesturechange", blockGesture, { passive: false, capture: true });
  document.addEventListener("gestureend", blockGesture, { passive: false, capture: true });

  // Multi-touch pinch on some browsers
  let lastTouchCount = 0;
  window.addEventListener(
    "touchmove",
    (e) => {
      if (e.touches.length > 1) e.preventDefault();
      lastTouchCount = e.touches.length;
    },
    { passive: false, capture: true },
  );
  void lastTouchCount;

  syncVisualViewport();
  window.visualViewport?.addEventListener("resize", syncVisualViewport);
  window.visualViewport?.addEventListener("scroll", syncVisualViewport);
}

installNoZoom();
""",
    encoding="utf-8",
)
print(f"wrote {no_zoom}")

main = root / "src" / "main.tsx"
mt = main.read_text(encoding="utf-8")
if 'import "./noZoom"' not in mt and "from \"./noZoom\"" not in mt:
    # insert after last import-style line of CSS imports
    if 'import "./admin.css";' in mt:
        mt = mt.replace('import "./admin.css";', 'import "./admin.css";\nimport "./noZoom";')
    elif 'import "./index.css";' in mt:
        mt = mt.replace('import "./index.css";', 'import "./index.css";\nimport "./noZoom";')
    else:
        mt = 'import "./noZoom";\n' + mt
    main.write_text(mt, encoding="utf-8")
    print(f"updated {main}")
else:
    print(f"already imports noZoom in {main}")

# 4) Admin editor preview: never scale above 1
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
